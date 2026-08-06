//! `SignedVault` — the end-user's data plane: it never holds `S3_*`
//! credentials. It asks the Coordinator's `vault:sign` action for a
//! short-lived presigned URL per operation, then executes that URL directly
//! against the object store with `reqwest`. Contrast with
//! [`ft_vault::S3Vault`], which holds real credentials and is the
//! operator-only path used by `gc` (`docs/adr/`, `crates/ft-vault/src/lib.rs`).
//!
//! Two properties of that arrangement drive most of the code below. First, every
//! signed PUT is create-only, and the precondition is part of the signature
//! ([`CREATE_ONLY`]). Second, unlike `S3Vault` — which gets the AWS SDK's
//! retries, timeouts and body limits for free — this is a bare `reqwest` client,
//! so the resilience the SDK would have provided has to be explicit here: see
//! [`build_http_client`], [`send_with_retry`] and [`read_capped_body`]. This is
//! the path every real user is on.

use std::collections::{BTreeMap, HashMap};
use std::error::Error as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use convex::{ConvexClient, FunctionResult, Value};
use ft_vault::{Vault, VaultError, VaultObject, VaultResult, WarmMethod, WarmOp};
use futures::StreamExt;
use tokio::sync::Mutex;

/// The Convex action that mints presigned S3 URLs for the caller's Account.
const SIGN_ACTION: &str = "vault:sign";

/// Presigned URLs minted by `vault:sign` are valid for this long (matches the
/// action's TTL, `packages/backend/convex/vault.ts`).
const SIGN_URL_TTL_SECS: u64 = 900;

/// Safety margin subtracted from [`SIGN_URL_TTL_SECS`] before a cached URL is
/// treated as expired, so a cached URL is never handed out so close to its
/// real expiry that the HTTP request could land after the object store has
/// already rejected it.
const SIGN_URL_TTL_MARGIN_SECS: u64 = 60;

/// How long a signed URL is trusted from the cache: [`SIGN_URL_TTL_SECS`]
/// minus [`SIGN_URL_TTL_MARGIN_SECS`].
const SIGN_URL_CACHE_TTL: Duration =
    Duration::from_secs(SIGN_URL_TTL_SECS - SIGN_URL_TTL_MARGIN_SECS);

/// Max ops per `vault:sign` call (the action's own batch limit,
/// `packages/backend/convex/vault.ts`).
const SIGN_BATCH_LIMIT: usize = 256;
/// Independent Convex signing actions allowed in flight while warming a large
/// transfer. This removes the O(number-of-batches) latency chain without
/// flooding the Coordinator.
const SIGN_BATCH_CONCURRENCY: usize = 4;

/// Value of the `If-None-Match` header every presigned PUT MUST carry.
///
/// `vault:sign` builds each PUT as `PutObjectCommand({ IfNoneMatch: "*" })`
/// (`packages/backend/convex/vault.ts`, CREATE_ONLY) and the AWS signer keeps
/// `if-none-match` a SIGNED header — it appears in
/// `X-Amz-SignedHeaders=host;if-none-match` instead of being hoisted into the
/// query string. A request that omits it therefore fails the signature check
/// with 403 SignatureDoesNotMatch, i.e. EVERY upload fails. The write-once
/// condition is deliberately part of the signature so no client can drop it.
const CREATE_ONLY: &str = "*";

// ---------------------------------------------------------------------------
// HTTP policy for the data plane: timeouts, retries and object-size caps
// ---------------------------------------------------------------------------

/// Bound on DNS + TCP + TLS. The handshake either completes quickly or the
/// endpoint is unreachable, so this stays tight (same value as the Better Auth
/// client in `apps/cli/src/auth.rs`).
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle bound on a request, not a total deadline: it resets on every successful
/// read, so a legitimately large transfer on a slow link is never killed by
/// elapsed time — only a stalled one is.
///
/// A total `timeout` is deliberately NOT set for GET/PUT. Object bodies scale
/// with the data (`ft_core::LARGE_CHUNK_MAX` per Block, more for a full Manifest
/// page), so any elapsed-time bound big enough for a slow link would be too big
/// to detect a stall. `reqwest` applies this bound both while waiting for the
/// response head and to each body chunk; for a PUT the head only arrives after
/// the request body has been written, which makes 60s the effective ceiling for
/// uploading one object. That covers a 4 MiB Block at ~70 KiB/s while still
/// capping a wedged transfer at [`HTTP_MAX_ATTEMPTS`] × 60s instead of forever
/// (a stalled request used to freeze every Space: the daemon awaits the pull
/// inline and all Spaces share one task).
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Total deadline for a presigned HEAD. A HEAD has no response body, so unlike
/// GET/PUT its elapsed time does not scale with the object and a hard deadline
/// is the tighter, better bound.
const HTTP_HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Attempts (not retries) per presigned request before giving up.
const HTTP_MAX_ATTEMPTS: u32 = 4;

/// First backoff window. Kept small because commit/pull fan thousands of
/// objects out with `try_collect`, where the first hard failure aborts the whole
/// operation: retrying cheaply is much better than restarting a large `init`.
const HTTP_RETRY_BASE: Duration = Duration::from_millis(200);

/// Poly1305 tag appended by `alg=1` Block/page encryption (`docs/format.md §4.4`).
const AEAD_TAG_LEN: u64 = 16;

/// Largest legitimate `blocks/<aa>/<cid>` object: the fixed header
/// (`docs/format.md §4.3`) + the biggest chunk the large-binary CDC profile can
/// emit (`§3`) + the AEAD tag.
const MAX_BLOCK_OBJECT_BYTES: u64 =
    ft_core::BLOCK_HEADER_LEN as u64 + ft_core::LARGE_CHUNK_MAX as u64 + AEAD_TAG_LEN;

/// Largest legitimate Manifest page (and, by extension, `blocklist/`, `meta/`
/// and `keys/` object): a leaf page holds up to [`ft_core::LEAF_FANOUT`]
/// entries, and an entry's `bk` list is externalized only once the entry's own
/// CBOR passes [`ft_core::ENTRY_INLINE_MAX`] (`docs/format.md §5.3`), so a full
/// page of just-under-threshold entries is the worst legitimate case.
const MAX_PAGE_OBJECT_BYTES: u64 = ft_core::BLOCK_HEADER_LEN as u64
    + (ft_core::LEAF_FANOUT as u64 * ft_core::ENTRY_INLINE_MAX as u64)
    + AEAD_TAG_LEN;

/// Most bytes reserved up front for a response body. The real cap
/// ([`max_object_bytes`]) is enforced while reading; this smaller reservation
/// keeps a lying `Content-Length` from turning every concurrent GET into a
/// multi-megabyte allocation.
const BODY_RESERVE_MAX_BYTES: u64 = MAX_BLOCK_OBJECT_BYTES;

/// A cached presigned URL plus the instant it stops being trusted.
#[derive(Debug, Clone)]
struct CachedUrl {
    url: String,
    expires_at: Instant,
}

/// `true` while `expires_at` is still in the future.
fn is_fresh(expires_at: Instant) -> bool {
    expires_at > Instant::now()
}

/// Maximum body we are willing to read from a presigned GET of `key`.
///
/// The object's size is remote-controlled and the caller only verifies the
/// reassembled bytes against the Manifest's `pcid`/`sz` AFTER they are in RAM,
/// so a 2 GiB object parked at a Block key would OOM the client before any
/// check runs. The ceiling is derived from the format's own limits (ft-core)
/// per key prefix, so `blocks/` — the overwhelming majority of objects — gets
/// the tight bound rather than the loosest one.
fn max_object_bytes(key: &str) -> u64 {
    match key.split('/').next() {
        Some("blocks") => MAX_BLOCK_OBJECT_BYTES,
        _ => MAX_PAGE_OBJECT_BYTES,
    }
}

/// The data plane's HTTP client: bounded timeouts and no redirect following.
///
/// Redirects are off because a presigned URL is signed for exactly one host, so
/// a 3xx can only mean a misconfigured endpoint or an attempt to make us forward
/// `X-Amz-Signature` (and a PUT body) somewhere else. A 3xx is surfaced as a
/// hard error instead.
///
/// `expect` rather than a fallback: with `rustls-tls` (webpki roots, no OS trust
/// store to read) this builder does not fail in practice, and falling back to an
/// untimed `Client::new()` would silently restore the stall that wedges every
/// Space — a loud failure at construction is the safer of the two.
fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .read_timeout(HTTP_READ_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("building the presigned data-plane HTTP client")
}

/// How the retry driver should treat one finished attempt.
#[derive(Debug)]
enum Attempt<T> {
    /// The request is done: hand `T` to the caller.
    Done(T),
    /// The request failed for a reason another attempt cannot change.
    Fatal(VaultError),
    /// Transient failure: back off and retry the same presigned URL.
    Transient(String),
    /// The store rejected the signature: re-sign, then retry.
    Stale(String),
}

/// What an HTTP status means for retrying, before the verb decides what it means
/// for the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusClass {
    /// Final: the verb interprets it (2xx, 404, 412, …).
    Final,
    /// Worth another attempt at the same URL.
    Transient,
    /// The presigned signature was rejected; re-sign before retrying.
    Stale,
}

/// Classifies an HTTP status for the retry driver.
///
/// - 403: almost always an expired signature (15-minute TTL vs. a sync that runs
///   longer), so re-sign instead of failing. A genuine denial simply 403s again
///   and surfaces after [`HTTP_MAX_ATTEMPTS`].
/// - 408/429/5xx: R2 answers 503 `SlowDown` under ordinary burst load, and
///   commit/pull fan out with `try_collect`, so one transient status used to
///   abort a whole sync.
/// - 409: S3-compatible stores report a create-only PUT that raced another
///   writer this way; the retry then sees 412, which is success for a
///   content-addressed key.
/// - Everything else (notably 404) stays final so `head`/`get` absence semantics
///   are unchanged.
fn class_for_status(status: reqwest::StatusCode) -> StatusClass {
    if status == reqwest::StatusCode::FORBIDDEN {
        StatusClass::Stale
    } else if status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::CONFLICT
        || status.is_server_error()
    {
        StatusClass::Transient
    } else {
        StatusClass::Final
    }
}

/// Renders a status the data plane treats as final-and-wrong.
fn final_status_message(verb: &str, key: &str, status: reqwest::StatusCode) -> String {
    if status.is_redirection() {
        format!(
            "{verb} {key} returned HTTP {status}: the data plane does not follow redirects — a presigned URL is signed for one host"
        )
    } else {
        format!("{verb} {key} returned HTTP {status}")
    }
}

/// Renders a transport failure WITHOUT the URL `reqwest` attaches to it.
///
/// `reqwest`'s `Display` appends `" for url (…)"`, which for us is a live
/// presigned URL: its `X-Amz-Credential` + `X-Amz-Signature` are a working,
/// time-limited write capability on the bucket. daemon.log gets pasted into
/// issues, so it must never carry one. The cause chain is appended by hand
/// because dropping the URL is the only thing being dropped — the real reason
/// (dns error, connection reset, timed out) is what makes the message useful.
fn transport_message(verb: &str, key: &str, err: reqwest::Error) -> String {
    let err = err.without_url();
    let mut message = format!("{verb} {key}: {err}");
    let mut cause = err.source();
    while let Some(source) = cause {
        message.push_str(&format!(": {source}"));
        cause = source.source();
    }
    message
}

/// Classifies a transport-level failure.
///
/// Everything except a builder error is retryable: a DNS hiccup, a reset
/// connection, a TLS error and a stalled body all clear up often enough to be
/// worth up to [`HTTP_MAX_ATTEMPTS`] tries, while a malformed URL never will.
/// Retrying a PUT is safe even when the first attempt actually landed — the key
/// is content-addressed and create-only, so the retry gets 412, which is
/// success.
fn transport_attempt<T>(verb: &str, key: &str, err: reqwest::Error) -> Attempt<T> {
    let is_builder = err.is_builder();
    let message = transport_message(verb, key, err);
    if is_builder {
        Attempt::Fatal(VaultError::S3 {
            key: key.to_string(),
            message,
        })
    } else {
        Attempt::Transient(message)
    }
}

/// Backoff before retry number `attempt` (1-based): the exponential window
/// `HTTP_RETRY_BASE * 2^(attempt - 1)` scaled by `jitter` into its upper half.
///
/// The jitter is load-bearing, not decoration: a commit fans thousands of
/// objects out at once, so without it every object hit by the same 503 burst
/// would retry in lockstep and re-create the burst it is backing off from. Half
/// the window stays fixed so a retry always waits.
fn backoff_delay(attempt: u32, jitter: f64) -> Duration {
    // Saturating/clamped: the release profile enables `overflow-checks`, so
    // arithmetic that used to wrap now panics.
    let steps = attempt.saturating_sub(1).min(HTTP_MAX_ATTEMPTS);
    let window = HTTP_RETRY_BASE.saturating_mul(1u32 << steps);
    window.mul_f64(0.5 + jitter.clamp(0.0, 1.0) / 2.0)
}

/// Waits out a backoff window. Separate from [`backoff_delay`] so the retry
/// driver can be tested without a real clock.
async fn sleep_backoff(delay: Duration) {
    tokio::time::sleep(delay).await;
}

/// Runs one presigned request until it succeeds, fails for a reason another
/// attempt cannot change, or the [`HTTP_MAX_ATTEMPTS`] budget runs out.
///
/// The three moving parts are injected — same internal-seam idea as
/// [`sign_warm_batches`] — so the loop is testable without a Convex client or a
/// real clock: `sign(refresh)` mints the presigned URL (`refresh` must bypass
/// the cache), `attempt(url)` runs the request once, and `sleep(d)` waits.
/// A signing failure is NOT retried here: it comes from the Coordinator (auth,
/// bad key, ownership), where another identical call changes nothing.
async fn send_with_retry<T, S, SFut, A, AFut, Z, ZFut>(
    key: &str,
    verb: &str,
    sign: S,
    attempt: A,
    sleep: Z,
) -> VaultResult<T>
where
    S: Fn(bool) -> SFut,
    SFut: Future<Output = VaultResult<String>>,
    A: Fn(String) -> AFut,
    AFut: Future<Output = Attempt<T>>,
    Z: Fn(Duration) -> ZFut,
    ZFut: Future<Output = ()>,
{
    let mut refresh = false;
    let mut last = String::new();
    for attempt_no in 1..=HTTP_MAX_ATTEMPTS {
        let url = sign(refresh).await?;
        match attempt(url).await {
            Attempt::Done(value) => return Ok(value),
            Attempt::Fatal(error) => return Err(error),
            Attempt::Transient(message) => {
                refresh = false;
                last = message;
            }
            Attempt::Stale(message) => {
                refresh = true;
                last = message;
            }
        }
        // A transient data-plane failure used to be invisible: daemon.log had
        // nothing to go on. A retry is exactly the moment worth recording.
        tracing::debug!(key, verb, attempt = attempt_no, reason = %last, "retrying presigned request");
        if attempt_no < HTTP_MAX_ATTEMPTS {
            sleep(backoff_delay(attempt_no, rand::random::<f64>())).await;
        }
    }
    Err(VaultError::S3 {
        key: key.to_string(),
        message: format!("{last} (gave up after {HTTP_MAX_ATTEMPTS} attempts)"),
    })
}

/// Why [`read_capped_body`] stopped short.
#[derive(Debug)]
enum BodyError {
    /// The body is bigger than the largest legitimate object for its key.
    TooLarge {
        /// The cap that was exceeded, in bytes.
        limit: u64,
    },
    /// The transfer failed or stalled part-way through the body.
    Transport(reqwest::Error),
}

/// Reads a response body into memory, refusing to buffer more than `limit`.
///
/// `Content-Length` is honoured as an early reject, but it is remote-controlled
/// and therefore not trusted: the running total is checked chunk by chunk, so a
/// missing or lying `Content-Length` cannot beat the cap either. The up-front
/// reservation is capped separately ([`BODY_RESERVE_MAX_BYTES`]) so a lie in the
/// other direction cannot turn every concurrent GET into a large allocation.
async fn read_capped_body(mut resp: reqwest::Response, limit: u64) -> Result<Vec<u8>, BodyError> {
    if let Some(claimed) = resp.content_length() {
        if claimed > limit {
            return Err(BodyError::TooLarge { limit });
        }
    }
    let reserve = resp
        .content_length()
        .unwrap_or(0)
        .min(BODY_RESERVE_MAX_BYTES) as usize;
    let mut body = Vec::with_capacity(reserve);
    while let Some(chunk) = resp.chunk().await.map_err(BodyError::Transport)? {
        if body.len() as u64 + chunk.len() as u64 > limit {
            return Err(BodyError::TooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// One presigned HEAD attempt.
async fn attempt_head(http: &reqwest::Client, key: &str, url: String) -> Attempt<bool> {
    let sent = http.head(&url).timeout(HTTP_HEAD_TIMEOUT).send().await;
    let resp = match sent {
        Ok(resp) => resp,
        Err(err) => return transport_attempt("HEAD", key, err),
    };
    let status = resp.status();
    match class_for_status(status) {
        StatusClass::Transient => Attempt::Transient(final_status_message("HEAD", key, status)),
        StatusClass::Stale => Attempt::Stale(final_status_message("HEAD", key, status)),
        // `head_result_from_status` owns the present/absent mapping; the message
        // comes from `final_status_message` so all three verbs explain a
        // redirect the same way.
        StatusClass::Final => match head_result_from_status(status) {
            Ok(present) => Attempt::Done(present),
            Err(_) => Attempt::Fatal(VaultError::S3 {
                key: key.to_string(),
                message: final_status_message("HEAD", key, status),
            }),
        },
    }
}

/// One presigned GET attempt, bounded by `limit` bytes of response body.
async fn attempt_get(
    http: &reqwest::Client,
    key: &str,
    url: String,
    limit: u64,
) -> Attempt<Vec<u8>> {
    let resp = match http.get(&url).send().await {
        Ok(resp) => resp,
        Err(err) => return transport_attempt("GET", key, err),
    };
    let status = resp.status();
    match class_for_status(status) {
        StatusClass::Transient => {
            return Attempt::Transient(final_status_message("GET", key, status))
        }
        StatusClass::Stale => return Attempt::Stale(final_status_message("GET", key, status)),
        StatusClass::Final => {}
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Attempt::Fatal(VaultError::NotFound {
            key: key.to_string(),
        });
    }
    if !status.is_success() {
        return Attempt::Fatal(VaultError::S3 {
            key: key.to_string(),
            message: final_status_message("GET", key, status),
        });
    }
    match read_capped_body(resp, limit).await {
        Ok(body) => Attempt::Done(body),
        // A body that stops part-way is the stalled-transfer case retrying
        // exists for; an over-cap object will not shrink on a second try.
        Err(BodyError::Transport(err)) => transport_attempt("GET", key, err),
        Err(BodyError::TooLarge { limit }) => Attempt::Fatal(VaultError::S3 {
            key: key.to_string(),
            message: format!(
                "GET {key}: object exceeds the {limit}-byte maximum for its key prefix"
            ),
        }),
    }
}

/// One presigned PUT attempt, carrying the signed create-only precondition.
async fn attempt_put(http: &reqwest::Client, key: &str, url: String, body: &[u8]) -> Attempt<()> {
    let sent = http
        .put(&url)
        // Part of the signature, not an optimization — see [`CREATE_ONLY`].
        .header(reqwest::header::IF_NONE_MATCH, CREATE_ONLY)
        .body(body.to_vec())
        .send()
        .await;
    let resp = match sent {
        Ok(resp) => resp,
        Err(err) => return transport_attempt("PUT", key, err),
    };
    let status = resp.status();
    // 412 is the dedup case, not a failure: the key is a hash of the bytes
    // (`docs/format.md §6.1`), so an object that already exists necessarily
    // holds the same object. `vault:sign` documents this as part of the
    // create-only contract.
    if status == reqwest::StatusCode::PRECONDITION_FAILED {
        return Attempt::Done(());
    }
    match class_for_status(status) {
        StatusClass::Transient => Attempt::Transient(final_status_message("PUT", key, status)),
        StatusClass::Stale => Attempt::Stale(final_status_message("PUT", key, status)),
        StatusClass::Final if status.is_success() => Attempt::Done(()),
        StatusClass::Final => Attempt::Fatal(VaultError::S3 {
            key: key.to_string(),
            message: final_status_message("PUT", key, status),
        }),
    }
}

/// Maps a [`WarmMethod`] to the HTTP verb string `vault:sign` expects.
fn method_to_str(method: WarmMethod) -> &'static str {
    match method {
        WarmMethod::Head => "HEAD",
        WarmMethod::Get => "GET",
        WarmMethod::Put => "PUT",
    }
}

/// Presigned URLs kept in [`UrlCache`] at once.
///
/// The cache used to be unbounded, so a daemon that runs for weeks accumulated
/// one entry per distinct object forever — almost all of them long expired. The
/// ceiling is generous on purpose: `warm` pre-signs every object of a commit or
/// a pull in one go, and a batch that does not fit degrades to one `vault:sign`
/// round-trip per object. 32768 entries covers a multi-GiB first commit at
/// roughly 750 bytes per entry (a presigned R2 URL is ~500 chars).
const URL_CACHE_CAPACITY: usize = 32768;

/// Bounded cache of presigned URLs keyed by `(key, method)`.
///
/// Entries expire a little before the real URL TTL ([`SIGN_URL_CACHE_TTL`]) so
/// an expired URL is re-signed instead of being sent to a store that would only
/// answer 403.
#[derive(Debug, Default)]
struct UrlCache {
    entries: HashMap<(String, WarmMethod), CachedUrl>,
}

impl UrlCache {
    /// A still-fresh URL for `(key, method)`, if one is cached.
    fn get(&self, key: &str, method: WarmMethod) -> Option<String> {
        self.entries
            .get(&(key.to_string(), method))
            .filter(|cached| is_fresh(cached.expires_at))
            .map(|cached| cached.url.clone())
    }

    /// Remembers `url` for `(key, method)` until it expires.
    fn insert(&mut self, key: &str, method: WarmMethod, url: String) {
        let entry_key = (key.to_string(), method);
        // Only pay for housekeeping once the cap actually bites; re-signing an
        // already-cached key replaces an entry and never grows the map.
        if self.entries.len() >= URL_CACHE_CAPACITY && !self.entries.contains_key(&entry_key) {
            self.entries.retain(|_, cached| is_fresh(cached.expires_at));
            if self.entries.len() >= URL_CACHE_CAPACITY {
                // Full of still-fresh URLs: keep them and drop this one instead
                // of evicting the oldest. `warm` inserts in the order the caller
                // will consume the keys, so evicting the oldest would evict
                // exactly the URL needed next and turn one big batch into one
                // `vault:sign` per object. A cache miss only costs a signing
                // round-trip — `url_for` always re-signs when it misses.
                return;
            }
        }
        self.entries.insert(
            entry_key,
            CachedUrl {
                url,
                expires_at: Instant::now() + SIGN_URL_CACHE_TTL,
            },
        );
    }

    /// Forgets `(key, method)` so the next lookup re-signs.
    fn invalidate(&mut self, key: &str, method: WarmMethod) {
        self.entries.remove(&(key.to_string(), method));
    }
}

/// One presigned operation as returned by `vault:sign`: the Vault key, the
/// HTTP method it authorizes, and the URL to hit.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedOp {
    key: String,
    method: String,
    url: String,
}

/// A [`Vault`] that talks to the object store only through presigned URLs.
///
/// `head`/`get`/`put` call `vault:sign` for a single-element `ops` batch (the
/// action is batch-shaped for future callers that sign several keys at once),
/// then run the returned URL through `reqwest`. `list`/`delete` are NOT
/// supported here: garbage collection needs to enumerate and delete across
/// the WHOLE bucket, which a single presigned object URL cannot do — that
/// stays on the operator-only [`ft_vault::S3Vault`] path with real `S3_*`
/// credentials.
pub struct SignedVault {
    /// Guards the single `ConvexClient`. Cloned out and released before each
    /// `action` call (cloning is cheap — it shares the underlying connection)
    /// so concurrent Vault calls don't serialize behind the lock.
    client: Mutex<ConvexClient>,
    http: reqwest::Client,
    /// Presigned URLs already minted, keyed by `(key, method)`. A hit inside
    /// its TTL skips `vault:sign` entirely; own `std::sync::Mutex` (never
    /// held across an `await`) since lookups are synchronous map ops.
    cache: StdMutex<UrlCache>,
}

impl SignedVault {
    /// Builds a `SignedVault` over `client`, which the caller has already
    /// authenticated (`set_auth`/`set_auth_callback`) so `vault:sign` runs as
    /// the right Account.
    pub fn new(client: ConvexClient) -> Self {
        Self {
            client: Mutex::new(client),
            http: build_http_client(),
            cache: StdMutex::new(UrlCache::default()),
        }
    }

    /// Remembers a freshly-signed `url` for `(key, method)` until it expires.
    fn cache_url(&self, key: &str, method: WarmMethod, url: String) {
        self.cache.lock().unwrap().insert(key, method, url);
    }

    /// Returns a presigned URL for `(key, method)`: a fresh cache hit, or a
    /// fresh `vault:sign` call whose result is cached for next time.
    ///
    /// `refresh` drops any cached entry first. The retry driver sets it after a
    /// 403: a presigned URL lives 15 minutes and a large sync outlives that, so
    /// the likeliest cause of a 403 is an expired signature, not a real denial.
    async fn url_for(&self, key: &str, method: WarmMethod, refresh: bool) -> VaultResult<String> {
        // Scoped so the std guard is provably released before the `await`.
        {
            let mut cache = self.cache.lock().unwrap();
            if refresh {
                cache.invalidate(key, method);
            } else if let Some(url) = cache.get(key, method) {
                return Ok(url);
            }
        }
        let url = self.sign_one(key, method).await?;
        self.cache_url(key, method, url.clone());
        Ok(url)
    }

    /// Calls `vault:sign` for exactly one `(key, method)` pair and returns its
    /// presigned URL.
    async fn sign_one(&self, key: &str, method: WarmMethod) -> VaultResult<String> {
        let ops = self.sign_batch(&[(key, method)]).await?;
        let method_str = method_to_str(method);
        ops.into_iter()
            .find(|op| op.key == key && op.method.eq_ignore_ascii_case(method_str))
            .map(|op| op.url)
            .ok_or_else(|| VaultError::S3 {
                key: key.to_string(),
                message: format!(
                    "{SIGN_ACTION} did not return a presigned URL for {method_str} {key}"
                ),
            })
    }

    /// Calls `vault:sign` for up to [`SIGN_BATCH_LIMIT`] `(key, method)` pairs
    /// in one action round-trip and returns the signed ops (order per
    /// `parse_sign_response`, i.e. as `vault:sign` returned them).
    async fn sign_batch(&self, ops: &[(&str, WarmMethod)]) -> VaultResult<Vec<SignedOp>> {
        // Clone the client and drop the lock immediately: `action` awaits a
        // network round-trip, and holding the mutex across it would serialize
        // every Vault call onto one in-flight request at a time.
        let mut client = self.client.lock().await.clone();

        let sign_ops: Vec<Value> = ops
            .iter()
            .map(|(key, method)| signed_op_arg(key, method_to_str(*method)))
            .collect();
        let args = BTreeMap::from([("ops".to_string(), Value::Array(sign_ops))]);

        let batch_label = || format!("batch of {} ops", ops.len());

        let result = client
            .action(SIGN_ACTION, args)
            .await
            .map_err(|err| VaultError::S3 {
                key: batch_label(),
                message: format!("calling {SIGN_ACTION}: {err}"),
            })?;

        parse_sign_response(result).map_err(|message| VaultError::S3 {
            key: batch_label(),
            message,
        })
    }

    /// Builds the "signed vault cannot do this" error shared by `list`/`delete`.
    fn unsupported(key: &str, op: &str) -> VaultError {
        VaultError::S3 {
            key: key.to_string(),
            message: format!(
                "signed vault cannot {op}: gc requires direct storage credentials (S3_*) — operator-only"
            ),
        }
    }
}

/// Builds one `vault:sign` request-array element for `(key, method)`.
fn signed_op_arg(key: &str, method: &str) -> Value {
    Value::Object(BTreeMap::from([
        ("key".to_string(), Value::String(key.to_string())),
        ("method".to_string(), Value::String(method.to_string())),
    ]))
}

/// Pairs each [`WarmOp`] with its `(key, method)` shape for [`SignedVault::sign_batch`].
#[cfg(test)]
fn batch_pairs(ops: &[WarmOp]) -> Vec<(&str, WarmMethod)> {
    ops.iter().map(|op| (op.key.as_str(), op.method)).collect()
}

type SignBatchFuture<'a> = Pin<Box<dyn Future<Output = VaultResult<Vec<SignedOp>>> + Send + 'a>>;
type OwnedWarmOp = (String, WarmMethod);

struct SignedWarmBatches {
    signed: Vec<SignedOp>,
    first_error: Option<VaultError>,
}

/// Signs independent warm batches with bounded concurrency. The callback is an
/// internal seam: production passes the Convex signer, while tests can inject a
/// deterministic latency adapter and verify the performance characteristic.
async fn sign_warm_batches<'a, F>(ops: &[WarmOp], signer: F) -> SignedWarmBatches
where
    F: Fn(Vec<OwnedWarmOp>) -> SignBatchFuture<'a> + Clone + Send + Sync + 'a,
{
    let owned_batches: Vec<Vec<OwnedWarmOp>> = ops
        .chunks(SIGN_BATCH_LIMIT)
        .map(|chunk| chunk.iter().map(|op| (op.key.clone(), op.method)).collect())
        .collect();
    let batches: Vec<VaultResult<Vec<SignedOp>>> = futures::stream::iter(owned_batches)
        .map(move |batch| {
            let signer = signer.clone();
            signer(batch)
        })
        .buffer_unordered(SIGN_BATCH_CONCURRENCY)
        .collect()
        .await;
    let mut signed = Vec::new();
    let mut first_error = None;
    for batch in batches {
        match batch {
            Ok(mut batch) => signed.append(&mut batch),
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    SignedWarmBatches {
        signed,
        first_error,
    }
}

/// Parses a `vault:sign` [`FunctionResult`] into the [`SignedOp`]s it
/// authorized, or an error message. Pure and independent of the Convex
/// transport, so it is unit-testable without a live client.
fn parse_sign_response(result: FunctionResult) -> Result<Vec<SignedOp>, String> {
    let value = match result {
        FunctionResult::Value(value) => value,
        FunctionResult::ErrorMessage(message) => return Err(message),
        FunctionResult::ConvexError(err) => return Err(err.message),
    };
    let Value::Array(items) = value else {
        return Err(format!(
            "{SIGN_ACTION} returned {value:?}, expected an array of signed ops"
        ));
    };
    items.into_iter().map(parse_signed_op).collect()
}

/// Parses one element of the `vault:sign` array into a [`SignedOp`].
fn parse_signed_op(item: Value) -> Result<SignedOp, String> {
    let Value::Object(fields) = item else {
        return Err(format!(
            "{SIGN_ACTION} array item was {item:?}, expected an object"
        ));
    };
    Ok(SignedOp {
        key: expect_string(&fields, "key")?,
        method: expect_string(&fields, "method")?,
        url: expect_string(&fields, "url")?,
    })
}

/// Reads a required string field out of a `vault:sign` response object.
fn expect_string(fields: &BTreeMap<String, Value>, field: &str) -> Result<String, String> {
    match fields.get(field) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(format!(
            "{SIGN_ACTION} field {field:?} was {other:?}, expected a string"
        )),
        None => Err(format!(
            "{SIGN_ACTION} response object is missing {field:?}"
        )),
    }
}

/// Maps an HTTP status from a presigned HEAD request to the [`Vault::head`]
/// result: success means present, 404 means absent, anything else is a real
/// failure. Pure so the mapping is unit-testable without a live request.
fn head_result_from_status(status: reqwest::StatusCode) -> Result<bool, String> {
    if status.is_success() {
        Ok(true)
    } else if status == reqwest::StatusCode::NOT_FOUND {
        Ok(false)
    } else {
        Err(format!("HEAD returned HTTP {status}"))
    }
}

#[async_trait]
impl Vault for SignedVault {
    async fn head(&self, key: &str) -> VaultResult<bool> {
        send_with_retry(
            key,
            "HEAD",
            |refresh| self.url_for(key, WarmMethod::Head, refresh),
            |url| attempt_head(&self.http, key, url),
            sleep_backoff,
        )
        .await
    }

    async fn get(&self, key: &str) -> VaultResult<Vec<u8>> {
        let limit = max_object_bytes(key);
        send_with_retry(
            key,
            "GET",
            |refresh| self.url_for(key, WarmMethod::Get, refresh),
            |url| attempt_get(&self.http, key, url, limit),
            sleep_backoff,
        )
        .await
    }

    async fn put(&self, key: &str, body: Vec<u8>) -> VaultResult<()> {
        send_with_retry(
            key,
            "PUT",
            |refresh| self.url_for(key, WarmMethod::Put, refresh),
            |url| attempt_put(&self.http, key, url, &body),
            sleep_backoff,
        )
        .await
    }

    async fn list(&self, prefix: &str) -> VaultResult<Vec<VaultObject>> {
        Err(Self::unsupported(prefix, "list"))
    }

    async fn delete(&self, key: &str) -> VaultResult<()> {
        Err(Self::unsupported(key, "delete"))
    }

    async fn warm(&self, ops: &[WarmOp]) -> VaultResult<()> {
        let batches = sign_warm_batches(ops, |chunk| {
            Box::pin(async move {
                let pairs: Vec<(&str, WarmMethod)> = chunk
                    .iter()
                    .map(|(key, method)| (key.as_str(), *method))
                    .collect();
                self.sign_batch(&pairs).await
            })
        })
        .await;
        let by_operation: HashMap<(String, String), String> = batches
            .signed
            .into_iter()
            .map(|op| ((op.key, op.method.to_ascii_uppercase()), op.url))
            .collect();

        let mut warm_error = batches.first_error;
        for op in ops {
            let method_str = method_to_str(op.method);
            if let Some(url) = by_operation
                .get(&(op.key.clone(), method_str.to_string()))
                .cloned()
            {
                self.cache_url(&op.key, op.method, url);
            } else if warm_error.is_none() {
                warm_error = Some(VaultError::S3 {
                    key: op.key.clone(),
                    message: format!(
                        "{SIGN_ACTION} did not return a presigned URL for {method_str} {} in warm batch",
                        op.key
                    ),
                });
            }
        }
        if let Some(error) = warm_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use convex::ConvexError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A minimal HTTP/1.1 server for the presigned-request tests: it answers each
    /// request with the next scripted response and records what it received.
    /// Hand-rolled because the workspace has no HTTP-mock crate and the contract
    /// under test lives at the raw-header level (`If-None-Match`, 412, 503, a
    /// lying `Content-Length`).
    struct FakeStore {
        base: String,
        requests: Arc<StdMutex<Vec<String>>>,
    }

    impl FakeStore {
        /// Serves `script` in order, one entry per request; the last entry is
        /// reused if more requests arrive than were scripted.
        async fn start(script: Vec<Vec<u8>>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let requests = Arc::new(StdMutex::new(Vec::new()));
            let seen = requests.clone();
            tokio::spawn(async move {
                let script = Arc::new(script);
                let next = Arc::new(AtomicUsize::new(0));
                while let Ok((stream, _)) = listener.accept().await {
                    let (seen, script, next) = (seen.clone(), script.clone(), next.clone());
                    tokio::spawn(serve_connection(stream, seen, script, next));
                }
            });
            Self {
                base: format!("http://{addr}"),
                requests,
            }
        }

        /// A presigned-looking URL for `key`, carrying the same query parameters
        /// a real `vault:sign` URL does (including the signature to redact).
        fn url(&self, key: &str, signature: &str) -> String {
            format!(
                "{}/{key}?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Credential=AKIAEXAMPLE%2F20260729%2Fauto%2Fs3%2Faws4_request\
                 &X-Amz-Expires=900&X-Amz-SignedHeaders=host%3Bif-none-match\
                 &X-Amz-Signature={signature}",
                self.base
            )
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    /// Serves every request on one connection, recording `<head><body>` per
    /// request so a test can assert on headers and payload alike.
    async fn serve_connection(
        mut stream: tokio::net::TcpStream,
        seen: Arc<StdMutex<Vec<String>>>,
        script: Arc<Vec<Vec<u8>>>,
        next: Arc<AtomicUsize>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut buf: Vec<u8> = Vec::new();
        loop {
            let head_end = loop {
                if let Some(at) = find_subslice(&buf, b"\r\n\r\n") {
                    break at + 4;
                }
                let mut chunk = [0u8; 1024];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let body_len = content_length_of(&head);
            while buf.len() < head_end + body_len {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let body = String::from_utf8_lossy(&buf[head_end..head_end + body_len]).to_string();
            seen.lock().unwrap().push(format!("{head}{body}"));
            buf.drain(..head_end + body_len);

            let at = next.fetch_add(1, Ordering::SeqCst).min(script.len() - 1);
            if stream.write_all(&script[at]).await.is_err() {
                return;
            }
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn content_length_of(head: &str) -> usize {
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse().ok())
            .unwrap_or(0)
    }

    /// A scripted response with an honest `Content-Length`.
    fn response(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// A scripted response with NO `Content-Length`, so a size cap can only be
    /// enforced while reading the body.
    fn chunked_response(body: &str) -> Vec<u8> {
        let mut out = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        for piece in body.as_bytes().chunks(8) {
            out.push_str(&format!(
                "{:x}\r\n{}\r\n",
                piece.len(),
                String::from_utf8_lossy(piece)
            ));
        }
        out.push_str("0\r\n\r\n");
        out.into_bytes()
    }

    /// A response whose `Content-Length` claims far more than the cap allows.
    fn oversized_response(claimed: usize) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {claimed}\r\n\r\n").into_bytes();
        out.extend_from_slice(&vec![b'x'; claimed]);
        out
    }

    fn signed_op_value(key: &str, method: &str, url: &str) -> Value {
        Value::Object(BTreeMap::from([
            ("key".to_string(), Value::String(key.to_string())),
            ("method".to_string(), Value::String(method.to_string())),
            ("url".to_string(), Value::String(url.to_string())),
        ]))
    }

    // ----- parse_sign_response -----

    #[test]
    fn parse_sign_response_reads_one_op() {
        let result = FunctionResult::Value(Value::Array(vec![signed_op_value(
            "blocks/9f/9f86aa",
            "GET",
            "https://r2.example.com/signed",
        )]));
        let ops = parse_sign_response(result).unwrap();
        assert_eq!(
            ops,
            vec![SignedOp {
                key: "blocks/9f/9f86aa".to_string(),
                method: "GET".to_string(),
                url: "https://r2.example.com/signed".to_string(),
            }]
        );
    }

    #[test]
    fn parse_sign_response_reads_several_ops() {
        let result = FunctionResult::Value(Value::Array(vec![
            signed_op_value("a", "HEAD", "https://x/a"),
            signed_op_value("b", "PUT", "https://x/b"),
        ]));
        let ops = parse_sign_response(result).unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[1].key, "b");
    }

    #[test]
    fn parse_sign_response_propagates_error_message() {
        let result = FunctionResult::ErrorMessage("bad_key".to_string());
        assert_eq!(parse_sign_response(result).unwrap_err(), "bad_key");
    }

    #[test]
    fn parse_sign_response_propagates_convex_error_message() {
        let result = FunctionResult::ConvexError(ConvexError {
            message: "storage_unconfigured".to_string(),
            data: Value::Null,
        });
        assert_eq!(
            parse_sign_response(result).unwrap_err(),
            "storage_unconfigured"
        );
    }

    #[test]
    fn parse_sign_response_rejects_non_array_value() {
        let result = FunctionResult::Value(Value::Null);
        let err = parse_sign_response(result).unwrap_err();
        assert!(err.contains("expected an array"), "got: {err}");
    }

    #[test]
    fn parse_sign_response_rejects_item_missing_url() {
        let item = Value::Object(BTreeMap::from([
            ("key".to_string(), Value::String("a".to_string())),
            ("method".to_string(), Value::String("GET".to_string())),
        ]));
        let result = FunctionResult::Value(Value::Array(vec![item]));
        let err = parse_sign_response(result).unwrap_err();
        assert!(err.contains("\"url\""), "got: {err}");
    }

    #[test]
    fn parse_sign_response_rejects_non_string_field() {
        let item = Value::Object(BTreeMap::from([
            ("key".to_string(), Value::String("a".to_string())),
            ("method".to_string(), Value::String("GET".to_string())),
            ("url".to_string(), Value::Int64(1)),
        ]));
        let result = FunctionResult::Value(Value::Array(vec![item]));
        let err = parse_sign_response(result).unwrap_err();
        assert!(err.contains("expected a string"), "got: {err}");
    }

    // ----- head_result_from_status -----

    #[test]
    fn head_result_from_status_ok_on_2xx() {
        assert_eq!(head_result_from_status(reqwest::StatusCode::OK), Ok(true));
    }

    #[test]
    fn head_result_from_status_false_on_404() {
        assert_eq!(
            head_result_from_status(reqwest::StatusCode::NOT_FOUND),
            Ok(false)
        );
    }

    #[test]
    fn head_result_from_status_errors_on_other_codes() {
        let err = head_result_from_status(reqwest::StatusCode::FORBIDDEN).unwrap_err();
        assert!(err.contains("403"), "got: {err}");
    }

    // ----- method_to_str -----

    #[test]
    fn method_to_str_maps_each_variant() {
        assert_eq!(method_to_str(WarmMethod::Head), "HEAD");
        assert_eq!(method_to_str(WarmMethod::Get), "GET");
        assert_eq!(method_to_str(WarmMethod::Put), "PUT");
    }

    // ----- warm batching (chunks of SIGN_BATCH_LIMIT) -----

    #[test]
    fn warm_ops_split_into_chunks_of_256() {
        let ops: Vec<WarmOp> = (0..301)
            .map(|i| WarmOp {
                key: format!("blocks/aa/{i}"),
                method: WarmMethod::Get,
            })
            .collect();

        let chunks: Vec<&[WarmOp]> = ops.chunks(SIGN_BATCH_LIMIT).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 256);
        assert_eq!(chunks[1].len(), 45);
    }

    #[test]
    fn batch_pairs_preserves_key_and_method_per_chunk() {
        let ops: Vec<WarmOp> = (0..301)
            .map(|i| WarmOp {
                key: format!("blocks/aa/{i}"),
                method: if i % 2 == 0 {
                    WarmMethod::Get
                } else {
                    WarmMethod::Head
                },
            })
            .collect();

        let second_chunk = &ops.chunks(SIGN_BATCH_LIMIT).collect::<Vec<_>>()[1];
        let pairs = batch_pairs(second_chunk);

        assert_eq!(pairs.len(), 45);
        // The chunk starts at global index 256 (even => Get).
        assert_eq!(pairs[0], ("blocks/aa/256", WarmMethod::Get));
        assert_eq!(pairs[1], ("blocks/aa/257", WarmMethod::Head));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn warm_batches_are_signed_with_bounded_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let ops: Vec<WarmOp> = (0..(SIGN_BATCH_LIMIT * 4 + 1))
            .map(|i| WarmOp {
                key: format!("blocks/aa/{i}"),
                method: WarmMethod::Put,
            })
            .collect();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));

        let batches = sign_warm_batches(&ops, {
            let in_flight = in_flight.clone();
            let max_in_flight = max_in_flight.clone();
            move |chunk| {
                let in_flight = in_flight.clone();
                let max_in_flight = max_in_flight.clone();
                Box::pin(async move {
                    let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_in_flight.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    let signed = chunk
                        .iter()
                        .map(|(key, method)| SignedOp {
                            key: key.clone(),
                            method: method_to_str(*method).to_string(),
                            url: format!("https://example.invalid/{key}"),
                        })
                        .collect();
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok(signed)
                })
            }
        })
        .await;

        assert_eq!(batches.signed.len(), ops.len());
        assert!(batches.first_error.is_none());
        assert_eq!(
            max_in_flight.load(Ordering::SeqCst),
            SIGN_BATCH_CONCURRENCY,
            "warm must fill, but never exceed, its bounded signing window"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn warm_batch_failure_preserves_other_successful_results() {
        let ops: Vec<WarmOp> = (0..(SIGN_BATCH_LIMIT * 3))
            .map(|i| WarmOp {
                key: format!("blocks/aa/{i}"),
                method: WarmMethod::Head,
            })
            .collect();

        let batches = sign_warm_batches(&ops, |batch| {
            Box::pin(async move {
                if batch[0].0 == format!("blocks/aa/{SIGN_BATCH_LIMIT}") {
                    return Err(VaultError::S3 {
                        key: "injected batch".to_string(),
                        message: "injected signing failure".to_string(),
                    });
                }
                Ok(batch
                    .into_iter()
                    .map(|(key, method)| SignedOp {
                        url: format!("https://example.invalid/{key}"),
                        key,
                        method: method_to_str(method).to_string(),
                    })
                    .collect())
            })
        })
        .await;

        assert_eq!(
            batches.signed.len(),
            SIGN_BATCH_LIMIT * 2,
            "successful batches must remain available for caching"
        );
        assert!(batches.first_error.is_some());
    }

    // ----- signed URL cache expiration -----

    #[test]
    fn is_fresh_true_for_a_future_instant() {
        let expires_at = Instant::now() + Duration::from_secs(60);
        assert!(is_fresh(expires_at));
    }

    #[test]
    fn is_fresh_false_for_a_past_instant() {
        // An entry whose TTL already elapsed must not be reused.
        let expires_at = Instant::now() - Duration::from_secs(1);
        assert!(!is_fresh(expires_at));
    }

    #[test]
    fn cache_ttl_is_ttl_minus_margin() {
        assert_eq!(
            SIGN_URL_CACHE_TTL,
            Duration::from_secs(SIGN_URL_TTL_SECS - SIGN_URL_TTL_MARGIN_SECS)
        );
    }

    // ----- bounded presigned-URL cache -----

    /// Inserts `count` entries straight into the map with a chosen expiry, so a
    /// test can build a full or already-expired cache without waiting 15 minutes.
    fn fill_cache(cache: &mut UrlCache, count: usize, expires_at: Instant) {
        for i in 0..count {
            cache.entries.insert(
                (format!("blocks/aa/{i}"), WarmMethod::Get),
                CachedUrl {
                    url: format!("https://example.invalid/{i}"),
                    expires_at,
                },
            );
        }
    }

    #[test]
    fn url_cache_drops_expired_entries_instead_of_growing_past_its_cap() {
        let mut cache = UrlCache::default();
        fill_cache(
            &mut cache,
            URL_CACHE_CAPACITY,
            Instant::now() - Duration::from_secs(1),
        );

        cache.insert(
            "blocks/bb/fresh",
            WarmMethod::Put,
            "https://x/1".to_string(),
        );

        assert_eq!(
            cache.entries.len(),
            1,
            "a full cache of expired URLs must be swept, not kept forever"
        );
        assert_eq!(
            cache.get("blocks/bb/fresh", WarmMethod::Put).as_deref(),
            Some("https://x/1")
        );
    }

    #[test]
    fn url_cache_keeps_the_urls_it_already_has_when_full_of_fresh_ones() {
        let mut cache = UrlCache::default();
        fill_cache(
            &mut cache,
            URL_CACHE_CAPACITY,
            Instant::now() + SIGN_URL_CACHE_TTL,
        );

        cache.insert(
            "blocks/bb/late",
            WarmMethod::Get,
            "https://x/late".to_string(),
        );

        assert_eq!(
            cache.entries.len(),
            URL_CACHE_CAPACITY,
            "the cache must never grow past its cap"
        );
        assert!(
            cache.get("blocks/bb/late", WarmMethod::Get).is_none(),
            "an overflowing insert is dropped rather than evicting the URLs warm just signed"
        );
        // Re-signing a key that IS cached still replaces it: that is not growth.
        cache.insert("blocks/aa/0", WarmMethod::Get, "https://x/new".to_string());
        assert_eq!(
            cache.get("blocks/aa/0", WarmMethod::Get).as_deref(),
            Some("https://x/new")
        );
        assert_eq!(cache.entries.len(), URL_CACHE_CAPACITY);
    }

    #[test]
    fn url_cache_get_ignores_an_entry_whose_ttl_elapsed() {
        let mut cache = UrlCache::default();
        fill_cache(&mut cache, 1, Instant::now() - Duration::from_secs(1));
        assert!(cache.get("blocks/aa/0", WarmMethod::Get).is_none());
    }

    #[test]
    fn url_cache_invalidate_forces_the_next_lookup_to_resign() {
        let mut cache = UrlCache::default();
        cache.insert("blocks/aa/0", WarmMethod::Put, "https://x/0".to_string());
        cache.invalidate("blocks/aa/0", WarmMethod::Put);
        assert!(cache.get("blocks/aa/0", WarmMethod::Put).is_none());
    }

    // ----- retry classification and backoff -----

    #[test]
    fn class_for_status_retries_the_transient_classes_only() {
        for code in [408, 429, 409, 500, 502, 503, 504] {
            let status = reqwest::StatusCode::from_u16(code).unwrap();
            assert_eq!(
                class_for_status(status),
                StatusClass::Transient,
                "HTTP {code} must be retried"
            );
        }
        assert_eq!(
            class_for_status(reqwest::StatusCode::FORBIDDEN),
            StatusClass::Stale
        );
        for code in [200, 204, 301, 400, 404, 412] {
            let status = reqwest::StatusCode::from_u16(code).unwrap();
            assert_eq!(
                class_for_status(status),
                StatusClass::Final,
                "HTTP {code} must not be retried"
            );
        }
    }

    #[test]
    fn backoff_delay_doubles_each_attempt_and_stays_inside_its_jitter_window() {
        for attempt in 1..=HTTP_MAX_ATTEMPTS {
            let window = HTTP_RETRY_BASE * (1u32 << (attempt - 1));
            let shortest = backoff_delay(attempt, 0.0);
            let longest = backoff_delay(attempt, 1.0);
            assert_eq!(shortest, window / 2, "a retry must always wait a little");
            assert_eq!(longest, window);
            // A jitter value outside [0, 1) must not escape the window either.
            assert!(backoff_delay(attempt, 4.0) <= window);
            assert!(backoff_delay(attempt, -1.0) >= window / 2);
        }
    }

    // ----- send_with_retry (driver, no sockets) -----

    /// Drives [`send_with_retry`] over `outcomes`, one per attempt, recording the
    /// backoff windows and whether each attempt asked for a re-signed URL.
    async fn drive_retry(
        outcomes: Vec<Attempt<u8>>,
        signed: Arc<StdMutex<Vec<bool>>>,
        slept: Arc<StdMutex<Vec<Duration>>>,
    ) -> VaultResult<u8> {
        let outcomes = StdMutex::new(outcomes.into_iter());
        send_with_retry(
            "blocks/aa/00",
            "GET",
            |refresh| {
                signed.lock().unwrap().push(refresh);
                std::future::ready(Ok("https://example.invalid/signed".to_string()))
            },
            |_url| {
                let next = outcomes.lock().unwrap().next();
                std::future::ready(next.expect("send_with_retry asked for one attempt too many"))
            },
            |delay| {
                slept.lock().unwrap().push(delay);
                std::future::ready(())
            },
        )
        .await
    }

    #[tokio::test]
    async fn send_with_retry_gives_up_after_the_attempt_budget_and_reports_the_last_reason() {
        let signed = Arc::new(StdMutex::new(Vec::new()));
        let slept = Arc::new(StdMutex::new(Vec::new()));
        let outcomes = (0..HTTP_MAX_ATTEMPTS)
            .map(|i| Attempt::Transient(format!("GET returned HTTP 503 (#{i})")))
            .collect();

        let err = drive_retry(outcomes, signed.clone(), slept.clone())
            .await
            .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("#3"), "got: {message}");
        assert!(
            message.contains("gave up after 4 attempts"),
            "got: {message}"
        );
        assert_eq!(signed.lock().unwrap().len(), HTTP_MAX_ATTEMPTS as usize);
        assert_eq!(
            slept.lock().unwrap().len(),
            HTTP_MAX_ATTEMPTS as usize - 1,
            "no backoff after the last attempt"
        );
    }

    #[tokio::test]
    async fn send_with_retry_recovers_from_a_transient_failure() {
        let signed = Arc::new(StdMutex::new(Vec::new()));
        let slept = Arc::new(StdMutex::new(Vec::new()));

        let value = drive_retry(
            vec![
                Attempt::Transient("GET returned HTTP 503".to_string()),
                Attempt::Done(7),
            ],
            signed.clone(),
            slept.clone(),
        )
        .await
        .unwrap();

        assert_eq!(value, 7);
        assert_eq!(slept.lock().unwrap().len(), 1);
        assert_eq!(
            *signed.lock().unwrap(),
            vec![false, false],
            "a transient failure reuses the same presigned URL"
        );
    }

    #[tokio::test]
    async fn send_with_retry_resigns_after_a_403_because_the_signature_expires_first() {
        let signed = Arc::new(StdMutex::new(Vec::new()));
        let slept = Arc::new(StdMutex::new(Vec::new()));

        let value = drive_retry(
            vec![
                Attempt::Stale("GET returned HTTP 403 Forbidden".to_string()),
                Attempt::Done(1),
            ],
            signed.clone(),
            slept.clone(),
        )
        .await
        .unwrap();

        assert_eq!(value, 1);
        assert_eq!(
            *signed.lock().unwrap(),
            vec![false, true],
            "a 403 must invalidate the cached URL and re-sign before retrying"
        );
    }

    #[tokio::test]
    async fn send_with_retry_never_retries_a_fatal_outcome() {
        let signed = Arc::new(StdMutex::new(Vec::new()));
        let slept = Arc::new(StdMutex::new(Vec::new()));

        let err = drive_retry(
            vec![Attempt::Fatal(VaultError::NotFound {
                key: "blocks/aa/00".to_string(),
            })],
            signed.clone(),
            slept.clone(),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, VaultError::NotFound { .. }), "got: {err}");
        assert_eq!(signed.lock().unwrap().len(), 1);
        assert!(slept.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn send_with_retry_does_not_retry_a_signing_failure() {
        let attempts = AtomicUsize::new(0);
        let result: VaultResult<u8> = send_with_retry(
            "blocks/aa/00",
            "GET",
            |_refresh| {
                std::future::ready(Err(VaultError::S3 {
                    key: "batch of 1 ops".to_string(),
                    message: "calling vault:sign: unauthenticated".to_string(),
                }))
            },
            |_url| {
                attempts.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Attempt::Done(0u8))
            },
            |_delay| std::future::ready(()),
        )
        .await;

        let err = result.unwrap_err();
        assert!(err.to_string().contains("vault:sign"), "got: {err}");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            0,
            "a Coordinator refusal is deterministic: never hit the object store"
        );
    }

    // ----- presigned PUT: the create-only contract -----

    #[tokio::test]
    async fn presigned_put_sends_the_signed_create_only_precondition() {
        let store = FakeStore::start(vec![response("200 OK", "")]).await;
        let http = build_http_client();
        let key = "blocks/aa/aa00";

        let attempt = attempt_put(&http, key, store.url(key, "sig0"), b"block bytes").await;

        assert!(matches!(attempt, Attempt::Done(())), "got: {attempt:?}");
        let seen = store.requests();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].to_ascii_lowercase().contains("if-none-match: *"),
            "vault:sign signs `if-none-match` — without it every PUT is 403; got: {}",
            seen[0]
        );
        assert!(seen[0].contains("block bytes"), "got: {}", seen[0]);
    }

    #[tokio::test]
    async fn presigned_put_treats_412_precondition_failed_as_success() {
        let store = FakeStore::start(vec![response("412 Precondition Failed", "")]).await;
        let http = build_http_client();
        let key = "blocks/aa/aa01";

        let attempt = attempt_put(&http, key, store.url(key, "sig0"), b"same bytes").await;

        assert!(
            matches!(attempt, Attempt::Done(())),
            "412 means the content-addressed object is already there — the normal dedup case; got: {attempt:?}"
        );
    }

    #[tokio::test]
    async fn presigned_put_retries_a_503_and_still_sends_the_precondition() {
        let store = FakeStore::start(vec![
            response("503 Service Unavailable", "SlowDown"),
            response("200 OK", ""),
        ])
        .await;
        let http = build_http_client();
        let key = "blocks/aa/aa02";
        let url = store.url(key, "sig0");

        let result = send_with_retry(
            key,
            "PUT",
            |_refresh| std::future::ready(Ok(url.clone())),
            |url| attempt_put(&http, key, url, b"payload"),
            |_delay| std::future::ready(()),
        )
        .await;

        assert!(result.is_ok(), "got: {result:?}");
        let seen = store.requests();
        assert_eq!(seen.len(), 2, "R2 answers 503 under burst load: retry it");
        for request in &seen {
            assert!(
                request.to_ascii_lowercase().contains("if-none-match: *"),
                "every attempt must carry the signed header; got: {request}"
            );
        }
    }

    #[tokio::test]
    async fn presigned_request_resigns_the_url_after_a_403_and_retries_with_the_new_one() {
        let store = FakeStore::start(vec![
            response("403 Forbidden", "SignatureDoesNotMatch"),
            response("200 OK", "page bytes"),
        ])
        .await;
        let http = build_http_client();
        let key = "manifest/aa/aa03";
        let first = store.url(key, "expired");
        let second = store.url(key, "renewed");

        let body = send_with_retry(
            key,
            "GET",
            |refresh| {
                std::future::ready(Ok(if refresh {
                    second.clone()
                } else {
                    first.clone()
                }))
            },
            |url| attempt_get(&http, key, url, max_object_bytes(key)),
            |_delay| std::future::ready(()),
        )
        .await
        .unwrap();

        assert_eq!(body, b"page bytes");
        let seen = store.requests();
        assert_eq!(seen.len(), 2);
        assert!(
            seen[0].contains("X-Amz-Signature=expired"),
            "got: {}",
            seen[0]
        );
        assert!(
            seen[1].contains("X-Amz-Signature=renewed"),
            "a 403 is usually the 15-minute TTL running out mid-sync; got: {}",
            seen[1]
        );
    }

    // ----- presigned HEAD / GET: absence stays non-retryable -----

    #[tokio::test]
    async fn presigned_head_reports_absence_without_retrying() {
        let store = FakeStore::start(vec![response("404 Not Found", "")]).await;
        let http = build_http_client();
        let key = "blocks/aa/aa04";

        let present = send_with_retry(
            key,
            "HEAD",
            |_refresh| std::future::ready(Ok(store.url(key, "sig0"))),
            |url| attempt_head(&http, key, url),
            |_delay| std::future::ready(()),
        )
        .await
        .unwrap();

        assert!(!present);
        assert_eq!(
            store.requests().len(),
            1,
            "404 is an answer, not a failure: retrying it would multiply every head() by 4"
        );
    }

    #[tokio::test]
    async fn presigned_get_maps_404_to_not_found_without_retrying() {
        let store = FakeStore::start(vec![response("404 Not Found", "")]).await;
        let http = build_http_client();
        let key = "blocks/aa/aa05";

        let err = send_with_retry(
            key,
            "GET",
            |_refresh| std::future::ready(Ok(store.url(key, "sig0"))),
            |url| attempt_get(&http, key, url, max_object_bytes(key)),
            |_delay| std::future::ready(()),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, VaultError::NotFound { .. }), "got: {err}");
        assert_eq!(store.requests().len(), 1);
    }

    // ----- redirects are never followed -----

    #[tokio::test]
    async fn presigned_get_refuses_a_redirect_instead_of_forwarding_the_signature() {
        let store = FakeStore::start(vec![
            b"HTTP/1.1 302 Found\r\nLocation: http://attacker.invalid/steal\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ])
        .await;
        let http = build_http_client();
        let key = "blocks/aa/aa06";

        let attempt = attempt_get(&http, key, store.url(key, "sig0"), max_object_bytes(key)).await;

        match attempt {
            Attempt::Fatal(VaultError::S3 { message, .. }) => assert!(
                message.contains("does not follow redirects"),
                "got: {message}"
            ),
            other => panic!("a 3xx must be refused, not chased: {other:?}"),
        }
    }

    // ----- bounded timeouts -----

    #[test]
    fn the_data_plane_client_bounds_the_requests_it_makes() {
        // reqwest exposes its configuration only through `Debug`, and these two
        // settings are worth pinning: an untimed client wedges every Space (the
        // daemon awaits the pull inline and all Spaces share one task), and a
        // followed redirect forwards the presigned signature off-host.
        let debug = format!("{:?}", build_http_client());
        assert!(debug.contains("read_timeout: 60s"), "got: {debug}");
        assert!(
            debug.contains(r#"redirect_policy: "Policy(None)""#),
            "got: {debug}"
        );
    }

    #[tokio::test]
    async fn a_response_that_stalls_after_its_headers_becomes_a_retryable_failure() {
        // The store answers with headers and half a body, then keeps the
        // connection open and goes quiet — the application-level stall that used
        // to hang forever, with nothing in daemon.log. Same client shape as
        // production with a 150ms idle bound so the test stays fast.
        let store = FakeStore::start(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\nhalf".to_vec()
        ])
        .await;
        let http = reqwest::Client::builder()
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .read_timeout(Duration::from_millis(150))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let key = "blocks/aa/aa13";

        let attempt = attempt_get(&http, key, store.url(key, "sig0"), max_object_bytes(key)).await;

        match attempt {
            Attempt::Transient(message) => assert!(message.contains(key), "got: {message}"),
            other => {
                panic!("a stalled transfer must end as a bounded, retryable failure: {other:?}")
            }
        }
    }

    // ----- the download cap -----

    #[test]
    fn max_object_bytes_is_derived_from_the_format_limits() {
        assert_eq!(
            max_object_bytes("blocks/aa/aa07"),
            ft_core::BLOCK_HEADER_LEN as u64 + ft_core::LARGE_CHUNK_MAX as u64 + AEAD_TAG_LEN
        );
        assert_eq!(
            max_object_bytes("manifest/aa/aa07"),
            ft_core::BLOCK_HEADER_LEN as u64
                + (ft_core::LEAF_FANOUT as u64 * ft_core::ENTRY_INLINE_MAX as u64)
                + AEAD_TAG_LEN
        );
        assert!(
            max_object_bytes("blocks/aa/aa07") < max_object_bytes("blocklist/aa/aa07"),
            "the prefix that carries almost every object gets the tight bound"
        );
    }

    #[tokio::test]
    async fn read_capped_body_rejects_a_content_length_over_the_cap() {
        let store = FakeStore::start(vec![oversized_response(4096)]).await;
        let http = build_http_client();
        let resp = http
            .get(store.url("blocks/aa/aa08", "sig0"))
            .send()
            .await
            .unwrap();

        let err = read_capped_body(resp, 16).await.unwrap_err();

        assert!(
            matches!(err, BodyError::TooLarge { limit: 16 }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_capped_body_rejects_an_unmeasured_body_that_grows_past_the_cap() {
        // No Content-Length at all: the only defence is the running total, which
        // is what stops a lying Content-Length too.
        let store = FakeStore::start(vec![chunked_response(&"x".repeat(4096))]).await;
        let http = build_http_client();
        let resp = http
            .get(store.url("blocks/aa/aa09", "sig0"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.content_length(), None);

        let err = read_capped_body(resp, 16).await.unwrap_err();

        assert!(
            matches!(err, BodyError::TooLarge { limit: 16 }),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_capped_body_returns_a_body_that_fits_the_cap() {
        let store = FakeStore::start(vec![response("200 OK", "sixteen bytes!!")]).await;
        let http = build_http_client();
        let resp = http
            .get(store.url("blocks/aa/aa10", "sig0"))
            .send()
            .await
            .unwrap();

        let body = read_capped_body(resp, 16).await.unwrap();

        assert_eq!(body, b"sixteen bytes!!");
    }

    // ----- credential redaction -----

    #[tokio::test]
    async fn transport_message_keeps_the_cause_but_drops_the_presigned_query_string() {
        // Port 1 refuses immediately, which is enough to make reqwest attach the
        // URL it was given to the error.
        let http = build_http_client();
        let url = "http://127.0.0.1:1/blocks/aa/aa11\
                   ?X-Amz-Credential=AKIAEXAMPLE%2F20260729%2Fauto%2Fs3%2Faws4_request\
                   &X-Amz-Signature=deadbeefcafe";
        let err = http.get(url).send().await.unwrap_err();
        assert!(
            err.to_string().contains("deadbeefcafe"),
            "precondition: reqwest's own Display leaks the signature: {err}"
        );

        let message = transport_message("GET", "blocks/aa/aa11", err);

        assert!(
            !message.contains("deadbeefcafe") && !message.contains("X-Amz-Credential"),
            "a presigned URL is a live write capability; daemon.log must not hold one: {message}"
        );
        assert!(
            message.starts_with("GET blocks/aa/aa11: "),
            "got: {message}"
        );
        assert!(
            message.len() > "GET blocks/aa/aa11: ".len() + 10,
            "the real cause must survive redaction: {message}"
        );
    }

    #[tokio::test]
    async fn transport_failures_are_retried_and_reported_without_the_url() {
        let http = build_http_client();
        let key = "blocks/aa/aa12";
        let url = format!("http://127.0.0.1:1/{key}?X-Amz-Signature=deadbeefcafe");
        let attempts = AtomicUsize::new(0);

        let err = send_with_retry(
            key,
            "GET",
            |_refresh| std::future::ready(Ok(url.clone())),
            |url| {
                attempts.fetch_add(1, Ordering::SeqCst);
                attempt_get(&http, key, url, max_object_bytes(key))
            },
            |_delay| std::future::ready(()),
        )
        .await
        .unwrap_err();

        assert_eq!(attempts.load(Ordering::SeqCst), HTTP_MAX_ATTEMPTS as usize);
        let message = err.to_string();
        assert!(!message.contains("deadbeefcafe"), "got: {message}");
        assert!(message.contains("gave up after"), "got: {message}");
    }
}
