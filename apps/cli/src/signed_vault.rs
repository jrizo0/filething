//! `SignedVault` — the end-user's data plane: it never holds `S3_*`
//! credentials. It asks the Coordinator's `vault:sign` action for a
//! short-lived presigned URL per operation, then executes that URL directly
//! against the object store with `reqwest`. Contrast with
//! [`ft_vault::S3Vault`], which holds real credentials and is the
//! operator-only path used by `gc` (`docs/adr/`, `crates/ft-vault/src/lib.rs`).

use std::collections::{BTreeMap, HashMap};
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

/// Maps a [`WarmMethod`] to the HTTP verb string `vault:sign` expects.
fn method_to_str(method: WarmMethod) -> &'static str {
    match method {
        WarmMethod::Head => "HEAD",
        WarmMethod::Get => "GET",
        WarmMethod::Put => "PUT",
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
    cache: StdMutex<HashMap<(String, WarmMethod), CachedUrl>>,
}

impl SignedVault {
    /// Builds a `SignedVault` over `client`, which the caller has already
    /// authenticated (`set_auth`/`set_auth_callback`) so `vault:sign` runs as
    /// the right Account.
    pub fn new(client: ConvexClient) -> Self {
        Self {
            client: Mutex::new(client),
            http: reqwest::Client::new(),
            cache: StdMutex::new(HashMap::new()),
        }
    }

    /// Looks up a still-fresh cached URL for `(key, method)`, if any.
    fn cached_url(&self, key: &str, method: WarmMethod) -> Option<String> {
        let cache = self.cache.lock().unwrap();
        cache
            .get(&(key.to_string(), method))
            .filter(|cached| is_fresh(cached.expires_at))
            .map(|cached| cached.url.clone())
    }

    /// Remembers a freshly-signed `url` for `(key, method)` until it expires.
    fn cache_url(&self, key: &str, method: WarmMethod, url: String) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            (key.to_string(), method),
            CachedUrl {
                url,
                expires_at: Instant::now() + SIGN_URL_CACHE_TTL,
            },
        );
    }

    /// Returns a presigned URL for `(key, method)`: a fresh cache hit, or a
    /// fresh `vault:sign` call whose result is cached for next time.
    async fn url_for(&self, key: &str, method: WarmMethod) -> VaultResult<String> {
        if let Some(url) = self.cached_url(key, method) {
            return Ok(url);
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
        let url = self.url_for(key, WarmMethod::Head).await?;
        let resp = self
            .http
            .head(&url)
            .send()
            .await
            .map_err(|err| VaultError::S3 {
                key: key.to_string(),
                message: format!("HEAD {key}: {err}"),
            })?;
        head_result_from_status(resp.status()).map_err(|message| VaultError::S3 {
            key: key.to_string(),
            message,
        })
    }

    async fn get(&self, key: &str) -> VaultResult<Vec<u8>> {
        let url = self.url_for(key, WarmMethod::Get).await?;
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|err| VaultError::S3 {
                key: key.to_string(),
                message: format!("GET {key}: {err}"),
            })?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(VaultError::NotFound {
                key: key.to_string(),
            });
        }
        if !status.is_success() {
            return Err(VaultError::S3 {
                key: key.to_string(),
                message: format!("GET {key} returned HTTP {status}"),
            });
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|err| VaultError::S3 {
                key: key.to_string(),
                message: format!("reading GET {key} body: {err}"),
            })
    }

    async fn put(&self, key: &str, body: Vec<u8>) -> VaultResult<()> {
        let url = self.url_for(key, WarmMethod::Put).await?;
        let resp = self
            .http
            .put(&url)
            .body(body)
            .send()
            .await
            .map_err(|err| VaultError::S3 {
                key: key.to_string(),
                message: format!("PUT {key}: {err}"),
            })?;
        let status = resp.status();
        if !status.is_success() {
            return Err(VaultError::S3 {
                key: key.to_string(),
                message: format!("PUT {key} returned HTTP {status}"),
            });
        }
        Ok(())
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
}
