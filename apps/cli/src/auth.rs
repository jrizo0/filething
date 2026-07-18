//! Better Auth client — the real auth flow for `filething` (`docs/adr/0014`).
//!
//! Identity now lives in Better Auth (backend `betterAuth.ts` / `http.ts`). This
//! module speaks its HTTP API directly (signup / login / mint a Convex-audience
//! JWT); the JWT is then attached to the Convex websocket via
//! [`convex::ConvexClient::set_auth`] (see [`crate::env`]) so every Coordinator
//! function runs authenticated.
//!
//! ## Endpoints (`<site_url>/api/auth`)
//!
//! - `POST /sign-up/email` `{name,email,password}` → `{token: sessionToken, …}`
//! - `POST /sign-in/email` `{email,password}` → `{token: sessionToken, …}`
//! - `GET  /convex/token` (Bearer sessionToken) → `{token: jwt}`
//!
//! The `sessionToken` lasts ~7 days; the minted `jwt` expires in ~15 min, so
//! long-running processes (daemon/watch) re-mint it (see
//! [`crate::env::connect_authed`]). We send ONLY `Content-Type: application/json`
//! — never `Origin`/`Referer`/`Cookie` (Better Auth treats those as browser
//! calls and applies CSRF/session-cookie rules that reject a headless client).

use std::time::Duration;

use anyhow::{anyhow, Context as _};

/// Env override for the Better Auth site URL (skips URL derivation).
const ENV_SITE_URL: &str = "CONVEX_SITE_URL";

/// Derives the Better Auth base URL (`<site_url>/api/auth`) for a deployment.
///
/// `site_url` is `CONVEX_SITE_URL` when set, else derived from the Convex
/// deployment URL:
/// - `*.convex.cloud` → `*.convex.site` (Convex Cloud's HTTP-actions host),
/// - a self-hosted URL with an explicit port → that port + 1 (the HTTP-actions
///   port; e.g. `http://host:3210` → `http://host:3211`).
///
/// Pure given the environment — the unit tests drive it via `convex_url`.
pub fn auth_base_url(convex_url: &str) -> anyhow::Result<String> {
    let site = match std::env::var(ENV_SITE_URL) {
        Ok(v) if !v.is_empty() => v.trim_end_matches('/').to_string(),
        _ => derive_site_url(convex_url)?,
    };
    Ok(format!("{site}/api/auth"))
}

/// The site-URL derivation half of [`auth_base_url`] (no env), factored out so it
/// is directly unit-testable.
pub fn derive_site_url(convex_url: &str) -> anyhow::Result<String> {
    let mut u = url::Url::parse(convex_url)
        .with_context(|| format!("parsing the Convex URL {convex_url:?}"))?;
    let host = u
        .host_str()
        .ok_or_else(|| anyhow!("Convex URL {convex_url:?} has no host"))?
        .to_string();

    if let Some(prefix) = host.strip_suffix(".convex.cloud") {
        // Convex Cloud: the HTTP-actions host swaps the TLD, default port.
        u.set_host(Some(&format!("{prefix}.convex.site")))
            .map_err(|e| anyhow!("rewriting host to .convex.site: {e}"))?;
        u.set_port(None)
            .map_err(|()| anyhow!("clearing port for .convex.site"))?;
    } else if let Some(port) = u.port() {
        // Self-hosted: HTTP actions live on the Convex port + 1 (3210 → 3211).
        u.set_port(Some(port + 1))
            .map_err(|()| anyhow!("setting the HTTP-actions port {}", port + 1))?;
    }
    // origin() serializes exactly `scheme://host[:port]` for http(s) URLs.
    Ok(u.origin().ascii_serialization())
}

/// A headless HTTP client for Better Auth: no cookie store, no proxy magic —
/// just JSON. Shared by signup/login/token so they all send the same headers.
fn client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        // Bounded timeouts are load-bearing, not just courtesy: the proactive JWT
        // refresh (issue #12) drives `convex_token` from INSIDE the ConvexClient's
        // single worker task (via `set_auth_callback` → the auth fetcher, which the
        // worker awaits), so a request to Better Auth that hangs with no timeout
        // would freeze that Space's entire sync loop indefinitely. Cap the whole
        // call and, tighter, the connect phase.
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("building the HTTP client for Better Auth")
}

/// Extracts the `token` (session token) from a sign-up / sign-in response body,
/// surfacing a Better Auth error `{message}` when the call failed.
fn session_token_from(
    status: reqwest::StatusCode,
    body: &str,
    what: &str,
) -> anyhow::Result<String> {
    let json: serde_json::Value = serde_json::from_str(body)
        .with_context(|| format!("{what}: response was not JSON (HTTP {status}): {body}"))?;
    if !status.is_success() {
        let msg = json.get("message").and_then(|m| m.as_str()).unwrap_or(body);
        return Err(anyhow!("{what} failed (HTTP {status}): {msg}"));
    }
    json.get("token")
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("{what}: response had no session token: {body}"))
}

/// `POST /sign-up/email` — create an Account and return its session token.
pub async fn sign_up(
    base_url: &str,
    name: &str,
    email: &str,
    password: &str,
) -> anyhow::Result<String> {
    let resp = client()?
        .post(format!("{base_url}/sign-up/email"))
        .json(&serde_json::json!({ "name": name, "email": email, "password": password }))
        .send()
        .await
        .context("POST /sign-up/email (is Better Auth reachable? check CONVEX_SITE_URL)")?;
    let status = resp.status();
    let body = resp.text().await.context("reading sign-up response body")?;
    session_token_from(status, &body, "sign-up")
}

/// `POST /sign-in/email` — authenticate an existing Account, return its session
/// token.
pub async fn sign_in(base_url: &str, email: &str, password: &str) -> anyhow::Result<String> {
    let resp = client()?
        .post(format!("{base_url}/sign-in/email"))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .context("POST /sign-in/email (is Better Auth reachable? check CONVEX_SITE_URL)")?;
    let status = resp.status();
    let body = resp.text().await.context("reading sign-in response body")?;
    session_token_from(status, &body, "sign-in")
}

/// `GET /convex/token` (Bearer `session_token`) — mint a fresh Convex-audience
/// JWT. Called at startup and again to refresh (the JWT expires in ~15 min).
pub async fn convex_token(base_url: &str, session_token: &str) -> anyhow::Result<String> {
    let resp = client()?
        .get(format!("{base_url}/convex/token"))
        .bearer_auth(session_token)
        .send()
        .await
        .context("GET /convex/token (mint the Convex JWT)")?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .context("reading convex/token response body")?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("convex/token: response was not JSON (HTTP {status}): {body}"))?;
    if !status.is_success() {
        let msg = json
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or(&body);
        return Err(anyhow!(
            "minting the Convex JWT failed (HTTP {status}): {msg} — has the session expired? \
             re-run `filething login`"
        ));
    }
    json.get("token")
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("convex/token: response had no jwt: {body}"))
}

// ---------------------------------------------------------------------------
// Proactive JWT refresh (issue #12)
// ---------------------------------------------------------------------------
//
// The minted Convex JWT expires in ~15 min. The `convex` crate (0.10.4) only
// invokes its `AuthTokenFetcher` at two moments: once when the callback is
// installed (`force_refresh=false`) and again on every websocket RECONNECT
// (`force_refresh=true`, `base_client/mod.rs:248-270`). It has NO internal timer
// that re-mints while a connection stays up. So if nothing forces a reconnect,
// the token silently expires server-side; the next mutation/query is rejected
// and the client only THEN reconnects to re-mint — the reactive AuthError +
// reconnect storm of #12.
//
// The fix is to re-mint BEFORE expiry. These helpers are the pure core:
// [`CachedJwt`] tracks a minted token and its parsed expiry, [`parse_jwt_exp`]
// reads the `exp` claim, and [`CachedJwt::refresh_due`] /
// [`CachedJwt::secs_until_refresh`] drive both the caching fetcher and the
// proactive timer wired up in [`crate::env`]. They are convex-free and network-
// free so the timing logic is unit-testable in isolation.

/// Re-mint this long before the JWT's `exp`. ~15-min TTL, so 3 min ≈ 20% of the
/// lifetime — comfortably covers clock skew and one mint round-trip while not
/// re-minting more than a few times per hour.
pub const JWT_REFRESH_MARGIN: Duration = Duration::from_secs(180);

/// Assumed JWT lifetime when the `exp` claim can't be parsed (Better Auth mints
/// ~15 min). Deliberately conservative: an unreadable `exp` makes us refresh on
/// this fixed cadence rather than trust an unknown expiry.
pub const JWT_ASSUMED_TTL: Duration = Duration::from_secs(15 * 60);

/// Floor on the proactive-refresh sleep, so a failed re-mint (network blip)
/// retries on a bounded cadence instead of spinning once the token is past its
/// refresh point.
pub const JWT_MIN_REFRESH_SLEEP: Duration = Duration::from_secs(30);

/// A minted Convex JWT plus the absolute instant it expires, so the caching
/// fetcher and the proactive timer can decide when to re-mint. `expires_at` is
/// unix seconds — parsed from the token's `exp` claim, or `minted_at +
/// JWT_ASSUMED_TTL` when the claim is unreadable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedJwt {
    /// The raw Convex-audience JWT.
    pub jwt: String,
    /// Absolute expiry (unix seconds).
    pub expires_at: u64,
}

impl CachedJwt {
    /// Builds a cache entry for a freshly minted `jwt` (minted at `now`, unix
    /// seconds), reading its `exp` claim and falling back to `now +
    /// JWT_ASSUMED_TTL` when the claim can't be read.
    pub fn new(jwt: String, now: u64) -> Self {
        let expires_at =
            parse_jwt_exp(&jwt).unwrap_or_else(|| now.saturating_add(JWT_ASSUMED_TTL.as_secs()));
        Self { jwt, expires_at }
    }

    /// True once the token is within `margin` of expiry (or already past it):
    /// the next non-forced fetch should re-mint rather than reuse the cache.
    pub fn refresh_due(&self, now: u64, margin: Duration) -> bool {
        now.saturating_add(margin.as_secs()) >= self.expires_at
    }

    /// Whole seconds from `now` until the proactive timer should next re-mint:
    /// `(expires_at - margin) - now`, floored at `JWT_MIN_REFRESH_SLEEP` so a
    /// token that is already due (or a failed re-mint that left the cache stale)
    /// retries on a bounded cadence instead of busy-looping.
    pub fn secs_until_refresh(&self, now: u64, margin: Duration) -> u64 {
        let refresh_at = self.expires_at.saturating_sub(margin.as_secs());
        refresh_at
            .saturating_sub(now)
            .max(JWT_MIN_REFRESH_SLEEP.as_secs())
    }
}

/// Reads the `exp` (expiry, unix seconds) claim from a JWT without verifying its
/// signature — we only need the expiry to schedule a re-mint, and the token was
/// just handed to us by our own Better Auth call over TLS. Returns `None` if the
/// token isn't three dot-separated segments, the payload isn't base64url JSON, or
/// there is no numeric `exp`.
pub fn parse_jwt_exp(jwt: &str) -> Option<u64> {
    let mut parts = jwt.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None; // not a well-formed JWT (more than 3 segments)
    }
    let bytes = base64url_decode(payload)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = json.get("exp")?;
    // NumericDate is an integer in practice; accept an integral float defensively.
    exp.as_u64()
        .or_else(|| exp.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
}

/// Minimal, dependency-free base64url decoder (RFC 4648 §5, no padding) for the
/// JWT payload segment. Tolerates trailing `=` padding if present.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        })
    }
    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        buf = (buf << 6) | sextet(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests set/clear CONVEX_SITE_URL — process-global state, while cargo
    // runs tests on parallel threads. Every test that touches the key must hold
    // this lock for its whole body (set + assert + restore), or a concurrent
    // `remove_var` lands between another test's `set_var` and its assertion.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_site_url<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var(ENV_SITE_URL).ok();
        match value {
            Some(v) => std::env::set_var(ENV_SITE_URL, v),
            None => std::env::remove_var(ENV_SITE_URL),
        }
        let out = f();
        match saved {
            Some(v) => std::env::set_var(ENV_SITE_URL, v),
            None => std::env::remove_var(ENV_SITE_URL),
        }
        out
    }

    fn with_site_url_unset<T>(f: impl FnOnce() -> T) -> T {
        with_site_url(None, f)
    }

    #[test]
    fn self_hosted_port_is_incremented() {
        with_site_url_unset(|| {
            assert_eq!(
                derive_site_url("http://localhost:3210").unwrap(),
                "http://localhost:3211"
            );
            assert_eq!(
                derive_site_url("http://127.0.0.1:3210").unwrap(),
                "http://127.0.0.1:3211"
            );
        });
    }

    #[test]
    fn convex_cloud_swaps_tld_and_drops_port() {
        with_site_url_unset(|| {
            assert_eq!(
                derive_site_url("https://happy-animal-123.convex.cloud").unwrap(),
                "https://happy-animal-123.convex.site"
            );
        });
    }

    #[test]
    fn auth_base_url_appends_api_auth() {
        with_site_url_unset(|| {
            assert_eq!(
                auth_base_url("http://localhost:3210").unwrap(),
                "http://localhost:3211/api/auth"
            );
        });
    }

    #[test]
    fn site_url_env_override_wins() {
        with_site_url(Some("https://auth.example.com/"), || {
            // Trailing slash is trimmed; derivation is skipped entirely.
            assert_eq!(
                auth_base_url("http://localhost:3210").unwrap(),
                "https://auth.example.com/api/auth"
            );
        });
    }

    // ----- proactive JWT refresh (issue #12) -----

    /// Base64url-encodes (no padding) — the inverse of [`base64url_decode`], used
    /// only to hand-build test JWT payloads.
    fn base64url_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for &b in bytes {
            buf = (buf << 8) | b as u32;
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((buf >> bits) & 0x3f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buf << (6 - bits)) & 0x3f) as usize] as char);
        }
        out
    }

    /// A syntactically valid JWT (`header.payload.sig`) whose payload is the given
    /// JSON. The header and signature are opaque here — we never verify them.
    fn jwt_with_payload(payload_json: &str) -> String {
        format!(
            "{}.{}.{}",
            base64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            base64url_encode(payload_json.as_bytes()),
            base64url_encode(b"not-a-real-signature"),
        )
    }

    #[test]
    fn base64url_roundtrips() {
        for sample in [
            b"".as_slice(),
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"hello world!",
        ] {
            let encoded = base64url_encode(sample);
            assert_eq!(
                base64url_decode(&encoded).unwrap(),
                sample,
                "roundtrip {sample:?}"
            );
        }
    }

    #[test]
    fn parse_jwt_exp_reads_the_exp_claim() {
        let jwt = jwt_with_payload(r#"{"sub":"user_1","exp":1893456000,"aud":"convex"}"#);
        assert_eq!(parse_jwt_exp(&jwt), Some(1893456000));
    }

    #[test]
    fn parse_jwt_exp_accepts_integral_float_exp() {
        // Some encoders serialize NumericDate as a float; an integral one parses.
        let jwt = jwt_with_payload(r#"{"exp":1893456000.0}"#);
        assert_eq!(parse_jwt_exp(&jwt), Some(1893456000));
    }

    #[test]
    fn parse_jwt_exp_none_without_exp() {
        let jwt = jwt_with_payload(r#"{"sub":"user_1","aud":"convex"}"#);
        assert_eq!(parse_jwt_exp(&jwt), None);
    }

    #[test]
    fn parse_jwt_exp_none_for_malformed_tokens() {
        assert_eq!(parse_jwt_exp("not-a-jwt"), None); // no dots
        assert_eq!(parse_jwt_exp("only.two"), None); // two segments
        assert_eq!(parse_jwt_exp("a.b.c.d"), None); // four segments
        assert_eq!(parse_jwt_exp("aaa.!!!not-base64!!!.ccc"), None); // bad payload
    }

    #[test]
    fn cached_jwt_new_uses_the_exp_claim() {
        let jwt = jwt_with_payload(r#"{"exp":1000}"#);
        let cached = CachedJwt::new(jwt.clone(), 500);
        assert_eq!(cached.expires_at, 1000);
        assert_eq!(cached.jwt, jwt);
    }

    #[test]
    fn cached_jwt_new_falls_back_to_assumed_ttl_without_exp() {
        let jwt = jwt_with_payload(r#"{"sub":"user_1"}"#);
        let cached = CachedJwt::new(jwt, 1000);
        assert_eq!(cached.expires_at, 1000 + JWT_ASSUMED_TTL.as_secs());
    }

    #[test]
    fn refresh_due_is_false_well_before_expiry() {
        let cached = CachedJwt {
            jwt: "j".into(),
            expires_at: 1000,
        };
        // 15 min TTL, 3 min margin: at now=700 (300s left) not yet due.
        assert!(!cached.refresh_due(700, JWT_REFRESH_MARGIN));
    }

    #[test]
    fn refresh_due_is_true_within_margin_and_past_expiry() {
        let cached = CachedJwt {
            jwt: "j".into(),
            expires_at: 1000,
        };
        // now=821 → 179s left, inside the 180s margin → due.
        assert!(cached.refresh_due(821, JWT_REFRESH_MARGIN));
        // Already expired → due.
        assert!(cached.refresh_due(2000, JWT_REFRESH_MARGIN));
    }

    #[test]
    fn secs_until_refresh_counts_down_to_the_margin() {
        let cached = CachedJwt {
            jwt: "j".into(),
            expires_at: 1000,
        };
        // refresh_at = 1000 - 180 = 820; from now=100 that is 720s away.
        assert_eq!(cached.secs_until_refresh(100, JWT_REFRESH_MARGIN), 720);
    }

    #[test]
    fn secs_until_refresh_floors_when_due_or_expired() {
        let cached = CachedJwt {
            jwt: "j".into(),
            expires_at: 1000,
        };
        // Past the refresh point: floored to the min retry cadence, never 0.
        assert_eq!(
            cached.secs_until_refresh(900, JWT_REFRESH_MARGIN),
            JWT_MIN_REFRESH_SLEEP.as_secs()
        );
        assert_eq!(
            cached.secs_until_refresh(5000, JWT_REFRESH_MARGIN),
            JWT_MIN_REFRESH_SLEEP.as_secs()
        );
    }
}
