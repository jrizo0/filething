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
}
