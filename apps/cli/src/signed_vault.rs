//! `SignedVault` — the end-user's data plane: it never holds `S3_*`
//! credentials. It asks the Coordinator's `vault:sign` action for a
//! short-lived presigned URL per operation, then executes that URL directly
//! against the object store with `reqwest`. Contrast with
//! [`ft_vault::S3Vault`], which holds real credentials and is the
//! operator-only path used by `gc` (`docs/adr/`, `crates/ft-vault/src/lib.rs`).

use std::collections::BTreeMap;

use async_trait::async_trait;
use convex::{ConvexClient, FunctionResult, Value};
use ft_vault::{Vault, VaultError, VaultObject, VaultResult};
use tokio::sync::Mutex;

/// The Convex action that mints presigned S3 URLs for the caller's Account.
const SIGN_ACTION: &str = "vault:sign";

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
}

impl SignedVault {
    /// Builds a `SignedVault` over `client`, which the caller has already
    /// authenticated (`set_auth`/`set_auth_callback`) so `vault:sign` runs as
    /// the right Account.
    pub fn new(client: ConvexClient) -> Self {
        Self {
            client: Mutex::new(client),
            http: reqwest::Client::new(),
        }
    }

    /// Calls `vault:sign` for exactly one `(key, method)` pair and returns its
    /// presigned URL.
    async fn sign_one(&self, key: &str, method: &str) -> VaultResult<String> {
        // Clone the client and drop the lock immediately: `action` awaits a
        // network round-trip, and holding the mutex across it would serialize
        // every Vault call onto one in-flight request at a time.
        let mut client = self.client.lock().await.clone();

        let op = Value::Object(BTreeMap::from([
            ("key".to_string(), Value::String(key.to_string())),
            ("method".to_string(), Value::String(method.to_string())),
        ]));
        let args = BTreeMap::from([("ops".to_string(), Value::Array(vec![op]))]);

        let result = client
            .action(SIGN_ACTION, args)
            .await
            .map_err(|err| VaultError::S3 {
                key: key.to_string(),
                message: format!("calling {SIGN_ACTION}: {err}"),
            })?;

        let ops = parse_sign_response(result).map_err(|message| VaultError::S3 {
            key: key.to_string(),
            message,
        })?;

        ops.into_iter()
            .find(|op| op.key == key && op.method.eq_ignore_ascii_case(method))
            .map(|op| op.url)
            .ok_or_else(|| VaultError::S3 {
                key: key.to_string(),
                message: format!("{SIGN_ACTION} did not return a presigned URL for {method} {key}"),
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
        let url = self.sign_one(key, "HEAD").await?;
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
        let url = self.sign_one(key, "GET").await?;
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
        let url = self.sign_one(key, "PUT").await?;
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
}
