//! ft-coordinator — Rust client for the Coordinator (control plane). `§6.2`, `§7`
//! (client side), `§8`.
//!
//! Wraps the official [`convex`] crate ([`convex::ConvexClient`]) and exposes the
//! filething control-plane operations as typed Rust methods: device/account
//! resolution ([`Coordinator::ensure_device`], the authenticated get-or-create
//! that replaced the MVP bootstrap/claim pairing), Space creation and lookup, the
//! Space-head compare-and-swap ([`Coordinator::commit_revision`], `§7`), revision
//! lookup by seq, and the reactive head subscription
//! ([`Coordinator::subscribe_head`], the change feed of `§8`).
//!
//! Auth: every contract function is now authenticated (`ctx.auth`, a Convex-
//! audience JWT minted by Better Auth). The caller attaches the JWT on the
//! underlying [`convex::ConvexClient`] (`set_auth` / `set_auth_callback`) before
//! building the [`Coordinator`]; this crate only shapes the typed calls.
//!
//! Only 32-byte pointers/hashes and tiny control scalars cross this boundary —
//! never file bytes nor Manifests (`§1`, `§6.2`). [`Cid`]/[`Pcid`] and the
//! `manifestRoot` travel as Convex bytestrings (`v.bytes()` ⇆ [`Value::Bytes`]),
//! Convex document ids travel as strings ([`AccountId`]/[`DeviceId`]/
//! [`RevisionId`]).
//!
//! ## Two layers
//!
//! - **Wire mapping** ([`wire`] helpers + the `from_value` parsers): pure,
//!   network-free functions that build the argument [`Value`] maps for each
//!   contract function and parse the documents Convex returns. These are what the
//!   unit tests exercise — no Convex deployment is required.
//! - **Transport** ([`Coordinator`]): thin async wrappers that call
//!   [`convex::ConvexClient`] with those argument maps and interpret the
//!   [`FunctionResult`]. The conflict path of the commit CAS (`§7`) is surfaced
//!   as a distinguishable [`CommitError::Conflict`].
//!
//! Two properties of the transport layer are load-bearing rather than incidental:
//! every call carries a deadline ([`DEFAULT_CALL_TIMEOUT`], see [`with_deadline`])
//! because the underlying client would otherwise retry a dead socket forever, and
//! [`Coordinator::list_revisions_from`] pages a long Revision chain because the GC
//! mark set it feeds must be COMPLETE or an error (`§6.3`, `docs/adr/0007`).

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use convex::{ConvexClient, ConvexError, FunctionResult, Value};
use ft_core::{Cid, Pcid};
use futures::{Stream, StreamExt};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from talking to the Coordinator.
#[derive(Debug, Error)]
pub enum CoordinatorError {
    /// The underlying [`convex`] transport failed (connection, protocol, …).
    #[error("convex transport error: {0}")]
    Transport(String),

    /// The referenced Space does not exist. Backend code `space_not_found`.
    /// Folded together with [`Self::NotAuthorized`] by the CLI into one "not
    /// found or no access" message, so the backend never leaks which Spaces
    /// exist — but kept distinct here so logs/verbose output (`RUST_LOG=debug`) stay precise.
    #[error("space not found: {message}")]
    SpaceNotFound {
        /// The raw backend message (carries the Convex Request ID in prod).
        message: String,
    },

    /// The caller is authenticated but does not own the Space/Device it named.
    /// Backend code `forbidden`.
    #[error("not authorized: {message}")]
    NotAuthorized {
        /// The raw backend message (carries the Convex Request ID in prod).
        message: String,
    },

    /// No authenticated identity, or an authenticated identity with no Account
    /// yet. Backend codes `unauthenticated` / `no_account`.
    #[error("not authenticated: {message}")]
    NotAuthenticated {
        /// The raw backend message (carries the Convex Request ID in prod).
        message: String,
    },

    /// The Vault (object store) is unreachable or misconfigured on the
    /// Coordinator. Backend codes `vault_unavailable` / `storage_unconfigured`.
    /// (Malformed-request codes like `bad_key`/`bad_request` are client bugs
    /// and stay on the [`CoordinatorError::Function`] fallback.)
    #[error("vault unavailable: {message}")]
    VaultUnavailable {
        /// The raw backend message (carries the Convex Request ID in prod).
        message: String,
    },

    /// A commit CAS conflict (`§7`): the Space head moved under the expected
    /// base. Backend code `conflict`. Callers usually branch on this via
    /// [`CommitError::Conflict`]; the variant exists so the classifier is total.
    #[error("commit conflict: {message}")]
    Conflict {
        /// The raw backend message (carries the Convex Request ID in prod).
        message: String,
    },

    /// The Coordinator refused the arguments as malformed. Backend codes
    /// `bad_request` / `bad_key` / `bad_manifest_root_cid` / `bad_meta_blob_cid`
    /// / `bad_space_key`. DETERMINISTIC — the same call fails identically on
    /// every retry, so callers must NOT back off and repeat it; it means this
    /// client (or the value it was handed) is wrong.
    #[error("coordinator rejected the request ({code}): {message}")]
    BadRequest {
        /// The backend `data.code`, kept verbatim so a new code still lands here
        /// with its identity intact.
        code: String,
        /// The raw backend message (carries the Convex Request ID in prod).
        message: String,
    },

    /// The Revision chain past the requested `minSeq` is longer than one
    /// `revisions:listFromSeq` answer may carry. Backend code
    /// `too_many_revisions`. [`Coordinator::list_revisions_from`] handles this by
    /// paging, so reaching a caller means even a windowed walk hit it — the set
    /// is INCOMPLETE and a GC mark phase must refuse to sweep (`§6.3`,
    /// `docs/adr/0007`).
    #[error("too many revisions in one window: {message}")]
    TooManyRevisions {
        /// The raw backend message (carries the limit and the window bounds).
        message: String,
    },

    /// The Space already has an escrow `space_key`, so `spaces:ensureSpaceKey`
    /// declined to overwrite it. Backend code `space_key_already_set`. Benign for
    /// an idempotent back-fill: the key that is already there is the right one.
    #[error("space key already set: {message}")]
    SpaceKeyAlreadySet {
        /// The raw backend message (carries the Convex Request ID in prod).
        message: String,
    },

    /// The Space head points at a Revision that does not exist — a Coordinator
    /// data-integrity fault, not a client error. Backend code `dangling_head`.
    #[error("space head points at a missing revision: {message}")]
    DanglingHead {
        /// The raw backend message (carries the Convex Request ID in prod).
        message: String,
    },

    /// One Coordinator round trip exceeded [`DEFAULT_CALL_TIMEOUT`] (or the
    /// override set by [`Coordinator::with_call_timeout`]). See
    /// [`with_deadline`] for why this crate imposes a deadline at all.
    #[error("coordinator did not answer {function} within {timeout:?}")]
    Timeout {
        /// The contract function that was called (e.g. `revisions:commit`).
        function: &'static str,
        /// The deadline that elapsed.
        timeout: Duration,
    },

    /// A Convex function returned an application error (a thrown `Error` or a
    /// `ConvexError`) whose `code` is not one this client maps to a typed
    /// variant above. Carries the raw message (and, in prod, the Request ID) so
    /// verbose output (`RUST_LOG=debug`)/logs still shows the full detail.
    #[error("convex function error: {0}")]
    Function(String),

    /// A returned document was missing an expected field.
    #[error("missing field {field:?} in {context}")]
    MissingField {
        /// The absent field name.
        field: &'static str,
        /// Where the field was expected (function/document name).
        context: &'static str,
    },

    /// A returned field had an unexpected Convex value type or shape.
    #[error("unexpected value for field {field:?} in {context}: {detail}")]
    UnexpectedValue {
        /// The offending field name.
        field: &'static str,
        /// Where the value came from.
        context: &'static str,
        /// Human-readable detail (what was expected vs. seen).
        detail: String,
    },

    /// A bytestring field was not exactly 32 bytes (a [`Cid`]/[`Pcid`] must be).
    #[error("invalid id length for {field:?} in {context}: expected 32 bytes, got {got}")]
    InvalidIdLength {
        /// The offending field name.
        field: &'static str,
        /// Where the value came from.
        context: &'static str,
        /// Actual byte length seen.
        got: usize,
    },
}

/// Crate `Result` alias over [`CoordinatorError`].
pub type Result<T> = std::result::Result<T, CoordinatorError>;

// ---------------------------------------------------------------------------
// Document-id newtypes (Convex `v.id(...)` ⇆ string)
// ---------------------------------------------------------------------------

/// Generates a thin `String` newtype for a Convex document id (`v.id(...)`),
/// which serializes on the wire as a string. Separate types keep account /
/// device / revision / space ids from being mixed up at call sites.
macro_rules! id_string_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub String);

        impl $name {
            /// Wraps a raw Convex id string.
            #[inline]
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            /// Borrows the id as a string slice.
            #[inline]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The Convex [`Value`] form (a string) for use as a function arg.
            #[inline]
            pub fn to_value(&self) -> Value {
                Value::String(self.0.clone())
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_string_newtype! {
    /// Id of an `Account` document (`v.id("accounts")`). `§6.2`.
    AccountId
}
id_string_newtype! {
    /// Id of a `Device` document (`v.id("devices")`). `§6.2`.
    DeviceId
}
id_string_newtype! {
    /// Id of a `Revision` document (`v.id("revisions")`). `§6.2`.
    RevisionId
}
id_string_newtype! {
    /// Id of a `Space` document (`v.id("spaces")`). `§6.2`.
    SpaceId
}

// ---------------------------------------------------------------------------
// Wire-mapping helpers (pure, network-free) — Cid/Pcid ⇆ v.bytes()
// ---------------------------------------------------------------------------

/// Pure helpers that convert between filething domain types and Convex
/// [`Value`]s. Kept in one module so the unit tests can exercise the full
/// wire mapping without any Convex deployment.
pub mod wire {
    use super::*;

    /// Encodes a [`Cid`] as a Convex bytestring (`v.bytes()`). `§6.2`.
    pub fn cid_to_value(cid: &Cid) -> Value {
        Value::Bytes(cid.as_bytes().to_vec())
    }

    /// Encodes a [`Pcid`] as a Convex bytestring (`v.bytes()`). `§6.2`.
    pub fn pcid_to_value(pcid: &Pcid) -> Value {
        Value::Bytes(pcid.as_bytes().to_vec())
    }

    /// Decodes a Convex bytestring back into a [`Cid`], checking the 32-byte
    /// length. Errors carry `field`/`context` for actionable diagnostics.
    pub fn value_to_cid(v: &Value, field: &'static str, context: &'static str) -> Result<Cid> {
        let arr = bytes32(v, field, context)?;
        Ok(Cid::new(arr))
    }

    /// Decodes a Convex bytestring back into a [`Pcid`], checking length.
    pub fn value_to_pcid(v: &Value, field: &'static str, context: &'static str) -> Result<Pcid> {
        let arr = bytes32(v, field, context)?;
        Ok(Pcid::new(arr))
    }

    /// Extracts exactly 32 bytes from a [`Value::Bytes`].
    pub(super) fn bytes32(
        v: &Value,
        field: &'static str,
        context: &'static str,
    ) -> Result<[u8; 32]> {
        match v {
            Value::Bytes(b) => {
                b.as_slice()
                    .try_into()
                    .map_err(|_| CoordinatorError::InvalidIdLength {
                        field,
                        context,
                        got: b.len(),
                    })
            }
            other => Err(CoordinatorError::UnexpectedValue {
                field,
                context,
                detail: format!("expected bytes, got {}", value_kind(other)),
            }),
        }
    }

    /// Reads a borrowed field out of a [`Value::Object`], erroring if absent.
    pub(super) fn field<'a>(
        obj: &'a BTreeMap<String, Value>,
        key: &'static str,
        context: &'static str,
    ) -> Result<&'a Value> {
        obj.get(key).ok_or(CoordinatorError::MissingField {
            field: key,
            context,
        })
    }

    /// Interprets a [`Value`] as the document object it must be.
    pub(super) fn as_object<'a>(
        v: &'a Value,
        context: &'static str,
    ) -> Result<&'a BTreeMap<String, Value>> {
        match v {
            Value::Object(map) => Ok(map),
            other => Err(CoordinatorError::UnexpectedValue {
                field: "<root>",
                context,
                detail: format!("expected object, got {}", value_kind(other)),
            }),
        }
    }

    /// Reads a `u64` from a Convex number. Convex numbers arrive as
    /// [`Value::Int64`] (the schema declares `seq`/`baseSeqInUse` as numbers);
    /// a [`Value::Float64`] with an integral value is also accepted defensively.
    pub(super) fn as_u64(v: &Value, field: &'static str, context: &'static str) -> Result<u64> {
        match v {
            Value::Int64(n) => u64::try_from(*n).map_err(|_| CoordinatorError::UnexpectedValue {
                field,
                context,
                detail: format!("negative seq {n}"),
            }),
            Value::Float64(f) if f.fract() == 0.0 && *f >= 0.0 => Ok(*f as u64),
            other => Err(CoordinatorError::UnexpectedValue {
                field,
                context,
                detail: format!("expected integer number, got {}", value_kind(other)),
            }),
        }
    }

    /// Reads a `String` field (e.g. an id, or a `name` of kind `v.string()`).
    pub(super) fn as_string(
        v: &Value,
        field: &'static str,
        context: &'static str,
    ) -> Result<String> {
        match v {
            Value::String(s) => Ok(s.clone()),
            other => Err(CoordinatorError::UnexpectedValue {
                field,
                context,
                detail: format!("expected string, got {}", value_kind(other)),
            }),
        }
    }

    /// `v.union(v.id(...), v.null())` field → `Option<String>` (the id, or
    /// `None` when null/absent).
    pub(super) fn as_opt_string(
        obj: &BTreeMap<String, Value>,
        key: &'static str,
        context: &'static str,
    ) -> Result<Option<String>> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(other) => Err(CoordinatorError::UnexpectedValue {
                field: key,
                context,
                detail: format!("expected id-string or null, got {}", value_kind(other)),
            }),
        }
    }

    /// `v.union(v.bytes(), v.null())` field → `Option<Cid>`.
    pub(super) fn as_opt_cid(
        obj: &BTreeMap<String, Value>,
        key: &'static str,
        context: &'static str,
    ) -> Result<Option<Cid>> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v @ Value::Bytes(_)) => Ok(Some(value_to_cid(v, key, context)?)),
            Some(other) => Err(CoordinatorError::UnexpectedValue {
                field: key,
                context,
                detail: format!("expected bytes or null, got {}", value_kind(other)),
            }),
        }
    }

    /// `v.union(v.bytes(), v.null())` (or an absent) field → `Option<[u8; 32]>`,
    /// checking the 32-byte length. Used for the optional escrow `spaceKey`.
    pub(super) fn as_opt_bytes32(
        obj: &BTreeMap<String, Value>,
        key: &'static str,
        context: &'static str,
    ) -> Result<Option<[u8; 32]>> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v @ Value::Bytes(_)) => Ok(Some(bytes32(v, key, context)?)),
            Some(other) => Err(CoordinatorError::UnexpectedValue {
                field: key,
                context,
                detail: format!("expected bytes or null, got {}", value_kind(other)),
            }),
        }
    }

    /// Optional `u64` from a nullable number field.
    pub(super) fn as_opt_u64(
        obj: &BTreeMap<String, Value>,
        key: &'static str,
        context: &'static str,
    ) -> Result<Option<u64>> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => Ok(Some(as_u64(v, key, context)?)),
        }
    }

    /// A short human label for a [`Value`]'s kind, for error messages.
    pub(super) fn value_kind(v: &Value) -> &'static str {
        match v {
            Value::Null => "null",
            Value::Int64(_) => "int64",
            Value::Float64(_) => "float64",
            Value::Boolean(_) => "boolean",
            Value::String(_) => "string",
            Value::Bytes(_) => "bytes",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

// ---------------------------------------------------------------------------
// Result / output types
// ---------------------------------------------------------------------------

/// Result of `auth:ensureDevice` — the authenticated get-or-create of the
/// caller's Account (keyed by the JWT subject) and this Device (by name). Called
/// at startup by every client; replaces the MVP bootstrap/claim pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureDeviceResult {
    /// The caller's Account (created on first call for this identity).
    pub account_id: AccountId,
    /// This Device (created on first call for this name).
    pub device_id: DeviceId,
    /// The AUTHORITATIVE per-Account escrow `dedup_secret` (`§4.4`). The client
    /// sends a fresh candidate; the server returns the existing one when the
    /// Account already had it, so every Device of the same user converges on the
    /// same 32-byte secret.
    pub dedup_secret: [u8; 32],
}

/// A `Space` document (`spaces:get` / `spaces:listMine`). `§6.2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Space {
    /// The Space's own document id.
    pub space_id: SpaceId,
    /// Owning Account.
    pub account_id: AccountId,
    /// Semantic name bytes (`v.bytes()`; UTF-8 cleartext in the MVP). `§6.2`.
    pub name: Vec<u8>,
    /// The Space head — `None` when the Space has no Revisions yet. `§6.2`.
    pub head_revision_id: Option<RevisionId>,
    /// Pointer into the Vault to the Space metadata blob (chunk secret, …).
    pub meta_blob_cid: Cid,
    /// The per-Space escrow `space_key` (`§4.5`): 32 bytes the client generated at
    /// `create` and the Coordinator only hands back to the owning Account. `None`
    /// for a legacy Space created before escrow existed — such a Space stays on
    /// the cleartext (`alg=0`) path.
    pub space_key: Option<[u8; 32]>,
}

/// A `Revision` document (`revisions:bySeq`). `§6.2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    /// This Revision's id.
    pub revision_id: RevisionId,
    /// The Space it belongs to.
    pub space_id: SpaceId,
    /// Parent Revision — `None` for the first Revision in the chain. `§6.2`.
    pub parent: Option<RevisionId>,
    /// Monotonic per-Space sequence number (the linear feed order). `§6.2`.
    pub seq: u64,
    /// Root of the Manifest B-tree in the Vault (32 bytes). `§6.2`.
    pub manifest_root_cid: Cid,
    /// The Device that authored this Revision.
    pub author_device_id: DeviceId,
}

/// Success of the commit CAS (`revisions:commit`). `§7`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOk {
    /// The newly inserted Revision.
    pub revision_id: RevisionId,
    /// Its assigned per-Space seq.
    pub seq: u64,
}

/// Failure of the commit CAS. `§7`. [`CommitError::Conflict`] is the
/// distinguishable "the head moved under me" case the caller must reconcile.
#[derive(Debug, Error)]
pub enum CommitError {
    /// CAS conflict: the live Space head was not `expected_base` when the
    /// mutation ran (another Device advanced it). The caller must pull, reconcile
    /// per-file (`§10`), rebuild the Manifest and retry (`§7` step 6).
    #[error("commit conflict: Space head advanced under the expected base")]
    Conflict,

    /// Any other failure (transport, non-conflict function error, bad response).
    #[error(transparent)]
    Other(#[from] CoordinatorError),
}

/// One value pushed by the reactive head subscription (`spaces:head`). The
/// change feed of `§8`: a new item appears every time the Space head moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadUpdate {
    /// Current head Revision id — `None` while the Space has no Revisions.
    pub head_revision_id: Option<RevisionId>,
    /// The head Revision's seq, if any.
    pub seq: Option<u64>,
    /// The head's `manifestRootCid` (32 bytes), if any. `§8`.
    pub manifest_root: Option<Cid>,
    /// The head Revision's parent, if any.
    pub parent: Option<RevisionId>,
}

/// A retained Revision's GC-relevant fields (`revisions:listFromSeq`). The GC
/// keeps every Vault object reachable from `manifest_root_cid`. `§6.3`,
/// `docs/adr/0007`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRoot {
    /// The Revision's id.
    pub revision_id: RevisionId,
    /// Its per-Space seq.
    pub seq: u64,
    /// The Manifest B-tree root to keep reachable (32 bytes).
    pub manifest_root_cid: Cid,
}

/// The recomputed GC retention floor (`spaces:refreshRetentionFloor`). `§6.3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionFloor {
    /// `min(baseSeqInUse)` over the Account's Devices, clamped to `[0, head]`.
    /// Revisions with `seq >= retention_floor_seq` must never be swept.
    pub retention_floor_seq: u64,
    /// The current head seq, if the Space has any Revision.
    pub head_seq: Option<u64>,
}

// ---------------------------------------------------------------------------
// Contract function names (single source of truth)
// ---------------------------------------------------------------------------

mod func {
    pub const AUTH_ENSURE_DEVICE: &str = "auth:ensureDevice";
    pub const SPACES_CREATE: &str = "spaces:create";
    pub const SPACES_GET: &str = "spaces:get";
    pub const SPACES_LIST_MINE: &str = "spaces:listMine";
    pub const SPACES_HEAD: &str = "spaces:head";
    pub const SPACES_REFRESH_RETENTION_FLOOR: &str = "spaces:refreshRetentionFloor";
    pub const REVISIONS_COMMIT: &str = "revisions:commit";
    pub const REVISIONS_BY_SEQ: &str = "revisions:bySeq";
    pub const REVISIONS_LIST_FROM_SEQ: &str = "revisions:listFromSeq";
    pub const DEVICES_SET_BASE_SEQ: &str = "devices:setBaseSeq";
}

/// Marker the backend's `revisions:commit` mutation uses to flag a CAS conflict
/// in a machine-distinguishable way: a thrown `ConvexError` whose `data` object
/// carries `{ "code": "conflict" }`.
const CONFLICT_CODE: &str = "conflict";

/// Codes that mean "the arguments were malformed" → [`CoordinatorError::BadRequest`].
/// All deterministic: a retry sends the same bad value and fails the same way.
const BAD_REQUEST_CODES: &[&str] = &[
    "bad_request",
    "bad_key",
    "bad_manifest_root_cid",
    "bad_meta_blob_cid",
    "bad_space_key",
];

/// Every `data.code` the backend can throw EXCEPT [`CONFLICT_CODE`]
/// (`packages/backend/convex/*.ts`). Two jobs: it documents the contract in one
/// place, and it keeps the legacy message fallback in
/// [`message_suggests_conflict`] from reading a typed, deterministic failure as a
/// retryable CAS race. The backend deliberately keeps `"conflict"` out of every
/// other code for the same reason — `codes_other_than_conflict_never_contain_the_word`
/// locks that in from this side.
const NON_CONFLICT_CODES: &[&str] = &[
    "space_not_found",
    "device_not_found",
    "forbidden",
    "unauthenticated",
    "no_account",
    "vault_unavailable",
    "storage_unconfigured",
    "too_many_revisions",
    "space_key_already_set",
    "dangling_head",
    "bad_request",
    "bad_key",
    "bad_manifest_root_cid",
    "bad_meta_blob_cid",
    "bad_space_key",
    "bad_dedup_secret",
    "dedup_secret_required",
];

// ---------------------------------------------------------------------------
// Argument builders (pure)
// ---------------------------------------------------------------------------

fn obj(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> BTreeMap<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn ensure_device_args(device_name: &str, dedup_secret: &[u8; 32]) -> BTreeMap<String, Value> {
    obj([
        ("deviceName", Value::String(device_name.to_string())),
        ("dedupSecret", Value::Bytes(dedup_secret.to_vec())),
    ])
}

fn create_space_args(
    name: &[u8],
    meta_blob_cid: &Cid,
    space_key: &[u8; 32],
) -> BTreeMap<String, Value> {
    obj([
        ("name", Value::Bytes(name.to_vec())),
        ("metaBlobCid", wire::cid_to_value(meta_blob_cid)),
        ("spaceKey", Value::Bytes(space_key.to_vec())),
    ])
}

fn get_space_args(space_id: &SpaceId) -> BTreeMap<String, Value> {
    obj([("spaceId", space_id.to_value())])
}

fn head_args(space_id: &SpaceId) -> BTreeMap<String, Value> {
    obj([("spaceId", space_id.to_value())])
}

fn commit_args(
    space_id: &SpaceId,
    expected_base: Option<&RevisionId>,
    manifest_root: &Cid,
    author_device_id: &DeviceId,
) -> BTreeMap<String, Value> {
    obj([
        ("spaceId", space_id.to_value()),
        (
            "expectedBaseRevisionId",
            expected_base
                .map(RevisionId::to_value)
                .unwrap_or(Value::Null),
        ),
        ("manifestRootCid", wire::cid_to_value(manifest_root)),
        ("authorDeviceId", author_device_id.to_value()),
    ])
}

fn revision_by_seq_args(space_id: &SpaceId, seq: u64) -> BTreeMap<String, Value> {
    obj([
        ("spaceId", space_id.to_value()),
        // The backend validator is `v.number()` (Convex float64). Sending
        // `Value::Int64` is rejected as a "Server Error". `seq` is well below
        // 2^53, so the f64 representation is exact. The RETURN seq is parsed
        // back via `wire::as_u64`, which accepts both Int64 and integral
        // Float64.
        ("seq", Value::Float64(seq as f64)),
    ])
}

fn set_base_seq_args(device_id: &DeviceId, base_seq_in_use: u64) -> BTreeMap<String, Value> {
    obj([
        ("deviceId", device_id.to_value()),
        // `v.number()` on the backend → send a Convex float64, not Int64
        // (see `revision_by_seq_args`).
        ("baseSeqInUse", Value::Float64(base_seq_in_use as f64)),
    ])
}

/// Args for `revisions:listFromSeq`. `max_seq` is the INCLUSIVE upper bound of a
/// window; `None` asks for the whole tail. The key is OMITTED when `None` (the
/// backend validator is `v.optional(v.number())`, and Convex rejects an
/// unexpected `null` as hard as an unexpected field) — which is also what keeps
/// the unwindowed call wire-identical to what a deployment predating `maxSeq`
/// accepts.
fn list_from_seq_args(
    space_id: &SpaceId,
    min_seq: u64,
    max_seq: Option<u64>,
) -> BTreeMap<String, Value> {
    let mut args = obj([
        ("spaceId", space_id.to_value()),
        // `v.number()` on the backend → Convex float64 (see `revision_by_seq_args`).
        ("minSeq", Value::Float64(min_seq as f64)),
    ]);
    if let Some(max) = max_seq {
        args.insert("maxSeq".to_string(), Value::Float64(max as f64));
    }
    args
}

fn refresh_retention_floor_args(space_id: &SpaceId) -> BTreeMap<String, Value> {
    obj([("spaceId", space_id.to_value())])
}

// ---------------------------------------------------------------------------
// Response parsers (pure)
// ---------------------------------------------------------------------------

fn parse_ensure_device(v: &Value) -> Result<EnsureDeviceResult> {
    const CTX: &str = func::AUTH_ENSURE_DEVICE;
    let o = wire::as_object(v, CTX)?;
    Ok(EnsureDeviceResult {
        account_id: AccountId(wire::as_string(
            wire::field(o, "accountId", CTX)?,
            "accountId",
            CTX,
        )?),
        device_id: DeviceId(wire::as_string(
            wire::field(o, "deviceId", CTX)?,
            "deviceId",
            CTX,
        )?),
        dedup_secret: wire::bytes32(wire::field(o, "dedupSecret", CTX)?, "dedupSecret", CTX)?,
    })
}

fn parse_space_id(v: &Value) -> Result<SpaceId> {
    const CTX: &str = func::SPACES_CREATE;
    let o = wire::as_object(v, CTX)?;
    Ok(SpaceId(wire::as_string(
        wire::field(o, "spaceId", CTX)?,
        "spaceId",
        CTX,
    )?))
}

/// Parses a `Space` document. The id field is `_id` (Convex's system field).
fn parse_space(v: &Value) -> Result<Space> {
    const CTX: &str = func::SPACES_GET;
    let o = wire::as_object(v, CTX)?;
    Ok(Space {
        space_id: SpaceId(wire::as_string(wire::field(o, "_id", CTX)?, "_id", CTX)?),
        account_id: AccountId(wire::as_string(
            wire::field(o, "accountId", CTX)?,
            "accountId",
            CTX,
        )?),
        name: match wire::field(o, "name", CTX)? {
            Value::Bytes(b) => b.clone(),
            other => {
                return Err(CoordinatorError::UnexpectedValue {
                    field: "name",
                    context: CTX,
                    detail: format!("expected bytes, got {}", wire::value_kind(other)),
                })
            }
        },
        head_revision_id: wire::as_opt_string(o, "headRevisionId", CTX)?.map(RevisionId),
        meta_blob_cid: wire::value_to_cid(wire::field(o, "metaBlobCid", CTX)?, "metaBlobCid", CTX)?,
        space_key: wire::as_opt_bytes32(o, "spaceKey", CTX)?,
    })
}

fn parse_space_list(v: &Value) -> Result<Vec<Space>> {
    const CTX: &str = func::SPACES_LIST_MINE;
    match v {
        Value::Array(items) => items.iter().map(parse_space).collect(),
        other => Err(CoordinatorError::UnexpectedValue {
            field: "<root>",
            context: CTX,
            detail: format!("expected array, got {}", wire::value_kind(other)),
        }),
    }
}

fn parse_revision(v: &Value) -> Result<Revision> {
    const CTX: &str = func::REVISIONS_BY_SEQ;
    let o = wire::as_object(v, CTX)?;
    Ok(Revision {
        revision_id: RevisionId(wire::as_string(wire::field(o, "_id", CTX)?, "_id", CTX)?),
        space_id: SpaceId(wire::as_string(
            wire::field(o, "spaceId", CTX)?,
            "spaceId",
            CTX,
        )?),
        parent: wire::as_opt_string(o, "parent", CTX)?.map(RevisionId),
        seq: wire::as_u64(wire::field(o, "seq", CTX)?, "seq", CTX)?,
        manifest_root_cid: wire::value_to_cid(
            wire::field(o, "manifestRootCid", CTX)?,
            "manifestRootCid",
            CTX,
        )?,
        author_device_id: DeviceId(wire::as_string(
            wire::field(o, "authorDeviceId", CTX)?,
            "authorDeviceId",
            CTX,
        )?),
    })
}

fn parse_commit_ok(v: &Value) -> Result<CommitOk> {
    const CTX: &str = func::REVISIONS_COMMIT;
    let o = wire::as_object(v, CTX)?;
    Ok(CommitOk {
        revision_id: RevisionId(wire::as_string(
            wire::field(o, "revisionId", CTX)?,
            "revisionId",
            CTX,
        )?),
        seq: wire::as_u64(wire::field(o, "seq", CTX)?, "seq", CTX)?,
    })
}

/// Parses the reactive `spaces:head` value. All four fields are nullable: a
/// Space with no Revisions yields a value with every field null.
fn parse_head_update(v: &Value) -> Result<HeadUpdate> {
    const CTX: &str = func::SPACES_HEAD;
    let o = wire::as_object(v, CTX)?;
    Ok(HeadUpdate {
        head_revision_id: wire::as_opt_string(o, "headRevisionId", CTX)?.map(RevisionId),
        seq: wire::as_opt_u64(o, "seq", CTX)?,
        manifest_root: wire::as_opt_cid(o, "manifestRootCid", CTX)?,
        parent: wire::as_opt_string(o, "parent", CTX)?.map(RevisionId),
    })
}

fn parse_revision_root(v: &Value) -> Result<RevisionRoot> {
    const CTX: &str = func::REVISIONS_LIST_FROM_SEQ;
    let o = wire::as_object(v, CTX)?;
    Ok(RevisionRoot {
        revision_id: RevisionId(wire::as_string(
            wire::field(o, "revisionId", CTX)?,
            "revisionId",
            CTX,
        )?),
        seq: wire::as_u64(wire::field(o, "seq", CTX)?, "seq", CTX)?,
        manifest_root_cid: wire::value_to_cid(
            wire::field(o, "manifestRootCid", CTX)?,
            "manifestRootCid",
            CTX,
        )?,
    })
}

fn parse_revision_roots(v: &Value) -> Result<Vec<RevisionRoot>> {
    const CTX: &str = func::REVISIONS_LIST_FROM_SEQ;
    match v {
        Value::Array(items) => items.iter().map(parse_revision_root).collect(),
        other => Err(CoordinatorError::UnexpectedValue {
            field: "<root>",
            context: CTX,
            detail: format!("expected array, got {}", wire::value_kind(other)),
        }),
    }
}

// ---------------------------------------------------------------------------
// Revision paging (pure) — §6.3 mark set
// ---------------------------------------------------------------------------

/// Width of one `revisions:listFromSeq` window when the chain is too long for a
/// single answer. Comfortably under the backend's own `MAX_REVISIONS_PER_CALL`
/// (4096, `packages/backend/convex/revisions.ts`) so a window can never be the
/// thing that trips the limit.
const REVISION_PAGE: u64 = 1024;

/// A window at or above the backend's limit could itself be the thing that trips
/// it, and a window of 0 would make the walk stand still — both are compile-time
/// mistakes, so they are caught at compile time.
const _: () = assert!(REVISION_PAGE >= 1 && REVISION_PAGE < 4096);

/// The next `[start, end]` (inclusive) window of a paged walk up to `head_seq`,
/// or `None` once `start` is past the head. Pure and saturating so the arithmetic
/// is unit-testable and cannot wrap — the release profile traps on overflow, and
/// a wrapped bound would re-request a window the walk already visited.
fn next_window(start: u64, head_seq: u64, page: u64) -> Option<(u64, u64)> {
    if start > head_seq {
        return None;
    }
    let end = start.saturating_add(page.saturating_sub(1)).min(head_seq);
    Some((start, end))
}

/// Appends one window's rows to the accumulating mark set, enforcing what the GC
/// depends on: every row inside the window that was asked for, and `seq` STRICTLY
/// increasing across the whole concatenation (no duplicate, nothing out of
/// order). A violated invariant is an error, never a quietly-accepted set — a
/// mark set that is short by one Revision makes the sweep delete live data
/// (`§6.3`, `docs/adr/0007`).
fn push_window(
    out: &mut Vec<RevisionRoot>,
    window: Vec<RevisionRoot>,
    min_seq: u64,
    max_seq: Option<u64>,
) -> Result<()> {
    for root in window {
        if root.seq < min_seq || max_seq.is_some_and(|max| root.seq > max) {
            return Err(CoordinatorError::UnexpectedValue {
                field: "seq",
                context: func::REVISIONS_LIST_FROM_SEQ,
                detail: format!(
                    "revision seq {} outside the requested window [{min_seq}, {}]",
                    root.seq,
                    max_seq.map_or_else(|| "unbounded".to_string(), |max| max.to_string()),
                ),
            });
        }
        if let Some(prev) = out.last() {
            if root.seq <= prev.seq {
                return Err(CoordinatorError::UnexpectedValue {
                    field: "seq",
                    context: func::REVISIONS_LIST_FROM_SEQ,
                    detail: format!(
                        "revision seq {} is not above the previous {}; the chain must be \
                         strictly ascending",
                        root.seq, prev.seq
                    ),
                });
            }
        }
        out.push(root);
    }
    Ok(())
}

fn parse_retention_floor(v: &Value) -> Result<RetentionFloor> {
    const CTX: &str = func::SPACES_REFRESH_RETENTION_FLOOR;
    let o = wire::as_object(v, CTX)?;
    Ok(RetentionFloor {
        retention_floor_seq: wire::as_u64(
            wire::field(o, "retentionFloorSeq", CTX)?,
            "retentionFloorSeq",
            CTX,
        )?,
        head_seq: wire::as_opt_u64(o, "headSeq", CTX)?,
    })
}

// ---------------------------------------------------------------------------
// FunctionResult interpretation
// ---------------------------------------------------------------------------

/// Reads the stable `code` string out of a `ConvexError`'s `data` payload
/// (`{ code, message, ... }`, the shape every backend throw uses). `None` when
/// `data` is not an object or carries no string `code` — e.g. a bare thrown
/// `Error` Convex redacted to a "Server Error" message with no structured data.
fn convex_error_code(e: &ConvexError) -> Option<&str> {
    match &e.data {
        Value::Object(data) => match data.get("code") {
            Some(Value::String(code)) => Some(code.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// Maps a `ConvexError` to a typed [`CoordinatorError`] by its `data.code`, the
/// contract the backend and this client share (`packages/backend/convex/*.ts`).
/// An unrecognized (or absent) code falls back to [`CoordinatorError::Function`]
/// carrying the raw message, so nothing is lost for verbose output (`RUST_LOG=debug`)/logs.
fn classify_convex_error(e: &ConvexError) -> CoordinatorError {
    let message = e.message.clone();
    // Codes are matched case-insensitively (the pre-typed conflict detection
    // used `eq_ignore_ascii_case`; keep that tolerance for the whole contract).
    let code = convex_error_code(e).map(str::to_ascii_lowercase);
    match code.as_deref() {
        Some(CONFLICT_CODE) => CoordinatorError::Conflict { message },
        Some("space_not_found") => CoordinatorError::SpaceNotFound { message },
        Some("forbidden") => CoordinatorError::NotAuthorized { message },
        Some("unauthenticated") | Some("no_account") => {
            CoordinatorError::NotAuthenticated { message }
        }
        Some("vault_unavailable") | Some("storage_unconfigured") => {
            CoordinatorError::VaultUnavailable { message }
        }
        Some("too_many_revisions") => CoordinatorError::TooManyRevisions { message },
        Some("space_key_already_set") => CoordinatorError::SpaceKeyAlreadySet { message },
        Some("dangling_head") => CoordinatorError::DanglingHead { message },
        // Malformed arguments (`bad_key`, `bad_manifest_root_cid`, …) get their
        // own variant rather than the `Function` fallback so a caller can tell a
        // DETERMINISTIC rejection from a transient outage: `VaultUnavailable`'s
        // "retry in a few seconds" advice would mislead, and a retry loop that
        // cannot tell them apart repeats the same bad call forever.
        Some(c) if BAD_REQUEST_CODES.contains(&c) => CoordinatorError::BadRequest {
            code: c.to_string(),
            message,
        },
        _ => CoordinatorError::Function(message),
    }
}

/// Unwraps a [`FunctionResult`] to its success [`Value`], mapping application
/// errors to a typed [`CoordinatorError`] (via [`classify_convex_error`] for a
/// `ConvexError`, or [`CoordinatorError::Function`] for a redacted message).
fn unwrap_value(result: FunctionResult) -> Result<Value> {
    match result {
        FunctionResult::Value(v) => Ok(v),
        FunctionResult::ErrorMessage(msg) => Err(CoordinatorError::Function(msg)),
        FunctionResult::ConvexError(e) => Err(classify_convex_error(&e)),
    }
}

/// True if a [`FunctionResult`] is the recognized commit-conflict signal.
///
/// The structured `data.code` DECIDES whenever the backend sent one: a code that
/// is not [`CONFLICT_CODE`] is a different failure, whatever its message says.
/// The message is only consulted when there is no code at all, because
/// `CommitError::Conflict` is the one commit failure `ft-engine` answers by
/// pulling and retrying (`§7` step 6) — reading a deterministic failure as a CAS
/// race turns it into a retry that can never succeed.
fn is_conflict(result: &FunctionResult) -> bool {
    match result {
        FunctionResult::ConvexError(e) => match convex_error_code(e) {
            Some(code) => code.eq_ignore_ascii_case(CONFLICT_CODE),
            None => message_suggests_conflict(&e.message),
        },
        FunctionResult::ErrorMessage(msg) => message_suggests_conflict(msg),
        FunctionResult::Value(_) => false,
    }
}

/// The legacy, message-only conflict test: kept so a deployment predating the
/// typed `data.code` (or a `ConvexError` Convex redacted to a bare message) still
/// reconciles instead of failing the commit outright. Deliberately narrow — it
/// runs only when no code is present, only on the commit path
/// ([`interpret_commit`] is its single caller), and never on a message that
/// carries one of the typed [`NON_CONFLICT_CODES`], so a newer backend's
/// deterministic error can never fall into it.
fn message_suggests_conflict(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    if NON_CONFLICT_CODES.iter().any(|code| lower.contains(code)) {
        return false;
    }
    lower.contains(CONFLICT_CODE)
}

/// Deadline for ONE Coordinator round trip. Generous on purpose: it must outlast
/// a full detect-and-reconnect cycle of the underlying [`convex`] client (30 s
/// server-inactivity threshold + its 15 s max reconnect backoff) so a transient
/// hiccup still completes, while still ending a call that never will.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// Bounds one round trip, mapping the elapsed deadline to
/// [`CoordinatorError::Timeout`].
///
/// The wrapper exists because [`convex::ConvexClient`] has no deadline of its
/// own: an outstanding query/mutation is RE-SENT on every reconnect
/// (`resend_ongoing_queries_mutations`), and the socket worker reconnects
/// forever. Against a Coordinator that accepts the connection and then stops
/// answering, the future therefore never resolves — a one-shot CLI command looks
/// wedged with no output, and the daemon's sync loop stops for good. Connecting
/// is bounded by the caller (`apps/cli`); everything after it is bounded here.
async fn with_deadline<F: Future>(
    timeout: Duration,
    function: &'static str,
    fut: F,
) -> Result<F::Output> {
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| CoordinatorError::Timeout { function, timeout })
}

/// Interprets the commit mutation result: success → [`CommitOk`]; conflict →
/// [`CommitError::Conflict`]; anything else → [`CommitError::Other`]. `§7`.
fn interpret_commit(result: FunctionResult) -> std::result::Result<CommitOk, CommitError> {
    if is_conflict(&result) {
        return Err(CommitError::Conflict);
    }
    let value = unwrap_value(result)?;
    Ok(parse_commit_ok(&value)?)
}

// ---------------------------------------------------------------------------
// Coordinator — the transport wrapper
// ---------------------------------------------------------------------------

/// A connected client of the Coordinator (Convex), wrapping
/// [`convex::ConvexClient`]. Cheap to [`Clone`] (the inner client multiplexes a
/// single WebSocket).
#[derive(Clone)]
pub struct Coordinator {
    client: ConvexClient,
    /// Per-call deadline — see [`with_deadline`] and [`DEFAULT_CALL_TIMEOUT`].
    call_timeout: Duration,
}

impl std::fmt::Debug for Coordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Coordinator").finish_non_exhaustive()
    }
}

impl Coordinator {
    /// Connects to a Convex deployment at `deployment_url` (e.g. a self-hosted
    /// backend or Convex cloud) and returns a [`Coordinator`].
    pub async fn connect(deployment_url: &str) -> Result<Self> {
        let client = ConvexClient::new(deployment_url)
            .await
            .map_err(|e| CoordinatorError::Transport(e.to_string()))?;
        Ok(Self::from_client(client))
    }

    /// Wraps an already-built [`convex::ConvexClient`] (e.g. one configured by a
    /// [`convex::ConvexClientBuilder`]).
    pub fn from_client(client: ConvexClient) -> Self {
        Self {
            client,
            call_timeout: DEFAULT_CALL_TIMEOUT,
        }
    }

    /// Overrides the per-call deadline ([`DEFAULT_CALL_TIMEOUT`]) for every call
    /// this [`Coordinator`] makes. A long-running daemon wants the default; a
    /// one-shot command that would rather fail fast can shorten it.
    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    /// The per-call deadline in force.
    pub fn call_timeout(&self) -> Duration {
        self.call_timeout
    }

    async fn call_mutation(
        &mut self,
        name: &'static str,
        args: BTreeMap<String, Value>,
    ) -> Result<Value> {
        // Read before the mutable borrow of `self.client` below.
        let timeout = self.call_timeout;
        let result = with_deadline(timeout, name, self.client.mutation(name, args))
            .await?
            .map_err(|e| CoordinatorError::Transport(e.to_string()))?;
        unwrap_value(result)
    }

    async fn call_query(
        &mut self,
        name: &'static str,
        args: BTreeMap<String, Value>,
    ) -> Result<Value> {
        let timeout = self.call_timeout;
        let result = with_deadline(timeout, name, self.client.query(name, args))
            .await?
            .map_err(|e| CoordinatorError::Transport(e.to_string()))?;
        unwrap_value(result)
    }

    // ----- auth -----

    /// `auth:ensureDevice` — the authenticated get-or-create every client calls at
    /// startup. Resolves the caller's identity (the JWT `sub`) to an Account
    /// (creating it on first use) and this Device (by `device_name`), and returns
    /// the authoritative escrow `dedup_secret`.
    ///
    /// The client ALWAYS generates a fresh 32-byte `dedup_secret` candidate and
    /// passes it; the server keeps the first one an Account ever saw and returns
    /// it, so every Device of the same user converges on the same secret.
    /// Idempotent — a repeat call for a known (Account, name) returns the existing
    /// rows. Replaces the MVP bootstrap/claim pairing.
    pub async fn ensure_device(
        &mut self,
        device_name: &str,
        dedup_secret_candidate: &[u8; 32],
    ) -> Result<EnsureDeviceResult> {
        let v = self
            .call_mutation(
                func::AUTH_ENSURE_DEVICE,
                ensure_device_args(device_name, dedup_secret_candidate),
            )
            .await?;
        parse_ensure_device(&v)
    }

    // ----- spaces -----

    /// `spaces:create` — create a Space (head starts `null`). The owning Account
    /// is derived from the caller's JWT (not an arg). `space_key` is the 32-byte
    /// escrow key the CLIENT generates (`§4.5`); the Coordinator stores it and
    /// hands it back only to the owning Account. Returns the new Space id.
    pub async fn create_space(
        &mut self,
        name: &[u8],
        meta_blob_cid: &Cid,
        space_key: &[u8; 32],
    ) -> Result<SpaceId> {
        let v = self
            .call_mutation(
                func::SPACES_CREATE,
                create_space_args(name, meta_blob_cid, space_key),
            )
            .await?;
        parse_space_id(&v)
    }

    /// `spaces:get` — fetch a Space document (including its escrow `space_key`).
    pub async fn get_space(&mut self, space_id: &SpaceId) -> Result<Space> {
        let v = self
            .call_query(func::SPACES_GET, get_space_args(space_id))
            .await?;
        parse_space(&v)
    }

    /// `spaces:listMine` — every Space owned by the authenticated caller's
    /// Account (the owner is derived from the JWT, so no account arg).
    pub async fn list_mine(&mut self) -> Result<Vec<Space>> {
        let v = self.call_query(func::SPACES_LIST_MINE, obj([])).await?;
        parse_space_list(&v)
    }

    // ----- revisions -----

    /// `revisions:commit` — the Space-head compare-and-swap (`§7`). On a CAS
    /// conflict the backend signals it distinguishably and this returns
    /// [`CommitError::Conflict`].
    pub async fn commit_revision(
        &mut self,
        space_id: &SpaceId,
        expected_base: Option<&RevisionId>,
        manifest_root: &Cid,
        author_device_id: &DeviceId,
    ) -> std::result::Result<CommitOk, CommitError> {
        let timeout = self.call_timeout;
        // A commit that times out MAY still have landed (the mutation is a
        // serializable txn on the server). That is safe to retry: the retry's CAS
        // sees the advanced head and comes back as a conflict, which `§7` step 6
        // already reconciles. Hanging forever is the only outcome with no recovery.
        let result = with_deadline(
            timeout,
            func::REVISIONS_COMMIT,
            self.client.mutation(
                func::REVISIONS_COMMIT,
                commit_args(space_id, expected_base, manifest_root, author_device_id),
            ),
        )
        .await
        .map_err(CommitError::Other)?
        .map_err(|e| CommitError::Other(CoordinatorError::Transport(e.to_string())))?;
        interpret_commit(result)
    }

    /// `revisions:bySeq` — the Revision at `seq` in a Space.
    pub async fn revision_by_seq(&mut self, space_id: &SpaceId, seq: u64) -> Result<Revision> {
        let v = self
            .call_query(func::REVISIONS_BY_SEQ, revision_by_seq_args(space_id, seq))
            .await?;
        parse_revision(&v)
    }

    /// `revisions:listFromSeq` — EVERY Revision root at or above `min_seq` (the
    /// GC's retained set, `§6.3`). Returns id + seq + Manifest root per Revision,
    /// ordered by ascending seq.
    ///
    /// Complete or `Err`, never partial: this is the mark phase of a destructive
    /// sweep, so a set that is short by one Revision makes the sweep delete live
    /// data (`docs/adr/0007`). The backend refuses to answer more than 4096
    /// Revisions in one call (`too_many_revisions`) rather than truncate, so a
    /// chain that long is walked here in `REVISION_PAGE`-wide windows and
    /// concatenated, with every window checked for gaps, duplicates and order.
    ///
    /// The common case is ONE unwindowed call, wire-identical to what this client
    /// has always sent. That is also what keeps `maxSeq` safe to use: Convex
    /// rejects an argument its validator does not declare, but only a backend that
    /// HAS `maxSeq` can answer `too_many_revisions` in the first place — so the
    /// windowed walk never runs against a deployment that predates it.
    pub async fn list_revisions_from(
        &mut self,
        space_id: &SpaceId,
        min_seq: u64,
    ) -> Result<Vec<RevisionRoot>> {
        match self.list_revision_window(space_id, min_seq, None).await {
            Ok(roots) => {
                // Even the single-call answer is checked: the invariants below are
                // what make the set usable as a mark set at all.
                let mut out = Vec::with_capacity(roots.len());
                push_window(&mut out, roots, min_seq, None)?;
                Ok(out)
            }
            Err(CoordinatorError::TooManyRevisions { .. }) => {
                self.page_revisions_from(space_id, min_seq).await
            }
            Err(e) => Err(e),
        }
    }

    /// One window of `revisions:listFromSeq` (`max_seq` inclusive, `None` = the
    /// whole tail).
    async fn list_revision_window(
        &mut self,
        space_id: &SpaceId,
        min_seq: u64,
        max_seq: Option<u64>,
    ) -> Result<Vec<RevisionRoot>> {
        let v = self
            .call_query(
                func::REVISIONS_LIST_FROM_SEQ,
                list_from_seq_args(space_id, min_seq, max_seq),
            )
            .await?;
        parse_revision_roots(&v)
    }

    /// The windowed walk behind [`Self::list_revisions_from`], for a chain the
    /// server refuses to hand over in one answer.
    async fn page_revisions_from(
        &mut self,
        space_id: &SpaceId,
        min_seq: u64,
    ) -> Result<Vec<RevisionRoot>> {
        // The head seq bounds the walk: `commit` assigns `seq = head.seq + 1`
        // inside the CAS txn (`§7`), so no Revision can sit above the head at the
        // instant this query reads it.
        let head = self.head(space_id).await?;
        let head_seq = match (&head.head_revision_id, head.seq) {
            (Some(_), Some(seq)) => seq,
            // The backend's defensive dangling-head answer: a head pointer whose
            // Revision is unreadable leaves the walk with no upper bound, so there
            // is no way to know the set is complete. Refuse loudly.
            (Some(id), None) => {
                return Err(CoordinatorError::DanglingHead {
                    message: format!(
                        "space head {id} has no readable seq, so the Revision chain cannot be \
                         paged completely"
                    ),
                })
            }
            // The unwindowed call reported >4096 Revisions and the head says the
            // Space has none: the two answers cannot both be true.
            (None, _) => {
                return Err(CoordinatorError::UnexpectedValue {
                    field: "headRevisionId",
                    context: func::SPACES_HEAD,
                    detail: "space reports no head yet listFromSeq reported too many Revisions"
                        .to_string(),
                })
            }
        };

        let mut out: Vec<RevisionRoot> = Vec::new();
        let mut next = Some(min_seq);
        while let Some((lo, hi)) =
            next.and_then(|start| next_window(start, head_seq, REVISION_PAGE))
        {
            let window = self.list_revision_window(space_id, lo, Some(hi)).await?;
            push_window(&mut out, window, lo, Some(hi))?;
            next = hi.checked_add(1);
        }

        // A commit that landed WHILE the walk ran got a seq above `head_seq` (seq
        // only ever grows), so one unbounded tail call makes the union complete as
        // of its own snapshot — the same guarantee the single-call path gives.
        if let Some(after_head) = head_seq.checked_add(1) {
            let tail = self
                .list_revision_window(space_id, after_head, None)
                .await?;
            push_window(&mut out, tail, after_head, None)?;
        }
        Ok(out)
    }

    // ----- devices -----

    /// `devices:setBaseSeq` — publish the Device's retention floor (`§6.3`).
    pub async fn set_base_seq(&mut self, device_id: &DeviceId, base_seq_in_use: u64) -> Result<()> {
        self.call_mutation(
            func::DEVICES_SET_BASE_SEQ,
            set_base_seq_args(device_id, base_seq_in_use),
        )
        .await?;
        Ok(())
    }

    /// `spaces:refreshRetentionFloor` — recompute + persist the Space's GC
    /// retention floor from live Device telemetry (`§6.3`). Called right before a
    /// sweep so the floor reflects the freshest `baseSeqInUse` values.
    pub async fn refresh_retention_floor(&mut self, space_id: &SpaceId) -> Result<RetentionFloor> {
        let v = self
            .call_mutation(
                func::SPACES_REFRESH_RETENTION_FLOOR,
                refresh_retention_floor_args(space_id),
            )
            .await?;
        parse_retention_floor(&v)
    }

    // ----- change feed (§8) -----

    /// `spaces:head` as a ONE-SHOT query: the same document
    /// [`Self::subscribe_head`] streams, read once. Used by
    /// [`Self::list_revisions_from`] to learn the head seq that bounds a paged
    /// walk, and by any caller that wants the head without holding a subscription.
    pub async fn head(&mut self, space_id: &SpaceId) -> Result<HeadUpdate> {
        let v = self
            .call_query(func::SPACES_HEAD, head_args(space_id))
            .await?;
        parse_head_update(&v)
    }

    /// `spaces:head` — subscribe to the reactive Space-head query and yield a
    /// [`HeadUpdate`] every time it changes. The change feed of `§8`.
    ///
    /// The returned [`Stream`] yields `Result<HeadUpdate>`: a parse failure on
    /// one pushed value is surfaced as an `Err` item without ending the stream.
    ///
    /// Only REGISTERING the subscription is deadlined (the `convex` client answers
    /// that from its own worker, but a worker stuck mid-reconnect would otherwise
    /// stall it). The stream itself is not: a change feed is idle by design between
    /// head moves, so a deadline on the next item would be a bug, not a guard.
    pub async fn subscribe_head(
        &mut self,
        space_id: &SpaceId,
    ) -> Result<impl Stream<Item = Result<HeadUpdate>>> {
        let timeout = self.call_timeout;
        let sub = with_deadline(
            timeout,
            func::SPACES_HEAD,
            self.client
                .subscribe(func::SPACES_HEAD, head_args(space_id)),
        )
        .await?
        .map_err(|e| CoordinatorError::Transport(e.to_string()))?;
        Ok(sub.map(|result| {
            let value = unwrap_value(result)?;
            parse_head_update(&value)
        }))
    }
}

// ---------------------------------------------------------------------------
// Tests — serialization / type mapping only (no network)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use convex::{ConvexError, Value};

    fn cid(n: u8) -> Cid {
        Cid::new([n; 32])
    }

    // ----- Cid/Pcid <-> bytes roundtrip -----

    #[test]
    fn cid_to_value_is_bytes_of_the_32_byte_digest() {
        let c = cid(7);
        match wire::cid_to_value(&c) {
            Value::Bytes(b) => assert_eq!(b, vec![7u8; 32]),
            other => panic!("expected bytes, got {other:?}"),
        }
    }

    #[test]
    fn cid_roundtrips_through_value() {
        let c = cid(0xAB);
        let v = wire::cid_to_value(&c);
        let back = wire::value_to_cid(&v, "cid", "test").unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn pcid_roundtrips_through_value() {
        let p = Pcid::new(core::array::from_fn(|i| i as u8));
        let v = wire::pcid_to_value(&p);
        let back = wire::value_to_pcid(&v, "pcid", "test").unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn value_to_cid_rejects_wrong_length() {
        let v = Value::Bytes(vec![0u8; 31]);
        match wire::value_to_cid(&v, "manifestRootCid", "ctx") {
            Err(CoordinatorError::InvalidIdLength { field, got, .. }) => {
                assert_eq!(field, "manifestRootCid");
                assert_eq!(got, 31);
            }
            other => panic!("expected InvalidIdLength, got {other:?}"),
        }
    }

    #[test]
    fn value_to_cid_rejects_non_bytes() {
        let v = Value::String("not bytes".into());
        assert!(matches!(
            wire::value_to_cid(&v, "cid", "ctx"),
            Err(CoordinatorError::UnexpectedValue { .. })
        ));
    }

    // ----- argument builders carry the exact contract keys -----

    #[test]
    fn ensure_device_args_carry_name_and_dedup_secret() {
        let dedup = [9u8; 32];
        let args = ensure_device_args("laptop", &dedup);
        let keys: Vec<_> = args.keys().cloned().collect();
        assert_eq!(keys, vec!["dedupSecret", "deviceName"]); // BTreeMap orders keys
        assert_eq!(args["deviceName"], Value::String("laptop".into()));
        assert_eq!(args["dedupSecret"], Value::Bytes(vec![9u8; 32]));
    }

    #[test]
    fn create_space_args_use_bytes_for_name_meta_and_key() {
        let name = "My Space".as_bytes();
        let meta = cid(3);
        let key = [5u8; 32];
        let args = create_space_args(name, &meta, &key);
        let keys: Vec<_> = args.keys().cloned().collect();
        assert_eq!(keys, vec!["metaBlobCid", "name", "spaceKey"]); // BTreeMap orders keys
        assert_eq!(args["name"], Value::Bytes(name.to_vec()));
        assert_eq!(args["metaBlobCid"], Value::Bytes(vec![3u8; 32]));
        assert_eq!(args["spaceKey"], Value::Bytes(vec![5u8; 32]));
        // The owning Account is derived from the JWT server-side, never an arg.
        assert!(!args.contains_key("accountId"));
    }

    #[test]
    fn get_and_head_args() {
        assert_eq!(
            get_space_args(&SpaceId::new("sp_1"))["spaceId"],
            Value::String("sp_1".into())
        );
        assert_eq!(
            head_args(&SpaceId::new("sp_2"))["spaceId"],
            Value::String("sp_2".into())
        );
    }

    #[test]
    fn commit_args_with_base_carry_all_four_keys() {
        let args = commit_args(
            &SpaceId::new("sp_1"),
            Some(&RevisionId::new("rev_7")),
            &cid(9),
            &DeviceId::new("dev_1"),
        );
        let keys: Vec<_> = args.keys().cloned().collect();
        assert_eq!(
            keys,
            vec![
                "authorDeviceId",
                "expectedBaseRevisionId",
                "manifestRootCid",
                "spaceId"
            ]
        );
        assert_eq!(
            args["expectedBaseRevisionId"],
            Value::String("rev_7".into())
        );
        assert_eq!(args["manifestRootCid"], Value::Bytes(vec![9u8; 32]));
        assert_eq!(args["authorDeviceId"], Value::String("dev_1".into()));
        assert_eq!(args["spaceId"], Value::String("sp_1".into()));
    }

    #[test]
    fn commit_args_with_no_base_send_null() {
        let args = commit_args(
            &SpaceId::new("sp_1"),
            None,
            &cid(1),
            &DeviceId::new("dev_1"),
        );
        assert_eq!(args["expectedBaseRevisionId"], Value::Null);
    }

    #[test]
    fn revision_by_seq_args_send_float64_seq() {
        // The backend validator is `v.number()` (Convex float64). The client
        // MUST send the seq as `Value::Float64`; `Value::Int64` is rejected by
        // the live backend as a "Server Error". Regression lock for the bug.
        let args = revision_by_seq_args(&SpaceId::new("sp_1"), 42);
        assert_eq!(args["spaceId"], Value::String("sp_1".into()));
        assert_eq!(args["seq"], Value::Float64(42.0));
    }

    #[test]
    fn set_base_seq_args_carry_device_and_float64_seq() {
        // `baseSeqInUse` is `v.number()` on the backend → must be Float64, not
        // Int64. Regression lock for the bug.
        let args = set_base_seq_args(&DeviceId::new("dev_1"), 5);
        let keys: Vec<_> = args.keys().cloned().collect();
        assert_eq!(keys, vec!["baseSeqInUse", "deviceId"]);
        assert_eq!(args["deviceId"], Value::String("dev_1".into()));
        assert_eq!(args["baseSeqInUse"], Value::Float64(5.0));
    }

    #[test]
    fn list_from_seq_args_send_float64_min_seq() {
        // `minSeq` is `v.number()` on the backend → Float64, not Int64.
        let args = list_from_seq_args(&SpaceId::new("sp_1"), 7, None);
        let keys: Vec<_> = args.keys().cloned().collect();
        assert_eq!(keys, vec!["minSeq", "spaceId"]);
        assert_eq!(args["spaceId"], Value::String("sp_1".into()));
        assert_eq!(args["minSeq"], Value::Float64(7.0));
    }

    #[test]
    fn list_from_seq_args_omit_max_seq_entirely_when_the_window_is_unbounded() {
        // `maxSeq` is `v.optional(v.number())`: omitted means "the whole tail".
        // Sending an explicit null would be REJECTED by the validator, and the
        // omitted form is also the exact request a deployment predating `maxSeq`
        // accepts — which is what keeps the unwindowed path compatible.
        let args = list_from_seq_args(&SpaceId::new("sp_1"), 0, None);
        assert!(!args.contains_key("maxSeq"));
    }

    #[test]
    fn list_from_seq_args_send_the_window_upper_bound_as_float64() {
        let args = list_from_seq_args(&SpaceId::new("sp_1"), 1024, Some(2047));
        let keys: Vec<_> = args.keys().cloned().collect();
        assert_eq!(keys, vec!["maxSeq", "minSeq", "spaceId"]);
        assert_eq!(args["minSeq"], Value::Float64(1024.0));
        assert_eq!(args["maxSeq"], Value::Float64(2047.0));
    }

    #[test]
    fn refresh_retention_floor_args_have_space() {
        let args = refresh_retention_floor_args(&SpaceId::new("sp_9"));
        assert_eq!(args.keys().cloned().collect::<Vec<_>>(), vec!["spaceId"]);
        assert_eq!(args["spaceId"], Value::String("sp_9".into()));
    }

    #[test]
    fn parse_revision_roots_reads_array() {
        // Accepts both Int64 and integral Float64 for seq (as `wire::as_u64` does).
        let a = objv([
            ("revisionId", Value::String("rev_2".into())),
            ("seq", Value::Int64(2)),
            ("manifestRootCid", Value::Bytes(vec![2u8; 32])),
        ]);
        let b = objv([
            ("revisionId", Value::String("rev_3".into())),
            ("seq", Value::Float64(3.0)),
            ("manifestRootCid", Value::Bytes(vec![3u8; 32])),
        ]);
        let roots = parse_revision_roots(&Value::Array(vec![a, b])).unwrap();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].revision_id, RevisionId::new("rev_2"));
        assert_eq!(roots[0].seq, 2);
        assert_eq!(roots[0].manifest_root_cid, cid(2));
        assert_eq!(roots[1].seq, 3);
        assert_eq!(roots[1].manifest_root_cid, cid(3));
    }

    // ----- Revision paging (§6.3 mark set) -----

    fn root(seq: u64) -> RevisionRoot {
        RevisionRoot {
            revision_id: RevisionId::new(format!("rev_{seq}")),
            seq,
            manifest_root_cid: cid(seq as u8),
        }
    }

    /// The windows a paged walk visits, driven exactly as `page_revisions_from`
    /// drives it.
    fn walk(min_seq: u64, head_seq: u64, page: u64) -> Vec<(u64, u64)> {
        let mut windows = Vec::new();
        let mut next = Some(min_seq);
        while let Some((lo, hi)) = next.and_then(|start| next_window(start, head_seq, page)) {
            windows.push((lo, hi));
            next = hi.checked_add(1);
        }
        windows
    }

    #[test]
    fn paged_windows_cover_the_whole_range_without_a_gap_or_an_overlap() {
        assert_eq!(walk(5, 12, 4), vec![(5, 8), (9, 12)]);
        // Exactly one full window.
        assert_eq!(walk(0, 3, 4), vec![(0, 3)]);
        // A single Revision.
        assert_eq!(walk(7, 7, 4), vec![(7, 7)]);
        // Nothing at or above min_seq → no call at all.
        assert!(walk(9, 8, 4).is_empty());
    }

    #[test]
    fn paged_windows_clamp_the_last_window_to_the_head_seq() {
        // The tail window must not ask beyond the head: `maxSeq` past the head is
        // harmless server-side but makes the client's own window check useless.
        assert_eq!(walk(0, 5, 4), vec![(0, 3), (4, 5)]);
    }

    #[test]
    fn paged_windows_saturate_instead_of_wrapping_at_the_top_of_u64() {
        // Release builds now trap on overflow, and a WRAPPED bound would send the
        // walk back over a window it already visited.
        assert_eq!(
            walk(u64::MAX - 1, u64::MAX, 1024),
            vec![(u64::MAX - 1, u64::MAX)]
        );
    }

    #[test]
    fn push_window_concatenates_ascending_windows_in_order() {
        let mut out = Vec::new();
        push_window(&mut out, vec![root(0), root(1)], 0, Some(1)).unwrap();
        push_window(&mut out, vec![root(2), root(3)], 2, Some(3)).unwrap();
        push_window(&mut out, vec![root(4)], 4, None).unwrap();
        assert_eq!(
            out.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn push_window_rejects_a_row_outside_the_requested_window() {
        // A row above `maxSeq` (or below `minSeq`) means the window bounds were
        // not honoured, so the walk's "no gap, no overlap" reasoning no longer
        // holds and the set cannot be trusted as a mark set.
        let mut out = Vec::new();
        match push_window(&mut out, vec![root(2), root(9)], 0, Some(3)) {
            Err(CoordinatorError::UnexpectedValue { field, detail, .. }) => {
                assert_eq!(field, "seq");
                assert!(detail.contains('9'), "detail names the offending seq");
            }
            other => panic!("expected UnexpectedValue, got {other:?}"),
        }
        let mut out2 = Vec::new();
        assert!(push_window(&mut out2, vec![root(1)], 4, Some(8)).is_err());
    }

    #[test]
    fn push_window_rejects_a_duplicate_or_out_of_order_seq() {
        // A duplicated Revision means the windows overlapped; a descending seq
        // means the chain came back unordered. Either way the count the GC reports
        // and the completeness it assumes are wrong — fail loudly.
        let mut out = Vec::new();
        push_window(&mut out, vec![root(0), root(1)], 0, Some(1)).unwrap();
        assert!(push_window(&mut out, vec![root(1)], 1, Some(2)).is_err());

        let mut out2 = Vec::new();
        assert!(push_window(&mut out2, vec![root(5), root(4)], 0, Some(9)).is_err());
    }

    #[test]
    fn parse_retention_floor_reads_object_and_null_head() {
        let v = objv([
            ("retentionFloorSeq", Value::Int64(4)),
            ("headSeq", Value::Int64(9)),
        ]);
        let rf = parse_retention_floor(&v).unwrap();
        assert_eq!(rf.retention_floor_seq, 4);
        assert_eq!(rf.head_seq, Some(9));

        // A Space with no Revisions → headSeq null, floor 0.
        let v2 = objv([
            ("retentionFloorSeq", Value::Int64(0)),
            ("headSeq", Value::Null),
        ]);
        let rf2 = parse_retention_floor(&v2).unwrap();
        assert_eq!(rf2.retention_floor_seq, 0);
        assert_eq!(rf2.head_seq, None);
    }

    // ----- response parsing -----

    fn objv(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    #[test]
    fn parse_ensure_device_result() {
        let v = objv([
            ("accountId", Value::String("acc_1".into())),
            ("deviceId", Value::String("dev_1".into())),
            ("dedupSecret", Value::Bytes(vec![7u8; 32])),
        ]);
        let r = parse_ensure_device(&v).unwrap();
        assert_eq!(r.account_id, AccountId::new("acc_1"));
        assert_eq!(r.device_id, DeviceId::new("dev_1"));
        assert_eq!(r.dedup_secret, [7u8; 32]);
    }

    #[test]
    fn parse_ensure_device_rejects_wrong_dedup_len() {
        let v = objv([
            ("accountId", Value::String("acc_1".into())),
            ("deviceId", Value::String("dev_1".into())),
            ("dedupSecret", Value::Bytes(vec![7u8; 16])),
        ]);
        assert!(matches!(
            parse_ensure_device(&v),
            Err(CoordinatorError::InvalidIdLength { field, got, .. }) if field == "dedupSecret" && got == 16
        ));
    }

    #[test]
    fn parse_space_id_from_create() {
        let v = objv([("spaceId", Value::String("sp_1".into()))]);
        assert_eq!(parse_space_id(&v).unwrap(), SpaceId::new("sp_1"));
    }

    #[test]
    fn parse_space_with_head() {
        let v = objv([
            ("_id", Value::String("sp_1".into())),
            ("accountId", Value::String("acc_1".into())),
            ("name", Value::Bytes("hello".as_bytes().to_vec())),
            ("headRevisionId", Value::String("rev_3".into())),
            ("metaBlobCid", Value::Bytes(vec![4u8; 32])),
            ("spaceKey", Value::Bytes(vec![8u8; 32])),
        ]);
        let s = parse_space(&v).unwrap();
        assert_eq!(s.space_id, SpaceId::new("sp_1"));
        assert_eq!(s.account_id, AccountId::new("acc_1"));
        assert_eq!(s.name, b"hello".to_vec());
        assert_eq!(s.head_revision_id, Some(RevisionId::new("rev_3")));
        assert_eq!(s.meta_blob_cid, cid(4));
        assert_eq!(s.space_key, Some([8u8; 32]));
    }

    #[test]
    fn parse_space_with_null_head() {
        let v = objv([
            ("_id", Value::String("sp_1".into())),
            ("accountId", Value::String("acc_1".into())),
            ("name", Value::Bytes(vec![])),
            ("headRevisionId", Value::Null),
            ("metaBlobCid", Value::Bytes(vec![0u8; 32])),
            ("spaceKey", Value::Bytes(vec![1u8; 32])),
        ]);
        let s = parse_space(&v).unwrap();
        assert_eq!(s.head_revision_id, None);
    }

    #[test]
    fn parse_space_without_space_key_is_legacy_none() {
        // A legacy Space created before escrow has no spaceKey field → None
        // (the client leaves it on the cleartext alg=0 path).
        let v = objv([
            ("_id", Value::String("sp_1".into())),
            ("accountId", Value::String("acc_1".into())),
            ("name", Value::Bytes(vec![])),
            ("headRevisionId", Value::Null),
            ("metaBlobCid", Value::Bytes(vec![0u8; 32])),
        ]);
        let s = parse_space(&v).unwrap();
        assert_eq!(s.space_key, None);
    }

    #[test]
    fn parse_space_list_of_two() {
        let one = objv([
            ("_id", Value::String("sp_1".into())),
            ("accountId", Value::String("acc_1".into())),
            ("name", Value::Bytes(vec![1])),
            ("headRevisionId", Value::Null),
            ("metaBlobCid", Value::Bytes(vec![1u8; 32])),
            ("spaceKey", Value::Bytes(vec![1u8; 32])),
        ]);
        let two = objv([
            ("_id", Value::String("sp_2".into())),
            ("accountId", Value::String("acc_1".into())),
            ("name", Value::Bytes(vec![2])),
            ("headRevisionId", Value::String("rev_9".into())),
            ("metaBlobCid", Value::Bytes(vec![2u8; 32])),
            ("spaceKey", Value::Bytes(vec![2u8; 32])),
        ]);
        let list = parse_space_list(&Value::Array(vec![one, two])).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].space_id, SpaceId::new("sp_1"));
        assert_eq!(list[1].head_revision_id, Some(RevisionId::new("rev_9")));
    }

    #[test]
    fn parse_revision_document() {
        let v = objv([
            ("_id", Value::String("rev_5".into())),
            ("spaceId", Value::String("sp_1".into())),
            ("parent", Value::String("rev_4".into())),
            ("seq", Value::Int64(5)),
            ("manifestRootCid", Value::Bytes(vec![6u8; 32])),
            ("authorDeviceId", Value::String("dev_1".into())),
        ]);
        let r = parse_revision(&v).unwrap();
        assert_eq!(r.revision_id, RevisionId::new("rev_5"));
        assert_eq!(r.space_id, SpaceId::new("sp_1"));
        assert_eq!(r.parent, Some(RevisionId::new("rev_4")));
        assert_eq!(r.seq, 5);
        assert_eq!(r.manifest_root_cid, cid(6));
        assert_eq!(r.author_device_id, DeviceId::new("dev_1"));
    }

    #[test]
    fn parse_first_revision_has_null_parent() {
        let v = objv([
            ("_id", Value::String("rev_0".into())),
            ("spaceId", Value::String("sp_1".into())),
            ("parent", Value::Null),
            ("seq", Value::Int64(0)),
            ("manifestRootCid", Value::Bytes(vec![0u8; 32])),
            ("authorDeviceId", Value::String("dev_1".into())),
        ]);
        let r = parse_revision(&v).unwrap();
        assert_eq!(r.parent, None);
        assert_eq!(r.seq, 0);
    }

    #[test]
    fn parse_commit_ok_result() {
        let v = objv([
            ("revisionId", Value::String("rev_8".into())),
            ("seq", Value::Int64(8)),
        ]);
        let ok = parse_commit_ok(&v).unwrap();
        assert_eq!(ok.revision_id, RevisionId::new("rev_8"));
        assert_eq!(ok.seq, 8);
    }

    // ----- HeadUpdate parsing (the change feed value) -----

    #[test]
    fn parse_head_update_populated() {
        let v = objv([
            ("headRevisionId", Value::String("rev_3".into())),
            ("seq", Value::Int64(3)),
            ("manifestRootCid", Value::Bytes(vec![7u8; 32])),
            ("parent", Value::String("rev_2".into())),
        ]);
        let h = parse_head_update(&v).unwrap();
        assert_eq!(h.head_revision_id, Some(RevisionId::new("rev_3")));
        assert_eq!(h.seq, Some(3));
        assert_eq!(h.manifest_root, Some(cid(7)));
        assert_eq!(h.parent, Some(RevisionId::new("rev_2")));
    }

    #[test]
    fn parse_head_update_empty_space_is_all_none() {
        // A Space with no Revisions: every field null.
        let v = objv([
            ("headRevisionId", Value::Null),
            ("seq", Value::Null),
            ("manifestRootCid", Value::Null),
            ("parent", Value::Null),
        ]);
        let h = parse_head_update(&v).unwrap();
        assert_eq!(
            h,
            HeadUpdate {
                head_revision_id: None,
                seq: None,
                manifest_root: None,
                parent: None,
            }
        );
    }

    #[test]
    fn parse_head_update_accepts_float_seq() {
        // Convex may surface a number as Float64; an integral one must parse.
        let v = objv([
            ("headRevisionId", Value::String("rev_1".into())),
            ("seq", Value::Float64(1.0)),
            ("manifestRootCid", Value::Bytes(vec![1u8; 32])),
            ("parent", Value::Null),
        ]);
        let h = parse_head_update(&v).unwrap();
        assert_eq!(h.seq, Some(1));
    }

    // ----- FunctionResult / conflict interpretation (§7) -----

    #[test]
    fn unwrap_value_passes_success() {
        let v = unwrap_value(FunctionResult::Value(Value::Int64(1))).unwrap();
        assert_eq!(v, Value::Int64(1));
    }

    #[test]
    fn unwrap_value_maps_error_message() {
        let e = unwrap_value(FunctionResult::ErrorMessage("boom".into()));
        assert!(matches!(e, Err(CoordinatorError::Function(m)) if m == "boom"));
    }

    #[test]
    fn conflict_detected_from_convex_error_data_code() {
        let data = Value::Object(
            [("code".to_string(), Value::String("conflict".into()))]
                .into_iter()
                .collect(),
        );
        let r = FunctionResult::ConvexError(ConvexError {
            message: "head moved".into(),
            data,
        });
        assert!(is_conflict(&r));
        assert!(matches!(interpret_commit(r), Err(CommitError::Conflict)));
    }

    #[test]
    fn conflict_detected_from_message_substring() {
        // Legacy fallback: a deployment predating the typed `data.code` only set a
        // message, and such a commit must still reconcile instead of failing.
        let r = FunctionResult::ErrorMessage("Conflict: base != head".into());
        assert!(is_conflict(&r));
        assert!(matches!(interpret_commit(r), Err(CommitError::Conflict)));
    }

    #[test]
    fn a_typed_non_conflict_code_is_never_a_cas_conflict_whatever_its_message_says() {
        // `CommitError::Conflict` is the ONE commit failure ft-engine answers by
        // pulling and retrying (§7 step 6), so a deterministic failure classified
        // as a CAS race becomes a retry that can never succeed. When the backend
        // sent a structured code, that code decides — the message is not read.
        let e = convex_err(
            "bad_manifest_root_cid",
            "manifestRootCid must be exactly 32 bytes; it conflicts with the stored root",
        );
        assert!(!is_conflict(&FunctionResult::ConvexError(e.clone())));
        match interpret_commit(FunctionResult::ConvexError(e)) {
            Err(CommitError::Other(CoordinatorError::BadRequest { code, .. })) => {
                assert_eq!(code, "bad_manifest_root_cid");
            }
            other => panic!("expected Other(BadRequest), got {other:?}"),
        }
    }

    #[test]
    fn the_legacy_message_fallback_ignores_a_message_carrying_a_typed_code() {
        // Belt to the braces above: even with no structured `data` at all, a
        // message that names one of the typed codes is that typed failure, not a
        // CAS race — so the fallback must not fire on it.
        for code in NON_CONFLICT_CODES {
            let msg = format!("Uncaught ConvexError: {code} (conflict while validating)");
            assert!(
                !message_suggests_conflict(&msg),
                "{code} must not be read as a CAS conflict"
            );
        }
    }

    #[test]
    fn codes_other_than_conflict_never_contain_the_word_conflict() {
        // The backend keeps "conflict" out of every other code on purpose, because
        // this client's legacy fallback matches that substring. Locked in from this
        // side so a new backend code cannot quietly reintroduce the ambiguity.
        for code in NON_CONFLICT_CODES {
            assert!(
                !code.contains(CONFLICT_CODE),
                "backend code {code} must not contain {CONFLICT_CODE:?}"
            );
        }
        for code in BAD_REQUEST_CODES {
            assert!(
                NON_CONFLICT_CODES.contains(code),
                "{code} must be listed among the non-conflict codes"
            );
        }
    }

    #[test]
    fn non_conflict_function_error_is_other_not_conflict() {
        let r = FunctionResult::ErrorMessage("some unrelated failure".into());
        assert!(!is_conflict(&r));
        match interpret_commit(r) {
            Err(CommitError::Other(CoordinatorError::Function(m))) => {
                assert_eq!(m, "some unrelated failure");
            }
            other => panic!("expected Other(Function), got {other:?}"),
        }
    }

    #[test]
    fn successful_commit_interprets_to_commit_ok() {
        let v = objv([
            ("revisionId", Value::String("rev_1".into())),
            ("seq", Value::Int64(1)),
        ]);
        let ok = interpret_commit(FunctionResult::Value(v)).unwrap();
        assert_eq!(
            ok,
            CommitOk {
                revision_id: RevisionId::new("rev_1"),
                seq: 1,
            }
        );
    }

    // ----- typed ConvexError.data.code -> CoordinatorError mapping -----

    /// Builds a `ConvexError` with a `{ code, message }` data payload, the shape
    /// every backend throw uses (`packages/backend/convex/*.ts`).
    fn convex_err(code: &str, message: &str) -> ConvexError {
        let data = Value::Object(
            [("code".to_string(), Value::String(code.into()))]
                .into_iter()
                .collect(),
        );
        ConvexError {
            message: message.into(),
            data,
        }
    }

    #[test]
    fn classify_maps_each_known_code_to_its_typed_variant() {
        assert!(matches!(
            classify_convex_error(&convex_err("space_not_found", "no such Space")),
            CoordinatorError::SpaceNotFound { message } if message == "no such Space"
        ));
        assert!(matches!(
            classify_convex_error(&convex_err("forbidden", "another Account")),
            CoordinatorError::NotAuthorized { .. }
        ));
        assert!(matches!(
            classify_convex_error(&convex_err("unauthenticated", "no identity")),
            CoordinatorError::NotAuthenticated { .. }
        ));
        assert!(matches!(
            classify_convex_error(&convex_err("no_account", "call ensureDevice")),
            CoordinatorError::NotAuthenticated { .. }
        ));
        assert!(matches!(
            classify_convex_error(&convex_err("vault_unavailable", "sign failed")),
            CoordinatorError::VaultUnavailable { .. }
        ));
        assert!(matches!(
            classify_convex_error(&convex_err("storage_unconfigured", "no S3 env")),
            CoordinatorError::VaultUnavailable { .. }
        ));
        assert!(matches!(
            classify_convex_error(&convex_err("conflict", "head moved")),
            CoordinatorError::Conflict { .. }
        ));
    }

    #[test]
    fn classify_matches_codes_case_insensitively() {
        // The pre-typed conflict detection used eq_ignore_ascii_case; the
        // classifier keeps that tolerance for the whole contract.
        assert!(matches!(
            classify_convex_error(&convex_err("Conflict", "head moved")),
            CoordinatorError::Conflict { .. }
        ));
        assert!(matches!(
            classify_convex_error(&convex_err("SPACE_NOT_FOUND", "no such Space")),
            CoordinatorError::SpaceNotFound { .. }
        ));
    }

    #[test]
    fn classify_maps_malformed_argument_codes_to_bad_request_with_the_code_kept() {
        // These are deterministic client bugs, not Vault outages: they must NOT get
        // VaultUnavailable's "retry in a few seconds" advice, and a caller must be
        // able to see they will fail identically forever rather than back off and
        // repeat them. The code travels with the error so the detail is not lost.
        for code in BAD_REQUEST_CODES {
            match classify_convex_error(&convex_err(code, "malformed")) {
                CoordinatorError::BadRequest { code: got, message } => {
                    assert_eq!(&got, code);
                    assert_eq!(message, "malformed");
                }
                other => panic!("expected BadRequest for {code}, got {other:?}"),
            }
        }
    }

    #[test]
    fn classify_maps_too_many_revisions_to_its_own_variant() {
        // `revisions:listFromSeq` refuses a window past 4096 rather than truncate;
        // a truncated mark set would make the GC delete live data (§6.3), so the
        // client must be able to tell this apart from a generic function error.
        match classify_convex_error(&convex_err(
            "too_many_revisions",
            "more than 4096 Revisions at or above seq 0",
        )) {
            CoordinatorError::TooManyRevisions { message } => {
                assert!(message.contains("4096"));
            }
            other => panic!("expected TooManyRevisions, got {other:?}"),
        }
    }

    #[test]
    fn classify_maps_space_key_already_set_and_dangling_head() {
        assert!(matches!(
            classify_convex_error(&convex_err(
                "space_key_already_set",
                "already has a spaceKey"
            )),
            CoordinatorError::SpaceKeyAlreadySet { .. }
        ));
        assert!(matches!(
            classify_convex_error(&convex_err(
                "dangling_head",
                "head points at a missing Revision"
            )),
            CoordinatorError::DanglingHead { .. }
        ));
    }

    #[test]
    fn classify_unknown_code_falls_back_to_function_with_message() {
        // A code this client does not map (e.g. bad_dedup_secret) keeps the raw
        // message so verbose output (RUST_LOG=debug)/logs still surfaces the detail.
        match classify_convex_error(&convex_err("bad_dedup_secret", "must be 32 bytes")) {
            CoordinatorError::Function(m) => assert_eq!(m, "must be 32 bytes"),
            other => panic!("expected Function fallback, got {other:?}"),
        }
    }

    #[test]
    fn classify_convex_error_without_data_code_is_function() {
        // A bare thrown Error (Convex redacts it to a message with no structured
        // data) must not misclassify; it falls back to Function.
        let e = ConvexError {
            message: "Server Error".into(),
            data: Value::Null,
        };
        assert!(matches!(
            classify_convex_error(&e),
            CoordinatorError::Function(m) if m == "Server Error"
        ));
    }

    #[test]
    fn unwrap_value_maps_convex_error_to_typed_variant() {
        let r = unwrap_value(FunctionResult::ConvexError(convex_err(
            "space_not_found",
            "no such Space",
        )));
        assert!(matches!(r, Err(CoordinatorError::SpaceNotFound { .. })));
    }

    // ----- id newtype ergonomics -----

    #[test]
    fn id_newtypes_display_and_to_value() {
        let a = AccountId::new("acc_x");
        assert_eq!(a.as_str(), "acc_x");
        assert_eq!(a.to_string(), "acc_x");
        assert_eq!(a.to_value(), Value::String("acc_x".into()));
    }

    #[test]
    fn missing_field_is_reported_with_context() {
        // A Space doc missing metaBlobCid.
        let v = objv([
            ("_id", Value::String("sp_1".into())),
            ("accountId", Value::String("acc_1".into())),
            ("name", Value::Bytes(vec![])),
            ("headRevisionId", Value::Null),
        ]);
        match parse_space(&v) {
            Err(CoordinatorError::MissingField { field, .. }) => assert_eq!(field, "metaBlobCid"),
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    // ----- per-call deadline -----

    #[tokio::test]
    async fn with_deadline_ends_a_call_the_coordinator_never_answers() {
        // The failure this guards: the convex client re-sends an outstanding call
        // on every reconnect and its socket worker reconnects forever, so a
        // Coordinator that accepts the connection and then goes silent leaves the
        // future pending for good — a one-shot command that looks wedged.
        let stalled = futures::future::pending::<FunctionResult>();
        match with_deadline(Duration::from_millis(10), func::REVISIONS_COMMIT, stalled).await {
            Err(CoordinatorError::Timeout { function, timeout }) => {
                assert_eq!(function, func::REVISIONS_COMMIT);
                assert_eq!(timeout, Duration::from_millis(10));
                // The message must name the function, so the log says WHICH call hung.
                let rendered = CoordinatorError::Timeout { function, timeout }.to_string();
                assert!(rendered.contains("revisions:commit"), "got {rendered}");
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn with_deadline_passes_an_answered_call_straight_through() {
        let ready = std::future::ready(Value::Int64(7));
        let v = with_deadline(DEFAULT_CALL_TIMEOUT, func::SPACES_HEAD, ready)
            .await
            .unwrap();
        assert_eq!(v, Value::Int64(7));
    }

    #[test]
    fn the_default_call_deadline_outlasts_one_reconnect_cycle_of_the_convex_client() {
        // The convex client gives up on a silent socket after 30s and reconnects
        // with at most 15s of backoff; a deadline shorter than that sum would fail
        // calls that were about to succeed.
        assert!(DEFAULT_CALL_TIMEOUT >= Duration::from_secs(45));
    }

    // ----- live integration (red real) — requires a Convex deployment -----
    //
    // This test talks to a real self-hosted Convex backend and is therefore
    // `#[ignore]`d: the normal `cargo test`/build must NOT depend on the
    // network. Run it explicitly with the env wired up:
    //
    //   CONVEX_SELF_HOSTED_URL=http://localhost:3210 \
    //   FILETHING_TEST_JWT=<a Convex-audience JWT from Better Auth> \
    //   cargo test -p ft-coordinator -- --ignored seq_args_are_accepted_by_live_backend
    //
    // NOTE: since Fase 3 every contract function is authenticated (`ctx.auth`),
    // so this needs a real USER JWT (minted by Better Auth), not the deployment
    // admin key — `set_admin_auth` no longer yields a `getUserIdentity()` and
    // `ensure_device` would reject with `unauthenticated`. Obtain a JWT the same
    // way the CLI does (see `apps/cli` login) and pass it in `FILETHING_TEST_JWT`.
    //
    // It exercises the exact path the seq bug breaks: a `v.number()` validator on
    // `revisions:bySeq` and `devices:setBaseSeq` rejects `Value::Int64`. With the
    // Float64 fix the round trip below must complete WITHOUT a function error.
    #[tokio::test]
    #[ignore = "requires a live self-hosted Convex backend + a user JWT (FILETHING_TEST_JWT)"]
    async fn seq_args_are_accepted_by_live_backend() {
        let url = match std::env::var("CONVEX_SELF_HOSTED_URL") {
            Ok(u) => u,
            Err(_) => "http://localhost:3210".to_string(),
        };
        let jwt = std::env::var("FILETHING_TEST_JWT")
            .expect("FILETHING_TEST_JWT (a Better Auth Convex-audience JWT) must be set");

        // Connect and present the user JWT so the authenticated functions run.
        let mut client = ConvexClient::new(&url)
            .await
            .expect("connect to self-hosted Convex");
        client.set_auth(Some(jwt)).await;
        let mut coord = Coordinator::from_client(client);

        // ensureDevice: get-or-create this identity's Account + Device.
        let ensured = coord
            .ensure_device("it-device", &[1u8; 32])
            .await
            .expect("ensure_device must succeed");

        // create_space: a fresh Space (head starts null). The client generates the
        // escrow space_key; the owning Account is derived from the JWT.
        let meta = cid(1);
        let space_id = coord
            .create_space(b"it-space", &meta, &[2u8; 32])
            .await
            .expect("create_space must succeed");

        // commit(base=None): the first Revision; the server assigns seq = 0.
        let ok = coord
            .commit_revision(&space_id, None, &cid(2), &ensured.device_id)
            .await
            .expect("first commit must succeed");
        assert_eq!(ok.seq, 0, "first Revision seq should be 0");

        // revision_by_seq(0): this is the call that sends `seq` and previously
        // failed with a "Server Error" because of the Int64/float64 mismatch.
        let rev = coord
            .revision_by_seq(&space_id, 0)
            .await
            .expect("revision_by_seq(0) must NOT return a server error");
        assert_eq!(rev.seq, 0);
        assert_eq!(rev.space_id, space_id);

        // set_base_seq(0): the second call that sends a number arg under a
        // `v.number()` validator.
        coord
            .set_base_seq(&ensured.device_id, 0)
            .await
            .expect("set_base_seq(0) must NOT return a server error");
    }
}
