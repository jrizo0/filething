//! ft-coordinator — Rust client for the Coordinator (control plane). `§6.2`, `§7`
//! (client side), `§8`.
//!
//! Wraps the official [`convex`] crate ([`convex::ConvexClient`]) and exposes the
//! filething control-plane operations as typed Rust methods: device pairing
//! ([`Coordinator::bootstrap`] / [`Coordinator::claim`]), Space creation and
//! lookup, the Space-head compare-and-swap ([`Coordinator::commit_revision`],
//! `§7`), revision lookup by seq, and the reactive head subscription
//! ([`Coordinator::subscribe_head`], the change feed of `§8`).
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

use std::collections::BTreeMap;

use convex::{ConvexClient, FunctionResult, Value};
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

    /// A Convex function returned an application error (a thrown `Error` or a
    /// `ConvexError`) that is NOT the recognized commit-conflict marker.
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

/// Result of `auth:bootstrap` — the first Device of a fresh Account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapResult {
    /// The freshly created Account.
    pub account_id: AccountId,
    /// This (first) Device.
    pub device_id: DeviceId,
    /// A pairing code a second Device can `claim`.
    pub pairing_code: String,
}

/// Result of `auth:claim` — a second Device joining an existing Account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimResult {
    /// The Account joined.
    pub account_id: AccountId,
    /// This (newly joined) Device.
    pub device_id: DeviceId,
}

/// A `Space` document (`spaces:get` / `spaces:listByAccount`). `§6.2`.
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
    pub const AUTH_BOOTSTRAP: &str = "auth:bootstrap";
    pub const AUTH_CLAIM: &str = "auth:claim";
    pub const SPACES_CREATE: &str = "spaces:create";
    pub const SPACES_GET: &str = "spaces:get";
    pub const SPACES_LIST_BY_ACCOUNT: &str = "spaces:listByAccount";
    pub const SPACES_HEAD: &str = "spaces:head";
    pub const SPACES_REFRESH_RETENTION_FLOOR: &str = "spaces:refreshRetentionFloor";
    pub const REVISIONS_COMMIT: &str = "revisions:commit";
    pub const REVISIONS_BY_SEQ: &str = "revisions:bySeq";
    pub const REVISIONS_LIST_FROM_SEQ: &str = "revisions:listFromSeq";
    pub const DEVICES_SET_BASE_SEQ: &str = "devices:setBaseSeq";
}

/// Marker the backend's `revisions:commit` mutation uses to flag a CAS conflict
/// in a machine-distinguishable way: a thrown `ConvexError` whose `data` object
/// carries `{ "code": "conflict" }`, and/or this substring in the message.
const CONFLICT_CODE: &str = "conflict";

// ---------------------------------------------------------------------------
// Argument builders (pure)
// ---------------------------------------------------------------------------

fn obj(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> BTreeMap<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

fn bootstrap_args(device_name: &str) -> BTreeMap<String, Value> {
    obj([("deviceName", Value::String(device_name.to_string()))])
}

fn claim_args(code: &str, device_name: &str) -> BTreeMap<String, Value> {
    obj([
        ("code", Value::String(code.to_string())),
        ("deviceName", Value::String(device_name.to_string())),
    ])
}

fn create_space_args(
    account_id: &AccountId,
    name: &[u8],
    meta_blob_cid: &Cid,
) -> BTreeMap<String, Value> {
    obj([
        ("accountId", account_id.to_value()),
        ("name", Value::Bytes(name.to_vec())),
        ("metaBlobCid", wire::cid_to_value(meta_blob_cid)),
    ])
}

fn get_space_args(space_id: &SpaceId) -> BTreeMap<String, Value> {
    obj([("spaceId", space_id.to_value())])
}

fn list_spaces_args(account_id: &AccountId) -> BTreeMap<String, Value> {
    obj([("accountId", account_id.to_value())])
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

fn list_from_seq_args(space_id: &SpaceId, min_seq: u64) -> BTreeMap<String, Value> {
    obj([
        ("spaceId", space_id.to_value()),
        // `v.number()` on the backend → Convex float64 (see `revision_by_seq_args`).
        ("minSeq", Value::Float64(min_seq as f64)),
    ])
}

fn refresh_retention_floor_args(space_id: &SpaceId) -> BTreeMap<String, Value> {
    obj([("spaceId", space_id.to_value())])
}

// ---------------------------------------------------------------------------
// Response parsers (pure)
// ---------------------------------------------------------------------------

fn parse_bootstrap(v: &Value) -> Result<BootstrapResult> {
    const CTX: &str = func::AUTH_BOOTSTRAP;
    let o = wire::as_object(v, CTX)?;
    Ok(BootstrapResult {
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
        pairing_code: wire::as_string(wire::field(o, "pairingCode", CTX)?, "pairingCode", CTX)?,
    })
}

fn parse_claim(v: &Value) -> Result<ClaimResult> {
    const CTX: &str = func::AUTH_CLAIM;
    let o = wire::as_object(v, CTX)?;
    Ok(ClaimResult {
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
    })
}

fn parse_space_list(v: &Value) -> Result<Vec<Space>> {
    const CTX: &str = func::SPACES_LIST_BY_ACCOUNT;
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

/// Unwraps a [`FunctionResult`] to its success [`Value`], mapping application
/// errors to [`CoordinatorError::Function`].
fn unwrap_value(result: FunctionResult) -> Result<Value> {
    match result {
        FunctionResult::Value(v) => Ok(v),
        FunctionResult::ErrorMessage(msg) => Err(CoordinatorError::Function(msg)),
        FunctionResult::ConvexError(e) => Err(CoordinatorError::Function(e.message)),
    }
}

/// True if a [`FunctionResult`] is the recognized commit-conflict signal: a
/// `ConvexError` whose `data` is `{ "code": "conflict" }` (preferred,
/// machine-stable), or an error whose message contains `"conflict"` (fallback).
fn is_conflict(result: &FunctionResult) -> bool {
    match result {
        FunctionResult::ConvexError(e) => {
            if let Value::Object(data) = &e.data {
                if let Some(Value::String(code)) = data.get("code") {
                    if code.eq_ignore_ascii_case(CONFLICT_CODE) {
                        return true;
                    }
                }
            }
            e.message.to_ascii_lowercase().contains(CONFLICT_CODE)
        }
        FunctionResult::ErrorMessage(msg) => msg.to_ascii_lowercase().contains(CONFLICT_CODE),
        FunctionResult::Value(_) => false,
    }
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
        Ok(Self { client })
    }

    /// Wraps an already-built [`convex::ConvexClient`] (e.g. one configured by a
    /// [`convex::ConvexClientBuilder`]).
    pub fn from_client(client: ConvexClient) -> Self {
        Self { client }
    }

    async fn call_mutation(&mut self, name: &str, args: BTreeMap<String, Value>) -> Result<Value> {
        let result = self
            .client
            .mutation(name, args)
            .await
            .map_err(|e| CoordinatorError::Transport(e.to_string()))?;
        unwrap_value(result)
    }

    async fn call_query(&mut self, name: &str, args: BTreeMap<String, Value>) -> Result<Value> {
        let result = self
            .client
            .query(name, args)
            .await
            .map_err(|e| CoordinatorError::Transport(e.to_string()))?;
        unwrap_value(result)
    }

    // ----- auth -----

    /// `auth:bootstrap` — create the first Account + Device and mint a pairing
    /// code.
    pub async fn bootstrap(&mut self, device_name: &str) -> Result<BootstrapResult> {
        let v = self
            .call_mutation(func::AUTH_BOOTSTRAP, bootstrap_args(device_name))
            .await?;
        parse_bootstrap(&v)
    }

    /// `auth:claim` — join an existing Account with a pairing `code`.
    pub async fn claim(&mut self, code: &str, device_name: &str) -> Result<ClaimResult> {
        let v = self
            .call_mutation(func::AUTH_CLAIM, claim_args(code, device_name))
            .await?;
        parse_claim(&v)
    }

    // ----- spaces -----

    /// `spaces:create` — create a Space (head starts `null`). Returns its id.
    pub async fn create_space(
        &mut self,
        account_id: &AccountId,
        name: &[u8],
        meta_blob_cid: &Cid,
    ) -> Result<SpaceId> {
        let v = self
            .call_mutation(
                func::SPACES_CREATE,
                create_space_args(account_id, name, meta_blob_cid),
            )
            .await?;
        parse_space_id(&v)
    }

    /// `spaces:get` — fetch a Space document.
    pub async fn get_space(&mut self, space_id: &SpaceId) -> Result<Space> {
        let v = self
            .call_query(func::SPACES_GET, get_space_args(space_id))
            .await?;
        parse_space(&v)
    }

    /// `spaces:listByAccount` — every Space of an Account.
    pub async fn list_spaces(&mut self, account_id: &AccountId) -> Result<Vec<Space>> {
        let v = self
            .call_query(func::SPACES_LIST_BY_ACCOUNT, list_spaces_args(account_id))
            .await?;
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
        let result = self
            .client
            .mutation(
                func::REVISIONS_COMMIT,
                commit_args(space_id, expected_base, manifest_root, author_device_id),
            )
            .await
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

    /// `revisions:listFromSeq` — every Revision root at or above `min_seq` (the
    /// GC's retained set, `§6.3`). Returns id + seq + Manifest root per Revision.
    pub async fn list_revisions_from(
        &mut self,
        space_id: &SpaceId,
        min_seq: u64,
    ) -> Result<Vec<RevisionRoot>> {
        let v = self
            .call_query(
                func::REVISIONS_LIST_FROM_SEQ,
                list_from_seq_args(space_id, min_seq),
            )
            .await?;
        parse_revision_roots(&v)
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

    /// `spaces:head` — subscribe to the reactive Space-head query and yield a
    /// [`HeadUpdate`] every time it changes. The change feed of `§8`.
    ///
    /// The returned [`Stream`] yields `Result<HeadUpdate>`: a parse failure on
    /// one pushed value is surfaced as an `Err` item without ending the stream.
    pub async fn subscribe_head(
        &mut self,
        space_id: &SpaceId,
    ) -> Result<impl Stream<Item = Result<HeadUpdate>>> {
        let sub = self
            .client
            .subscribe(func::SPACES_HEAD, head_args(space_id))
            .await
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
    fn bootstrap_args_have_device_name() {
        let args = bootstrap_args("laptop");
        assert_eq!(args.keys().cloned().collect::<Vec<_>>(), vec!["deviceName"]);
        assert_eq!(args["deviceName"], Value::String("laptop".into()));
    }

    #[test]
    fn claim_args_have_code_and_device_name() {
        let args = claim_args("ABCD-1234", "phone");
        let keys: Vec<_> = args.keys().cloned().collect();
        assert_eq!(keys, vec!["code", "deviceName"]);
        assert_eq!(args["code"], Value::String("ABCD-1234".into()));
        assert_eq!(args["deviceName"], Value::String("phone".into()));
    }

    #[test]
    fn create_space_args_use_bytes_for_name_and_meta() {
        let acct = AccountId::new("acc_1");
        let name = "My Space".as_bytes();
        let meta = cid(3);
        let args = create_space_args(&acct, name, &meta);
        let keys: Vec<_> = args.keys().cloned().collect();
        assert_eq!(keys, vec!["accountId", "metaBlobCid", "name"]); // BTreeMap orders keys
        assert_eq!(args["accountId"], Value::String("acc_1".into()));
        assert_eq!(args["name"], Value::Bytes(name.to_vec()));
        assert_eq!(args["metaBlobCid"], Value::Bytes(vec![3u8; 32]));
    }

    #[test]
    fn get_and_list_and_head_args() {
        assert_eq!(
            get_space_args(&SpaceId::new("sp_1"))["spaceId"],
            Value::String("sp_1".into())
        );
        assert_eq!(
            list_spaces_args(&AccountId::new("acc_1"))["accountId"],
            Value::String("acc_1".into())
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
        let args = list_from_seq_args(&SpaceId::new("sp_1"), 7);
        let keys: Vec<_> = args.keys().cloned().collect();
        assert_eq!(keys, vec!["minSeq", "spaceId"]);
        assert_eq!(args["spaceId"], Value::String("sp_1".into()));
        assert_eq!(args["minSeq"], Value::Float64(7.0));
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
    fn parse_bootstrap_result() {
        let v = objv([
            ("accountId", Value::String("acc_1".into())),
            ("deviceId", Value::String("dev_1".into())),
            ("pairingCode", Value::String("WXYZ-9999".into())),
        ]);
        let r = parse_bootstrap(&v).unwrap();
        assert_eq!(r.account_id, AccountId::new("acc_1"));
        assert_eq!(r.device_id, DeviceId::new("dev_1"));
        assert_eq!(r.pairing_code, "WXYZ-9999");
    }

    #[test]
    fn parse_claim_result() {
        let v = objv([
            ("accountId", Value::String("acc_2".into())),
            ("deviceId", Value::String("dev_2".into())),
        ]);
        let r = parse_claim(&v).unwrap();
        assert_eq!(r.account_id, AccountId::new("acc_2"));
        assert_eq!(r.device_id, DeviceId::new("dev_2"));
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
        ]);
        let s = parse_space(&v).unwrap();
        assert_eq!(s.space_id, SpaceId::new("sp_1"));
        assert_eq!(s.account_id, AccountId::new("acc_1"));
        assert_eq!(s.name, b"hello".to_vec());
        assert_eq!(s.head_revision_id, Some(RevisionId::new("rev_3")));
        assert_eq!(s.meta_blob_cid, cid(4));
    }

    #[test]
    fn parse_space_with_null_head() {
        let v = objv([
            ("_id", Value::String("sp_1".into())),
            ("accountId", Value::String("acc_1".into())),
            ("name", Value::Bytes(vec![])),
            ("headRevisionId", Value::Null),
            ("metaBlobCid", Value::Bytes(vec![0u8; 32])),
        ]);
        let s = parse_space(&v).unwrap();
        assert_eq!(s.head_revision_id, None);
    }

    #[test]
    fn parse_space_list_of_two() {
        let one = objv([
            ("_id", Value::String("sp_1".into())),
            ("accountId", Value::String("acc_1".into())),
            ("name", Value::Bytes(vec![1])),
            ("headRevisionId", Value::Null),
            ("metaBlobCid", Value::Bytes(vec![1u8; 32])),
        ]);
        let two = objv([
            ("_id", Value::String("sp_2".into())),
            ("accountId", Value::String("acc_1".into())),
            ("name", Value::Bytes(vec![2])),
            ("headRevisionId", Value::String("rev_9".into())),
            ("metaBlobCid", Value::Bytes(vec![2u8; 32])),
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
        let r = FunctionResult::ErrorMessage("Conflict: base != head".into());
        assert!(is_conflict(&r));
        assert!(matches!(interpret_commit(r), Err(CommitError::Conflict)));
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

    // ----- live integration (red real) — requires a Convex deployment -----
    //
    // This test talks to a real self-hosted Convex backend and is therefore
    // `#[ignore]`d: the normal `cargo test`/build must NOT depend on the
    // network. Run it explicitly with the env wired up:
    //
    //   CONVEX_SELF_HOSTED_URL=http://localhost:3210 \
    //   CONVEX_SELF_HOSTED_ADMIN_KEY=<admin-key> \
    //   cargo test -p ft-coordinator -- --ignored seq_args_are_accepted_by_live_backend
    //
    // It exercises the exact path the bug breaks: a `v.number()` validator on
    // `revisions:bySeq` and `devices:setBaseSeq` rejects `Value::Int64`. With
    // the Float64 fix the round trip below must complete WITHOUT a function
    // error.
    #[tokio::test]
    #[ignore = "requires a live self-hosted Convex backend (CONVEX_SELF_HOSTED_URL / _ADMIN_KEY)"]
    async fn seq_args_are_accepted_by_live_backend() {
        let url = match std::env::var("CONVEX_SELF_HOSTED_URL") {
            Ok(u) => u,
            Err(_) => "http://localhost:3210".to_string(),
        };
        let admin_key = std::env::var("CONVEX_SELF_HOSTED_ADMIN_KEY")
            .expect("CONVEX_SELF_HOSTED_ADMIN_KEY must be set to run this test");

        // Connect as a deployment admin so the contract functions run.
        let mut client = ConvexClient::new(&url)
            .await
            .expect("connect to self-hosted Convex");
        client.set_admin_auth(admin_key, None).await;
        let mut coord = Coordinator::from_client(client);

        // bootstrap: first Account + Device.
        let boot = coord
            .bootstrap("it-device")
            .await
            .expect("bootstrap must succeed");

        // create_space: a fresh Space (head starts null).
        let meta = cid(1);
        let space_id = coord
            .create_space(&boot.account_id, b"it-space", &meta)
            .await
            .expect("create_space must succeed");

        // commit(base=None): the first Revision; the server assigns seq = 0.
        let ok = coord
            .commit_revision(&space_id, None, &cid(2), &boot.device_id)
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
            .set_base_seq(&boot.device_id, 0)
            .await
            .expect("set_base_seq(0) must NOT return a server error");
    }
}
