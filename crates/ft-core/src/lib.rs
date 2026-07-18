//! ft-core — shared types and constants for filething (FOUNDATION).
//!
//! Owns the ubiquitous-language vocabulary at the type level: [`Cid`]/[`Pcid`]
//! (separate newtypes from day 1), [`FileEntry`], Manifest page types
//! ([`LeafPage`]/[`IndexPage`]/[`ChildRef`]), the [`BlockHeader`], the
//! wire/format constants and KDF context strings, plus the root [`Error`] enum.
//!
//! No hashing, IO, or wire serialization logic lives here — those belong to the
//! consuming crates (`ft-hash`, `ft-block`, `ft-manifest`, ...). This crate only
//! defines the stable types and constants every other crate shares, exactly per
//! `docs/format.md` §2, §4.3, §5.1, §5.3 and `docs/BUILD-PLAN.md` §3.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants — wire/format (docs/format.md §3, §4.3, §5.3; BUILD-PLAN §3)
// ---------------------------------------------------------------------------

/// FastCDC minimum chunk size (16 KiB). `docs/format.md §3`.
pub const CHUNK_MIN: usize = 16384;
/// FastCDC average / target chunk size (64 KiB). `docs/format.md §3`.
pub const CHUNK_AVG: usize = 65536;
/// FastCDC maximum chunk size (256 KiB). `docs/format.md §3`.
pub const CHUNK_MAX: usize = 262144;

/// Maximum `FileEntry` count per Manifest leaf page. `docs/format.md §5.3`.
pub const LEAF_FANOUT: usize = 256;
/// Maximum child count per Manifest index page. `docs/format.md §5.3`.
pub const INDEX_FANOUT: usize = 256;
/// Threshold (CBOR bytes) above which a `FileEntry`'s `bk` list is externalized
/// to a `blocklist/<cid>` object (256 KiB). `docs/format.md §5.3`.
pub const ENTRY_INLINE_MAX: usize = 262144;

/// Fixed Block/Manifest-page header length in bytes. `docs/format.md §4.3`.
pub const BLOCK_HEADER_LEN: usize = 64;

/// Magic for a Block object header: `b"FTB1"`. `docs/format.md §4.3`.
pub const MAGIC_BLOCK: [u8; 4] = *b"FTB1";
/// Magic for a Manifest-page object header: `b"FTM1"`. `docs/format.md §5.3`.
pub const MAGIC_MANIFEST: [u8; 4] = *b"FTM1";

/// Current header version. `docs/format.md §4.3`.
pub const HEADER_VERSION: u8 = 1;

/// AEAD algorithm id for cleartext payloads (MVP default). `docs/format.md §4.3`.
pub const ALG_CLEARTEXT: u8 = 0;
/// AEAD algorithm id for XChaCha20-Poly1305 runtime encryption. `docs/format.md §4.3`.
pub const ALG_AEAD: u8 = 1;
/// Alias of [`ALG_AEAD`] spelled out with the spec's primitive name, used by the
/// `alg=1` encode/decode path (`ft-block`) so call sites don't have to remember
/// that "AEAD" means XChaCha20-Poly1305 specifically. Same value as [`ALG_AEAD`].
pub const ALG_XCHACHA20_POLY1305: u8 = ALG_AEAD;

/// Wrap-algorithm id for the sidecar's `wrap_alg` field (`docs/format.md §4.5`):
/// XChaCha20-Poly1305 with the Space key (via a KDF subkey) as KEK. Numerically
/// equal to [`ALG_XCHACHA20_POLY1305`] today (same AEAD choice), but kept as its
/// own constant: a Block's `alg` and a sidecar's `wrap_alg` are logically
/// distinct fields that happen to share one algorithm.
pub const WRAP_ALG_XCHACHA20_POLY1305: u8 = 1;

// ---------------------------------------------------------------------------
// KDF context strings (docs/format.md §2.1)
// ---------------------------------------------------------------------------

/// KDF context for the FastCDC gear table (input: chunk secret). `docs/format.md §2.1`.
pub const CTX_CDC_GEAR: &str = "filething.cdc.gear.v1";
/// KDF context for the per-content data key (input: dedup secret, info=pcid). `docs/format.md §2.1`.
pub const CTX_BLOCK_KEY: &str = "filething.block.key.v1";
/// KDF context for the per-content nonce (input: dedup secret, info=pcid). `docs/format.md §2.1`.
pub const CTX_BLOCK_NONCE: &str = "filething.block.nonce.v1";
/// KDF context for the data-key wrap subkey (input: Space key). `docs/format.md §2.1`.
pub const CTX_KEYWRAP: &str = "filething.keywrap.v1";
/// KDF context for a Manifest-page data key (input: Space key, info=page pcid). `docs/format.md §2.1`.
pub const CTX_MANIFEST_KEY: &str = "filething.manifest.key.v1";

// ---------------------------------------------------------------------------
// Errors (docs/BUILD-PLAN.md §3 — root error enum with thiserror)
// ---------------------------------------------------------------------------

/// Root error type for the filething foundation crate.
///
/// Consuming crates typically define their own `thiserror` enum and convert
/// from this one where they touch core types.
#[derive(Debug, Error)]
pub enum Error {
    /// A hex string did not decode to the expected 32-byte content id.
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// A 32-byte id had the wrong length after hex decoding.
    #[error("invalid id length: expected {expected} bytes, got {got}")]
    InvalidIdLength { expected: usize, got: usize },

    /// A buffer presented as a Block/Manifest header was too short.
    #[error("buffer too short for header: expected {expected} bytes, got {got}")]
    HeaderTooShort { expected: usize, got: usize },

    /// The header magic did not match a known value.
    #[error("bad header magic: {got:02x?}")]
    BadMagic { got: [u8; 4] },

    /// The header version was not understood.
    #[error("unsupported header version: {0}")]
    UnsupportedHeaderVersion(u8),

    /// A `u8` value did not correspond to any [`FileType`] variant.
    #[error("invalid FileType discriminant: {0}")]
    InvalidFileType(u8),
}

/// Crate-wide `Result` alias over the root [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Content ids — Cid / Pcid (docs/format.md §4.1; BUILD-PLAN §3)
// ---------------------------------------------------------------------------

/// Generates a 32-byte content-id newtype with hex helpers and CBOR-bytestring
/// serde. `Cid` and `Pcid` are SEPARATE types from day 1 (`docs/format.md §4.1`)
/// even though `cid == pcid` while encryption is OFF in the MVP.
macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// Wraps a raw 32-byte digest.
            #[inline]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrows the underlying 32 bytes.
            #[inline]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Consumes into the raw 32 bytes.
            #[inline]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }

            /// Lowercase hex encoding (64 chars). `docs/format.md §2` naming.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parses a 64-char lowercase hex string back into the id.
            pub fn from_hex(s: &str) -> $crate::Result<Self> {
                let v = hex::decode(s)?;
                let arr: [u8; 32] = v
                    .as_slice()
                    .try_into()
                    .map_err(|_| $crate::Error::InvalidIdLength {
                        expected: 32,
                        got: v.len(),
                    })?;
                Ok(Self(arr))
            }
        }

        // Hex in Debug keeps logs readable and stable.
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        // Emit as a CBOR major-type-2 bytestring (via serde_bytes), NOT an array
        // of integers — required so `pcid`/`cid` are compact in the wire format
        // (docs/format.md §2, §5.1).
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                serde_bytes::serialize(&self.0[..], s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                d: D,
            ) -> std::result::Result<Self, D::Error> {
                let bytes: Vec<u8> = serde_bytes::deserialize(d)?;
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    serde::de::Error::invalid_length(
                        bytes.len(),
                        &"a 32-byte content id",
                    )
                })?;
                Ok(Self(arr))
            }
        }
    };
}

id_newtype! {
    /// Content id: `BLAKE3-256(nonce || stored payload)` — the addressing hash
    /// (ciphertext under encryption, cleartext in the MVP). Names objects in the
    /// Vault and appears in the Manifest. `docs/format.md §4.1`.
    Cid
}

id_newtype! {
    /// Plaintext content id: `BLAKE3-256(cleartext)` — the dedup key, scoped to
    /// the Account. Lives only in a Device's local index and the dedup table,
    /// never as an object name. SEPARATE from [`Cid`]. `docs/format.md §4.1`.
    Pcid
}

// ---------------------------------------------------------------------------
// Canonical path & casefold key (docs/format.md §5.2; BUILD-PLAN §3)
// ---------------------------------------------------------------------------

/// A canonical Space-relative path: forward slashes, relative (no leading `/`),
/// UTF-8. This is the Manifest KEY surface. `docs/format.md §5.2`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CanonicalPath(pub String);

impl CanonicalPath {
    /// Borrows the path as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanonicalPath({:?})", self.0)
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The ordering/collision key for a [`CanonicalPath`]: `casefold(NFC(p))`.
/// Used to order, compare and detect case/NFC collisions; never touches the
/// content. `docs/format.md §5.2`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CasefoldKey(pub String);

impl CasefoldKey {
    /// Borrows the key as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CasefoldKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CasefoldKey({:?})", self.0)
    }
}

impl fmt::Display for CasefoldKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// FileType (docs/format.md §5.1; BUILD-PLAN §3)
// ---------------------------------------------------------------------------

/// Kind of a [`FileEntry`]. Wire value is a `u8` (`0=file, 1=symlink,
/// 2=derived, 3=dir`). `docs/format.md §5.1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FileType {
    /// A regular file: uses `x`, `sz`, `pcid`, `bk`.
    File = 0,
    /// A symlink: uses `lt` (literal target).
    Symlink = 1,
    /// A derived path (e.g. `node_modules/`, `target/`): `bk` always empty.
    Derived = 2,
    /// A plain directory tracked as a first-class entry so empty directories
    /// sync (ADR 0019). Only `p` and `t` are meaningful: `sz=0`, `pcid` zeroed,
    /// `x=false`, `bk` empty, no `bk_ref`/`lt`. The Space root is never an entry.
    Dir = 3,
}

impl FileType {
    /// The wire `u8` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses a wire `u8` into a [`FileType`].
    #[inline]
    pub const fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(FileType::File),
            1 => Ok(FileType::Symlink),
            2 => Ok(FileType::Derived),
            3 => Ok(FileType::Dir),
            other => Err(Error::InvalidFileType(other)),
        }
    }
}

impl From<FileType> for u8 {
    #[inline]
    fn from(t: FileType) -> u8 {
        t.as_u8()
    }
}

impl TryFrom<u8> for FileType {
    type Error = Error;

    #[inline]
    fn try_from(v: u8) -> Result<Self> {
        FileType::from_u8(v)
    }
}

// FileType serializes as its bare u8 discriminant so the CBOR `t` field is an
// integer (docs/format.md §5.1), not a string variant name.
impl Serialize for FileType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for FileType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = u8::deserialize(d)?;
        FileType::from_u8(v).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// FileEntry (docs/format.md §5.1)
// ---------------------------------------------------------------------------

/// The Manifest unit: a canonical path mapped to its type and (for files) its
/// ordered list of Block [`Cid`]s. CBOR field names are the short `§5.1` codes.
///
/// Absent-by-variant fields use `skip_serializing_if` so a file entry carries no
/// `lt`, a symlink carries no `bk`/`sz`/`pcid`, etc. — keeping pages compact and
/// the encoding canonical. A `FileEntry` holds EITHER `bk` inline OR `bk_ref`
/// (externalized blocklist) per `§5.3`, never both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Canonical path — the Manifest KEY. `docs/format.md §5.1` field `"p"`.
    #[serde(rename = "p")]
    pub p: CanonicalPath,

    /// File type (`0=file, 1=symlink, 2=derived, 3=dir`). `§5.1` field `"t"`.
    #[serde(rename = "t")]
    pub t: FileType,

    /// Executable bit (files only). `§5.1` field `"x"`.
    #[serde(rename = "x")]
    pub x: bool,

    /// Cleartext content size in bytes (files only). `§5.1` field `"sz"`.
    #[serde(rename = "sz")]
    pub sz: u64,

    /// Whole-file plaintext content id (dedup / conflict / echo). `§5.1` `"pcid"`.
    /// Emitted as a CBOR bytestring.
    #[serde(rename = "pcid")]
    pub pcid: Pcid,

    /// Ordered list of Block ids; concatenating their payloads is the file.
    /// The order IS the content. Empty for symlink/derived. `§5.1` field `"bk"`.
    #[serde(rename = "bk", default, skip_serializing_if = "Vec::is_empty")]
    pub bk: Vec<Cid>,

    /// Reference to an externalized `blocklist/<cid>` when `bk` would exceed
    /// [`ENTRY_INLINE_MAX`] inline (`§5.3`). Mutually exclusive with `bk`.
    /// `§5.1` field `"bk_ref"`.
    #[serde(rename = "bk_ref", default, skip_serializing_if = "Option::is_none")]
    pub bk_ref: Option<Cid>,

    /// Literal symlink target (symlinks only), preserved byte-exact. `§5.1` `"lt"`.
    #[serde(rename = "lt", default, skip_serializing_if = "Option::is_none")]
    pub lt: Option<String>,

    /// RESERVED windows-unsafe flag; absent/false by default. `§5.1` field `"wu"`.
    #[serde(rename = "wu", default, skip_serializing_if = "Option::is_none")]
    pub wu: Option<bool>,
}

// ---------------------------------------------------------------------------
// SpaceCrypto — runtime encryption key material (docs/format.md §4.4/§4.5)
// ---------------------------------------------------------------------------

/// The in-memory key material that turns ON runtime `alg=1` encryption for a
/// mounted Space. Absent (`Option::None` at the call sites that take it) ⇒ the
/// cleartext `alg=0` path is used and nothing about behavior changes.
///
/// - `dedup_secret` is the per-Account secret that derives the DETERMINISTIC
///   per-content data key and nonce (`ft_hash::data_key` / `ft_hash::nonce`,
///   `§4.4`), so the same cleartext in the same Account always encrypts to the
///   same `cid` — the property cross-Device dedup relies on under encryption.
/// - `space_key` wraps/unwraps each Block's data key in its
///   `keys/<space_id>/<aa>/<cid>` sidecar (`§4.5`), so rotating it re-wraps the
///   ~88-byte sidecars without touching the immutable Block objects.
/// - `space_id` scopes the sidecar OBJECT KEY to this Space. The Block object
///   (`blocks/<cid>`) is Account-scoped and deduped across Spaces, but the
///   sidecar is wrapped with THIS Space's `space_key`, so two Spaces of one
///   Account sharing a chunk each need their own sidecar — hence the Space
///   component in the key (`§4.5`).
///
/// This type carries only the raw secrets; it deliberately has NO serde impl —
/// the escrow/keyring that supplies it lives outside this crate. Its [`Debug`]
/// is redacted so the secrets never reach a log.
#[derive(Clone)]
pub struct SpaceCrypto {
    /// Per-Account dedup secret (`§4.4`). Never logged (redacted in [`Debug`]).
    pub dedup_secret: [u8; 32],
    /// Per-Space key wrapping the sidecar data keys (`§4.5`). Never logged.
    pub space_key: [u8; 32],
    /// Id of the Space this key material belongs to; scopes the sidecar object
    /// key `keys/<space_id>/<aa>/<cid>` (`§4.5`). Not a secret.
    pub space_id: String,
}

impl fmt::Debug for SpaceCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the raw key bytes — a Debug of a mounted context or a
        // scan result must not leak either secret into a log or a panic message.
        f.debug_struct("SpaceCrypto")
            .field("dedup_secret", &"<redacted>")
            .field("space_key", &"<redacted>")
            .field("space_id", &self.space_id)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Manifest pages (docs/format.md §5.3)
// ---------------------------------------------------------------------------

/// A Manifest leaf page: a contiguous, key-ordered run of [`FileEntry`]s.
/// `docs/format.md §5.3`. Field `"k"` is the page kind (`0` for leaf), `"v"` the
/// page-format version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafPage {
    /// Page kind discriminant (`0` = leaf). `§5.3` field `"k"`.
    #[serde(rename = "k")]
    pub k: u8,

    /// Page-format version. `§5.3` field `"v"`.
    #[serde(rename = "v")]
    pub v: u8,

    /// Casefold key of the first entry on this page. `§5.3` field `"first"`.
    #[serde(rename = "first")]
    pub first: CasefoldKey,

    /// Casefold key of the last entry on this page. `§5.3` field `"last"`.
    #[serde(rename = "last")]
    pub last: CasefoldKey,

    /// The entries on this page, ordered by casefold key. `§5.3` field `"e"`.
    #[serde(rename = "e")]
    pub e: Vec<FileEntry>,
}

/// A pointer from a Manifest index page to a child page (leaf or index),
/// keyed by the minimum casefold key in that child's subtree. `§5.3`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildRef {
    /// Minimum casefold key covered by the child subtree. `§5.3` field `"min"`.
    #[serde(rename = "min")]
    pub min: CasefoldKey,

    /// Content id of the child page. `§5.3` field `"cid"`.
    #[serde(rename = "cid")]
    pub cid: Cid,
}

/// A Manifest index (internal) page: an ordered list of child references.
/// `docs/format.md §5.3`. Field `"k"` is the page kind (`1` for index).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexPage {
    /// Page kind discriminant (`1` = index). `§5.3` field `"k"`.
    #[serde(rename = "k")]
    pub k: u8,

    /// Page-format version. `§5.3` field `"v"`.
    #[serde(rename = "v")]
    pub v: u8,

    /// Child references, ordered by `min` key. `§5.3` field `"children"`.
    #[serde(rename = "children")]
    pub children: Vec<ChildRef>,
}

// ---------------------------------------------------------------------------
// BlockHeader — fixed 64-byte header (docs/format.md §4.3)
// ---------------------------------------------------------------------------

/// The fixed 64-byte header that prefixes every Block and Manifest-page object.
/// Layout (`docs/format.md §4.3`):
///
/// ```text
/// offset size  field
/// 0      4     magic            "FTB1" / "FTM1"
/// 4      1     header_version   1
/// 5      1     alg              0 cleartext / 1 AEAD
/// 6      1     flags            0
/// 7      1     reserved         0
/// 8      8     payload_len      u64 LE
/// 16     24    nonce            zeros in MVP
/// 40     24    reserved2        zeros
/// ```
///
/// The data key under encryption is NOT stored here (it lives in a sidecar) so
/// that `cid = BLAKE3-256(nonce || payload)` is rotation-stable (`§4.3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// 4-byte object magic ([`MAGIC_BLOCK`] / [`MAGIC_MANIFEST`]).
    pub magic: [u8; 4],
    /// Header format version ([`HEADER_VERSION`]).
    pub header_version: u8,
    /// AEAD algorithm id ([`ALG_CLEARTEXT`] / [`ALG_AEAD`]).
    pub alg: u8,
    /// Reserved bitfield flags (`0` in MVP).
    pub flags: u8,
    /// Reserved byte at offset 7 (`0`).
    pub reserved: u8,
    /// Stored payload length in bytes (little-endian on the wire).
    pub payload_len: u64,
    /// 24-byte nonce (all-zero in MVP). Folded into the `cid` (`§4.3`).
    pub nonce: [u8; 24],
    /// 24-byte reserved tail (all-zero).
    pub reserved2: [u8; 24],
}

impl BlockHeader {
    /// Builds a cleartext Block header (`alg=0`, zero nonce) for `payload_len`.
    pub fn new_block(payload_len: u64) -> Self {
        Self::new(MAGIC_BLOCK, payload_len)
    }

    /// Builds a cleartext Manifest-page header (`alg=0`, zero nonce).
    pub fn new_manifest(payload_len: u64) -> Self {
        Self::new(MAGIC_MANIFEST, payload_len)
    }

    /// Builds an encrypted (`alg=1`, [`ALG_XCHACHA20_POLY1305`]) Block header
    /// carrying the deterministic per-content `nonce` (`docs/format.md §4.3`,
    /// §4.4) and `payload_len` set to the CIPHERTEXT length (including the
    /// Poly1305 tag). Only Blocks are encrypted in this build — Manifest-page
    /// encryption (`§5.5`, zero-knowledge) is a separate future hookup.
    pub fn new_encrypted_block(payload_len: u64, nonce: [u8; 24]) -> Self {
        Self {
            magic: MAGIC_BLOCK,
            header_version: HEADER_VERSION,
            alg: ALG_XCHACHA20_POLY1305,
            flags: 0,
            reserved: 0,
            payload_len,
            nonce,
            reserved2: [0u8; 24],
        }
    }

    /// Builds a cleartext header with the given magic: `header_version=1`,
    /// `alg=0`, all reserved bytes and the nonce zeroed.
    pub fn new(magic: [u8; 4], payload_len: u64) -> Self {
        Self {
            magic,
            header_version: HEADER_VERSION,
            alg: ALG_CLEARTEXT,
            flags: 0,
            reserved: 0,
            payload_len,
            nonce: [0u8; 24],
            reserved2: [0u8; 24],
        }
    }

    /// Serializes to the fixed 64-byte on-wire layout (`payload_len` LE).
    pub fn encode(&self) -> [u8; BLOCK_HEADER_LEN] {
        let mut buf = [0u8; BLOCK_HEADER_LEN];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.header_version;
        buf[5] = self.alg;
        buf[6] = self.flags;
        buf[7] = self.reserved;
        buf[8..16].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[16..40].copy_from_slice(&self.nonce);
        buf[40..64].copy_from_slice(&self.reserved2);
        buf
    }

    /// Parses a 64-byte header. Validates length, magic ([`MAGIC_BLOCK`] or
    /// [`MAGIC_MANIFEST`]) and version. Does NOT consume the payload.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < BLOCK_HEADER_LEN {
            return Err(Error::HeaderTooShort {
                expected: BLOCK_HEADER_LEN,
                got: buf.len(),
            });
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        if magic != MAGIC_BLOCK && magic != MAGIC_MANIFEST {
            return Err(Error::BadMagic { got: magic });
        }
        let header_version = buf[4];
        if header_version != HEADER_VERSION {
            return Err(Error::UnsupportedHeaderVersion(header_version));
        }
        let alg = buf[5];
        let flags = buf[6];
        let reserved = buf[7];
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&buf[8..16]);
        let payload_len = u64::from_le_bytes(len_bytes);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&buf[16..40]);
        let mut reserved2 = [0u8; 24];
        reserved2.copy_from_slice(&buf[40..64]);
        Ok(Self {
            magic,
            header_version,
            alg,
            flags,
            reserved,
            payload_len,
            nonce,
            reserved2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Cid / Pcid hex roundtrip -----

    #[test]
    fn cid_hex_roundtrip() {
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let cid = Cid::new(bytes);
        let hex = cid.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(
            hex,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        let back = Cid::from_hex(&hex).unwrap();
        assert_eq!(cid, back);
        assert_eq!(back.into_bytes(), bytes);
    }

    #[test]
    fn pcid_hex_roundtrip() {
        let bytes = [0xabu8; 32];
        let pcid = Pcid::new(bytes);
        let back = Pcid::from_hex(&pcid.to_hex()).unwrap();
        assert_eq!(pcid, back);
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        // 31 bytes -> 62 hex chars.
        let short = "ab".repeat(31);
        match Cid::from_hex(&short) {
            Err(Error::InvalidIdLength { expected, got }) => {
                assert_eq!(expected, 32);
                assert_eq!(got, 31);
            }
            other => panic!("expected InvalidIdLength, got {other:?}"),
        }
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        assert!(matches!(Cid::from_hex("zz"), Err(Error::InvalidHex(_))));
    }

    #[test]
    fn cid_and_pcid_are_distinct_types() {
        // Compile-time proof they are separate newtypes: equal bytes, but you
        // cannot mix them. (This test exists to document the §4.1 invariant.)
        let bytes = [7u8; 32];
        let cid = Cid::new(bytes);
        let pcid = Pcid::new(bytes);
        assert_eq!(cid.as_bytes(), pcid.as_bytes());
    }

    // ----- FileType <-> u8 -----

    #[test]
    fn filetype_u8_roundtrip() {
        for (t, n) in [
            (FileType::File, 0u8),
            (FileType::Symlink, 1),
            (FileType::Derived, 2),
            (FileType::Dir, 3),
        ] {
            assert_eq!(t.as_u8(), n);
            assert_eq!(u8::from(t), n);
            assert_eq!(FileType::from_u8(n).unwrap(), t);
            assert_eq!(FileType::try_from(n).unwrap(), t);
        }
    }

    #[test]
    fn filetype_rejects_unknown() {
        // 3 is now Dir (ADR 0019); the first invalid discriminant is 4.
        assert_eq!(FileType::from_u8(3).unwrap(), FileType::Dir);
        assert!(matches!(
            FileType::from_u8(4),
            Err(Error::InvalidFileType(4))
        ));
        assert!(matches!(
            FileType::try_from(255u8),
            Err(Error::InvalidFileType(255))
        ));
    }

    // ----- BlockHeader encode / decode -----

    #[test]
    fn block_header_encodes_to_exactly_64_bytes() {
        let h = BlockHeader::new_block(12873);
        let bytes = h.encode();
        assert_eq!(bytes.len(), BLOCK_HEADER_LEN);
        assert_eq!(BLOCK_HEADER_LEN, 64);
    }

    #[test]
    fn block_header_default_is_cleartext_with_correct_magic() {
        let h = BlockHeader::new_block(42);
        assert_eq!(h.magic, MAGIC_BLOCK);
        assert_eq!(&h.magic, b"FTB1");
        assert_eq!(h.header_version, HEADER_VERSION);
        assert_eq!(h.alg, ALG_CLEARTEXT);
        assert_eq!(h.alg, 0);
        assert_eq!(h.flags, 0);
        assert_eq!(h.reserved, 0);
        assert_eq!(h.nonce, [0u8; 24]);
        assert_eq!(h.reserved2, [0u8; 24]);
    }

    #[test]
    fn manifest_header_uses_ftm1_magic() {
        let h = BlockHeader::new_manifest(7);
        assert_eq!(&h.magic, b"FTM1");
        assert_eq!(h.magic, MAGIC_MANIFEST);
    }

    #[test]
    fn encrypted_block_header_carries_alg1_and_nonce() {
        let nonce = [0x42u8; 24];
        let h = BlockHeader::new_encrypted_block(123, nonce);
        assert_eq!(h.magic, MAGIC_BLOCK);
        assert_eq!(h.alg, ALG_XCHACHA20_POLY1305);
        assert_eq!(h.alg, ALG_AEAD);
        assert_eq!(h.nonce, nonce);
        assert_eq!(h.payload_len, 123);
        assert_eq!(h.reserved2, [0u8; 24]);

        // Roundtrips through the wire encoding like any other header.
        let bytes = h.encode();
        let back = BlockHeader::decode(&bytes).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn block_header_roundtrip() {
        let h = BlockHeader::new_block(0xDEAD_BEEF);
        let bytes = h.encode();
        let back = BlockHeader::decode(&bytes).unwrap();
        assert_eq!(h, back);
        assert_eq!(back.payload_len, 0xDEAD_BEEF);
    }

    #[test]
    fn block_header_payload_len_is_little_endian() {
        let h = BlockHeader::new_block(1);
        let bytes = h.encode();
        assert_eq!(bytes[8], 1);
        assert_eq!(&bytes[9..16], &[0u8; 7]);
    }

    #[test]
    fn block_header_decode_rejects_short_buffer() {
        let short = [0u8; 32];
        assert!(matches!(
            BlockHeader::decode(&short),
            Err(Error::HeaderTooShort {
                expected: 64,
                got: 32
            })
        ));
    }

    #[test]
    fn block_header_decode_rejects_bad_magic() {
        let mut bytes = BlockHeader::new_block(1).encode();
        bytes[0] = b'X';
        assert!(matches!(
            BlockHeader::decode(&bytes),
            Err(Error::BadMagic { .. })
        ));
    }

    #[test]
    fn block_header_decode_rejects_bad_version() {
        let mut bytes = BlockHeader::new_block(1).encode();
        bytes[4] = 99;
        assert!(matches!(
            BlockHeader::decode(&bytes),
            Err(Error::UnsupportedHeaderVersion(99))
        ));
    }

    // ----- FileEntry CBOR roundtrip (ciborium) -----

    fn cbor_roundtrip(entry: &FileEntry) -> FileEntry {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(entry, &mut buf).expect("serialize");
        ciborium::de::from_reader(&buf[..]).expect("deserialize")
    }

    #[test]
    fn file_entry_cbor_roundtrip_file() {
        let entry = FileEntry {
            p: CanonicalPath("src/main.rs".to_string()),
            t: FileType::File,
            x: false,
            sz: 12873,
            pcid: Pcid::new([9u8; 32]),
            bk: vec![Cid::new([1u8; 32]), Cid::new([2u8; 32])],
            bk_ref: None,
            lt: None,
            wu: None,
        };
        assert_eq!(cbor_roundtrip(&entry), entry);
    }

    #[test]
    fn file_entry_cbor_roundtrip_symlink() {
        let entry = FileEntry {
            p: CanonicalPath("link".to_string()),
            t: FileType::Symlink,
            x: false,
            sz: 0,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![],
            bk_ref: None,
            lt: Some("../target".to_string()),
            wu: None,
        };
        assert_eq!(cbor_roundtrip(&entry), entry);
    }

    #[test]
    fn file_entry_cbor_roundtrip_externalized_blocklist() {
        let entry = FileEntry {
            p: CanonicalPath("big.bin".to_string()),
            t: FileType::File,
            x: true,
            sz: 1_073_741_824,
            pcid: Pcid::new([5u8; 32]),
            bk: vec![],
            bk_ref: Some(Cid::new([3u8; 32])),
            lt: None,
            wu: None,
        };
        assert_eq!(cbor_roundtrip(&entry), entry);
    }

    #[test]
    fn file_entry_cbor_uses_short_field_names_and_bytestrings() {
        // Verify the wire uses the §5.1 short keys and that pcid is a CBOR
        // bytestring (major type 2), not an array of integers.
        let entry = FileEntry {
            p: CanonicalPath("a".to_string()),
            t: FileType::File,
            x: false,
            sz: 1,
            pcid: Pcid::new([0u8; 32]),
            bk: vec![Cid::new([0u8; 32])],
            bk_ref: None,
            lt: None,
            wu: None,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&entry, &mut buf).unwrap();

        // Decode generically and check the map keys are the short codes.
        let val: ciborium::value::Value = ciborium::de::from_reader(&buf[..]).unwrap();
        let map = val.as_map().expect("entry is a CBOR map");
        let keys: Vec<&str> = map
            .iter()
            .map(|(k, _)| k.as_text().expect("string key"))
            .collect();
        // Variant-absent fields (bk_ref, lt, wu) must be skipped.
        assert_eq!(keys, vec!["p", "t", "x", "sz", "pcid", "bk"]);

        // pcid value must be a CBOR bytestring, not an array.
        let pcid_val = &map
            .iter()
            .find(|(k, _)| k.as_text() == Some("pcid"))
            .unwrap()
            .1;
        assert!(
            pcid_val.as_bytes().is_some(),
            "pcid must serialize as a bytestring"
        );
    }

    #[test]
    fn manifest_pages_cbor_roundtrip() {
        let leaf = LeafPage {
            k: 0,
            v: 1,
            first: CasefoldKey("a".to_string()),
            last: CasefoldKey("z".to_string()),
            e: vec![FileEntry {
                p: CanonicalPath("a".to_string()),
                t: FileType::File,
                x: false,
                sz: 3,
                pcid: Pcid::new([1u8; 32]),
                bk: vec![Cid::new([1u8; 32])],
                bk_ref: None,
                lt: None,
                wu: None,
            }],
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&leaf, &mut buf).unwrap();
        let back: LeafPage = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(leaf, back);

        let index = IndexPage {
            k: 1,
            v: 1,
            children: vec![
                ChildRef {
                    min: CasefoldKey("a".to_string()),
                    cid: Cid::new([1u8; 32]),
                },
                ChildRef {
                    min: CasefoldKey("m".to_string()),
                    cid: Cid::new([2u8; 32]),
                },
            ],
        };
        let mut buf2 = Vec::new();
        ciborium::ser::into_writer(&index, &mut buf2).unwrap();
        let back2: IndexPage = ciborium::de::from_reader(&buf2[..]).unwrap();
        assert_eq!(index, back2);
    }

    #[test]
    fn constants_match_spec() {
        assert_eq!(CHUNK_MIN, 16384);
        assert_eq!(CHUNK_AVG, 65536);
        assert_eq!(CHUNK_MAX, 262144);
        assert_eq!(LEAF_FANOUT, 256);
        assert_eq!(INDEX_FANOUT, 256);
        assert_eq!(ENTRY_INLINE_MAX, 262144);
        assert_eq!(BLOCK_HEADER_LEN, 64);
        assert_eq!(&MAGIC_BLOCK, b"FTB1");
        assert_eq!(&MAGIC_MANIFEST, b"FTM1");
        assert_eq!(HEADER_VERSION, 1);
        assert_eq!(ALG_CLEARTEXT, 0);
        assert_eq!(ALG_AEAD, 1);
        assert_eq!(ALG_XCHACHA20_POLY1305, 1);
        assert_eq!(WRAP_ALG_XCHACHA20_POLY1305, 1);
        assert_eq!(CTX_CDC_GEAR, "filething.cdc.gear.v1");
        assert_eq!(CTX_BLOCK_KEY, "filething.block.key.v1");
        assert_eq!(CTX_BLOCK_NONCE, "filething.block.nonce.v1");
        assert_eq!(CTX_KEYWRAP, "filething.keywrap.v1");
        assert_eq!(CTX_MANIFEST_KEY, "filething.manifest.key.v1");
    }
}
