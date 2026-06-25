//! Per-Space secrets and the Vault meta blob (`docs/format.md §3`, `§4.4`,
//! `§6.2`).
//!
//! The FastCDC `chunk_secret` is per-Space and MUST be identical on every Device
//! of the Space — otherwise two Devices would cut the same bytes differently,
//! producing different `bk`/`manifestRoot` and phantom conflicts (`§3`). The MVP
//! scheme:
//!
//! 1. [`init_space`](crate::SpaceContext::init_space) generates a random 32-byte
//!    `chunk_secret`.
//! 2. It is serialized into a small CBOR **meta blob** ([`MetaBlob`]) and stored
//!    in the Vault under `meta/<aa>/<cid>` where `cid = ft_hash::cid_of(bytes)`.
//!    That `cid` is what `coordinator.create_space` records as `metaBlobCid`.
//! 3. The secret is persisted locally in `space_state.chunk_secret` (`§9`).
//!
//! Cloning a Space (reading the meta blob back) is Part 2's job; this module
//! exposes [`write_meta_blob`] / [`load_meta_blob`] so that path can reuse them.
//!
//! `dedup_secret` is unused in the cleartext MVP (`alg=0`, `cid == pcid`) — it is
//! left `None` in `space_state` (`§4.4`, `§9`).

use ft_core::Cid;
use ft_vault::Vault;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{EngineError, Result};

/// Current meta-blob format version.
pub const META_BLOB_VERSION: u8 = 1;

/// The Space metadata blob stored content-addressed in the Vault (`§6.2`).
///
/// In the cleartext MVP it carries only the FastCDC `chunk_secret` and a version
/// byte; under zero-knowledge it becomes an opaque/cipherable blob without a
/// schema change (`§5.5`). Serialized as CBOR; addressed by `ft_hash::cid_of` of
/// those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaBlob {
    /// Format version (`§6.2`).
    pub v: u8,
    /// The per-Space FastCDC chunk secret (32 bytes, `§3`). Emitted as a CBOR
    /// bytestring via `serde_bytes`.
    #[serde(with = "serde_bytes")]
    pub chunk_secret: Vec<u8>,
}

impl MetaBlob {
    /// Wraps a 32-byte chunk secret into a versioned [`MetaBlob`].
    pub fn new(chunk_secret: &[u8; 32]) -> Self {
        Self {
            v: META_BLOB_VERSION,
            chunk_secret: chunk_secret.to_vec(),
        }
    }

    /// Returns the chunk secret as a fixed `[u8; 32]`, erroring if the stored
    /// blob's secret is not exactly 32 bytes.
    pub fn chunk_secret_array(&self) -> Result<[u8; 32]> {
        self.chunk_secret.as_slice().try_into().map_err(|_| {
            EngineError::MetaBlob(format!(
                "chunk_secret must be 32 bytes, got {}",
                self.chunk_secret.len()
            ))
        })
    }
}

/// Generates a fresh random 32-byte chunk secret (`§3`).
pub fn generate_chunk_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

/// Serializes a [`MetaBlob`] for `chunk_secret` to canonical-enough CBOR (the
/// blob is addressed by its own bytes, so any deterministic encoding works) and
/// PUTs it to the Vault under `meta/<aa>/<cid>`, returning that `cid`.
///
/// Reusable by Part 2's clone path's twin (`load_meta_blob`).
pub async fn write_meta_blob(vault: &dyn Vault, chunk_secret: &[u8; 32]) -> Result<Cid> {
    let blob = MetaBlob::new(chunk_secret);
    let bytes = encode_meta_blob(&blob)?;
    let cid = ft_hash::cid_of(&bytes);
    vault.put(&meta_key(&cid), bytes).await?;
    Ok(cid)
}

/// Fetches and decodes the [`MetaBlob`] at `cid` from the Vault, returning the
/// 32-byte chunk secret. The read path used when cloning a Space onto a new
/// Device (Part 2), exposed here so both halves share one codec.
pub async fn load_meta_blob(vault: &dyn Vault, cid: &Cid) -> Result<[u8; 32]> {
    let bytes = vault.get(&meta_key(cid)).await?;
    let blob = decode_meta_blob(&bytes)?;
    blob.chunk_secret_array()
}

/// Vault key for the Space meta blob: `"meta/<aa>/<cid_hex>"` (`§6.1`-style
/// fan-out, mirroring `ft_hash::block_key` for the reserved `meta/` prefix).
pub fn meta_key(cid: &Cid) -> String {
    ft_hash::fanout_key("meta", &ft_hash::hex_lower(cid.as_bytes()))
}

fn encode_meta_blob(blob: &MetaBlob) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(blob, &mut buf).map_err(|e| EngineError::MetaBlob(e.to_string()))?;
    Ok(buf)
}

fn decode_meta_blob(bytes: &[u8]) -> Result<MetaBlob> {
    ciborium::de::from_reader(bytes).map_err(|e| EngineError::MetaBlob(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ft_vault::FsVault;

    #[test]
    fn meta_blob_roundtrips_through_cbor() {
        let secret = [0x5au8; 32];
        let blob = MetaBlob::new(&secret);
        let bytes = encode_meta_blob(&blob).unwrap();
        let back = decode_meta_blob(&bytes).unwrap();
        assert_eq!(back, blob);
        assert_eq!(back.chunk_secret_array().unwrap(), secret);
        assert_eq!(back.v, META_BLOB_VERSION);
    }

    #[test]
    fn meta_blob_cid_is_deterministic() {
        // The same secret must produce the same metaBlobCid on any Device, since
        // it is content-addressed (cid_of the bytes).
        let secret = [7u8; 32];
        let a = encode_meta_blob(&MetaBlob::new(&secret)).unwrap();
        let b = encode_meta_blob(&MetaBlob::new(&secret)).unwrap();
        assert_eq!(ft_hash::cid_of(&a), ft_hash::cid_of(&b));
    }

    #[test]
    fn chunk_secret_array_rejects_wrong_length() {
        let blob = MetaBlob {
            v: META_BLOB_VERSION,
            chunk_secret: vec![1, 2, 3],
        };
        assert!(matches!(
            blob.chunk_secret_array(),
            Err(EngineError::MetaBlob(_))
        ));
    }

    #[tokio::test]
    async fn write_then_load_meta_blob_roundtrips_via_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let secret = generate_chunk_secret();

        let cid = write_meta_blob(&vault, &secret).await.unwrap();
        // The object lives under meta/<aa>/<cid> and HEADs true.
        assert!(vault.head(&meta_key(&cid)).await.unwrap());

        let loaded = load_meta_blob(&vault, &cid).await.unwrap();
        assert_eq!(loaded, secret);
    }

    #[test]
    fn generate_chunk_secret_is_not_all_zero() {
        let s = generate_chunk_secret();
        assert!(s.iter().any(|&b| b != 0));
    }
}
