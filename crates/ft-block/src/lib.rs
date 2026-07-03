//! ft-block — codec for the content-addressed Block object (`docs/format.md`
//! §4.1–4.5).
//!
//! A Block object is a fixed 64-byte header ([`ft_core::BlockHeader`]) followed
//! by its payload. This crate encodes/decodes that object, computes the
//! addressing [`Cid`], and verifies wire integrity by recomputing the hash and
//! comparing it against an expected `cid`. It also implements the `alg=1`
//! (XChaCha20-Poly1305) runtime encryption path and its `keys/<space_id>/<aa>/<cid>`
//! sidecar codec ([`sidecar`]).
//!
//! ## Cleartext (`alg=0`)
//!
//! The single load-bearing decision (`docs/format.md §4.3`): for cleartext the
//! `cid` is computed over the payload **without** prepending the nonce, i.e.
//!
//! ```text
//! cid = ft_hash::cid_of(payload) = BLAKE3-256(payload)
//! ```
//!
//! so that `cid == pcid` (`§4.3`: "en MVP nonce=ceros => cid=pcid"). The header
//! still carries 24 nonce bytes — all zero, a reserved field — but those bytes
//! do NOT enter the hash for `alg=0`.
//!
//! ## Encryption (`alg=1`, XChaCha20-Poly1305)
//!
//! [`encode_encrypted`] / [`decode_encrypted`] implement `docs/format.md §4.4`:
//! the data key and nonce are DETERMINISTIC per content (`ft_hash::data_key` /
//! `ft_hash::nonce`, derived from the per-Account dedup secret and the chunk's
//! `pcid`), so the same cleartext in the same Account always re-derives the same
//! key/nonce/ciphertext/`cid` — the property that makes cross-Device dedup
//! survive encryption. The addressing hash becomes
//!
//! ```text
//! cid = BLAKE3-256(nonce_24 || ciphertext)
//! ```
//!
//! and the 64-byte header is authenticated as the AEAD's associated data (AAD),
//! so the header is not maleable independently of the ciphertext (`§4.3`,
//! "regla DURA"). [`verify`] / [`cid_of_object`] recompute this hash straight
//! from the object's own bytes with NO key required — only [`decode_encrypted`]
//! (which actually recovers the cleartext) needs the `data_key`. The wrapped
//! data key itself never lives in the Block object; it lives in a
//! `keys/<space_id>/<aa>/<cid>` sidecar (`§4.5`), encoded/decoded by [`sidecar`].
//!
//! [`cid_of_object`] / [`verify`] return [`Error::UnsupportedAlg`] for any `alg`
//! other than `0` or `1` — a third algorithm is not a format this crate knows.

use ft_core::{BlockHeader, Cid, BLOCK_HEADER_LEN};
use thiserror::Error;

/// Errors produced while encoding, decoding or verifying a Block object.
#[derive(Debug, Error)]
pub enum Error {
    /// A header-level failure surfaced from [`ft_core`] (bad magic, short
    /// buffer, unsupported version, ...).
    #[error("block header error: {0}")]
    Header(#[from] ft_core::Error),

    /// The header parsed, but its magic was not [`ft_core::MAGIC_BLOCK`]. A Block
    /// object must carry `FTB1`; [`ft_core::BlockHeader::decode`] also accepts
    /// `FTM1` (a Manifest page), so this crate rejects the manifest magic here
    /// rather than mis-interpreting a `manifest/*` object as a Block.
    #[error("wrong object magic: expected {expected:02x?} (FTB1), got {got:02x?}")]
    WrongMagic {
        /// The magic a Block object must carry ([`ft_core::MAGIC_BLOCK`]).
        expected: [u8; 4],
        /// The magic actually found in the header.
        got: [u8; 4],
    },

    /// The object's declared `payload_len` did not match the bytes that
    /// actually followed the 64-byte header.
    #[error("payload length mismatch: header declares {declared} bytes, object carries {actual}")]
    PayloadLenMismatch {
        /// `payload_len` read from the header.
        declared: u64,
        /// Bytes actually present after the header.
        actual: u64,
    },

    /// The object's `alg` byte is neither [`ft_core::ALG_CLEARTEXT`] nor
    /// [`ft_core::ALG_XCHACHA20_POLY1305`] — not a format this crate knows.
    #[error("unsupported alg {0}: only cleartext (alg=0) and XChaCha20-Poly1305 (alg=1) are implemented")]
    UnsupportedAlg(u8),

    /// Integrity check failed: the recomputed `cid` did not equal the expected
    /// one (a corrupt or wrong object).
    #[error("cid mismatch: expected {expected}, computed {computed}")]
    CidMismatch {
        /// The `cid` the caller expected.
        expected: Cid,
        /// The `cid` recomputed from the object's bytes.
        computed: Cid,
    },

    /// A caller-supplied `alg`/`wrap_alg` did not match what an operation
    /// requires — e.g. [`decode_encrypted`] on an `alg=0` object, or
    /// [`sidecar::unwrap_data_key`] on a sidecar whose `wrap_alg` this crate
    /// does not implement.
    #[error("wrong alg: expected {expected}, got {got}")]
    WrongAlg {
        /// The `alg`/`wrap_alg` the operation requires.
        expected: u8,
        /// The `alg`/`wrap_alg` actually found.
        got: u8,
    },

    /// AEAD encryption failed. With the fixed 32-byte key / 24-byte nonce this
    /// crate always supplies, this should not happen in practice; surfaced as an
    /// error instead of panicking so a pathological input cannot crash a Device.
    #[error("AEAD encryption failed")]
    Encrypt,

    /// AEAD decryption/authentication failed: wrong `data_key` (or wrong
    /// `space_key` for a sidecar unwrap), or the ciphertext/AAD was tampered
    /// with. Deliberately does not distinguish which, per AEAD best practice.
    #[error("AEAD decryption failed: wrong key or tampered data")]
    Decrypt,

    /// A `keys/<space_id>/<aa>/<cid>` sidecar's CBOR payload failed to decode, or decoded
    /// to a `wrap_nonce`/`wrapped_data_key` of the wrong length.
    #[error("malformed sidecar: {0}")]
    MalformedSidecar(String),
}

/// Crate-wide `Result` alias over the block [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Encodes a cleartext Block object: the 64-byte header
/// ([`BlockHeader::new_block`] with `alg=0`, zero nonce and `payload_len` set to
/// `payload.len()`) immediately followed by `payload`.
///
/// The returned buffer is exactly `BLOCK_HEADER_LEN + payload.len()` bytes.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let header = BlockHeader::new_block(payload.len() as u64);
    let mut out = Vec::with_capacity(BLOCK_HEADER_LEN + payload.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
    out
}

/// Decodes a Block object into its header and an owned copy of its payload.
///
/// Validates the header via [`BlockHeader::decode`] (magic, version, length),
/// then requires the magic to be [`ft_core::MAGIC_BLOCK`] (`FTB1`), and finally
/// checks that the header's `payload_len` matches the number of bytes that
/// follow the 64-byte header. A truncated object — one whose trailing bytes are
/// shorter (or longer) than `payload_len` declares — is rejected with
/// [`Error::PayloadLenMismatch`].
///
/// `BlockHeader::decode` accepts both `FTB1` and `FTM1` (a Manifest page), so a
/// `manifest/*` object would otherwise be mis-decoded as a Block. This crate
/// rejects any non-Block magic with [`Error::WrongMagic`] so that only a true
/// `FTB1` object is treated as a Block. (Manifest pages are decoded by
/// `ft-manifest::decode_page`, not here.)
pub fn decode(obj: &[u8]) -> Result<(BlockHeader, Vec<u8>)> {
    let header = BlockHeader::decode(obj)?;
    if header.magic != ft_core::MAGIC_BLOCK {
        return Err(Error::WrongMagic {
            expected: ft_core::MAGIC_BLOCK,
            got: header.magic,
        });
    }
    // `decode` already guaranteed `obj.len() >= BLOCK_HEADER_LEN`.
    let payload = &obj[BLOCK_HEADER_LEN..];
    let actual = payload.len() as u64;
    if header.payload_len != actual {
        return Err(Error::PayloadLenMismatch {
            declared: header.payload_len,
            actual,
        });
    }
    Ok((header, payload.to_vec()))
}

/// Computes the addressing [`Cid`] for a cleartext `payload`.
///
/// `alg=0`: `cid = ft_hash::cid_of(payload) = BLAKE3-256(payload)`, so
/// `cid == pcid`. The nonce is NOT prepended for cleartext (`docs/format.md §4.3`).
pub fn cid_for(payload: &[u8]) -> Cid {
    ft_hash::cid_of(payload)
}

/// Computes the addressing [`Cid`] for an encrypted (`alg=1`) object's stored
/// ciphertext: `cid = BLAKE3-256(nonce || ciphertext)` (`docs/format.md §4.4`).
///
/// Needs no key: this is the wire-integrity hash, computable from the object's
/// own bytes alone (`§4.3`, "regla DURA").
pub fn cid_for_encrypted(nonce: &[u8; 24], ciphertext: &[u8]) -> Cid {
    let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(ciphertext);
    ft_hash::cid_of(&buf)
}

/// Decodes a Block object and computes the [`Cid`] of its stored payload
/// according to the header's `alg`.
///
/// - `alg=0` ([`ft_core::ALG_CLEARTEXT`]): hashes the payload alone
///   (`BLAKE3-256(payload)`), the nonce excluded — matching [`cid_for`].
/// - `alg=1` ([`ft_core::ALG_XCHACHA20_POLY1305`]): hashes `nonce || ciphertext`
///   — matching [`cid_for_encrypted`]. No key required.
/// - any other value: [`Error::UnsupportedAlg`].
pub fn cid_of_object(obj: &[u8]) -> Result<Cid> {
    let (header, payload) = decode(obj)?;
    match header.alg {
        ft_core::ALG_CLEARTEXT => Ok(cid_for(&payload)),
        ft_core::ALG_XCHACHA20_POLY1305 => Ok(cid_for_encrypted(&header.nonce, &payload)),
        other => Err(Error::UnsupportedAlg(other)),
    }
}

/// Recomputes the object's [`Cid`] (via [`cid_of_object`]) and compares it to
/// `expected`, returning [`Error::CidMismatch`] if they differ.
///
/// This is the wire-integrity check of `docs/format.md §4.3`: on download,
/// recompute the addressing hash from the object's own bytes and reject any
/// object that does not hash to the `cid` the Manifest referenced. A single
/// corrupted payload byte changes the BLAKE3 digest and is caught here.
pub fn verify(obj: &[u8], expected: &Cid) -> Result<()> {
    let computed = cid_of_object(obj)?;
    if &computed != expected {
        return Err(Error::CidMismatch {
            expected: *expected,
            computed,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encryption (alg=1, XChaCha20-Poly1305) — docs/format.md §4.4
// ---------------------------------------------------------------------------

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

/// Encrypts `payload` into a full encrypted (`alg=1`) Block object.
///
/// Implements `docs/format.md §4.4`: `pcid = pcid_of(payload)`; `data_key` and
/// `nonce` are DETERMINISTIC, derived from `dedup_secret` and `pcid`
/// (`ft_hash::data_key` / `ft_hash::nonce`) so the same cleartext in the same
/// Account always re-derives the same key/nonce — the property dedup relies on.
/// The 64-byte header (with `payload_len` set to the ciphertext length,
/// including the 16-byte Poly1305 tag) is authenticated as the AEAD's
/// associated data, then `cid = cid_for_encrypted(nonce, ciphertext)`.
///
/// Returns `(cid, pcid, object_bytes, data_key)`. The caller is responsible for
/// wrapping `data_key` into a `keys/<space_id>/<aa>/<cid>` sidecar ([`sidecar::wrap_data_key`])
/// before/alongside uploading `object_bytes` — this function does not touch the
/// sidecar.
pub fn encode_encrypted(
    payload: &[u8],
    dedup_secret: &[u8; 32],
) -> Result<(Cid, ft_core::Pcid, Vec<u8>, [u8; 32])> {
    let pcid = ft_hash::pcid_of(payload);
    let data_key = ft_hash::data_key(dedup_secret, &pcid);
    let nonce_bytes = ft_hash::nonce(dedup_secret, &pcid);

    // payload_len is the CIPHERTEXT length (plaintext + 16-byte Poly1305 tag),
    // known up-front so the header — the AEAD's AAD — can be built before
    // encrypting (docs/format.md §4.3 table, "futuro (alg=1)" column).
    let ciphertext_len = payload.len() as u64 + 16;
    let header = BlockHeader::new_encrypted_block(ciphertext_len, nonce_bytes);
    let aad = header.encode();

    let cipher = XChaCha20Poly1305::new(&Key::from(data_key));
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Encrypt)?;

    let cid = cid_for_encrypted(&nonce_bytes, &ciphertext);

    let mut obj = Vec::with_capacity(BLOCK_HEADER_LEN + ciphertext.len());
    obj.extend_from_slice(&aad);
    obj.extend_from_slice(&ciphertext);

    Ok((cid, pcid, obj, data_key))
}

/// Decrypts an encrypted (`alg=1`) Block object back to its cleartext payload.
///
/// Decodes the object ([`decode`]), requires `header.alg ==
/// `[`ft_core::ALG_XCHACHA20_POLY1305`], re-authenticates the 64-byte header as
/// AAD, and decrypts the ciphertext with `data_key` and the header's own nonce.
/// A wrong `data_key`, a tampered ciphertext, or a tampered header (AAD) all
/// surface as [`Error::Decrypt`] (AEAD does not distinguish these — that is the
/// point: it authenticates the header without revealing which part failed).
///
/// The caller obtains `data_key` by unwrapping the object's `keys/<space_id>/<aa>/<cid>`
/// sidecar ([`sidecar::unwrap_data_key`]) with the Space key.
pub fn decode_encrypted(obj: &[u8], data_key: &[u8; 32]) -> Result<Vec<u8>> {
    let (header, ciphertext) = decode(obj)?;
    if header.alg != ft_core::ALG_XCHACHA20_POLY1305 {
        return Err(Error::WrongAlg {
            expected: ft_core::ALG_XCHACHA20_POLY1305,
            got: header.alg,
        });
    }
    let aad = header.encode();
    let cipher = XChaCha20Poly1305::new(&Key::from(*data_key));
    cipher
        .decrypt(
            &XNonce::from(header.nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

// ---------------------------------------------------------------------------
// Sidecar: wrapped data key (docs/format.md §4.5)
// ---------------------------------------------------------------------------

/// Codec for the `keys/<space_id>/<aa>/<cid>` sidecar: the Block's data key, wrapped with
/// the Space key so rotating the Space key re-wraps (~88-byte objects) without
/// touching the (immutable) Block object or its `cid` (`docs/format.md §4.5`,
/// ADR-0004).
///
/// Wire format: canonical CBOR `{ wrap_alg, wrap_nonce (24B), wrapped_data_key
/// (48B = 32B ciphertext + 16B Poly1305 tag) }`. The struct fields below are
/// declared in that exact order and their CBOR key lengths are already strictly
/// ascending (`wrap_alg`=8, `wrap_nonce`=10, `wrapped_data_key`=16 chars), so
/// plain (declaration-order) `ciborium` struct serialization already satisfies
/// RFC 8949 §4.2.1's canonical map-key order for this type — no explicit
/// reordering pass is needed (contrast `ft-manifest`, whose page structs are NOT
/// naturally in that order and do need one).
pub mod sidecar {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
    use rand::RngCore;
    use serde::{Deserialize, Serialize};

    use crate::{Error, Result};

    /// The sidecar's `wrap_alg` value this crate produces and accepts:
    /// [`ft_core::WRAP_ALG_XCHACHA20_POLY1305`].
    pub const WRAP_ALG: u8 = ft_core::WRAP_ALG_XCHACHA20_POLY1305;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct SidecarWire {
        wrap_alg: u8,
        #[serde(with = "serde_bytes")]
        wrap_nonce: Vec<u8>,
        #[serde(with = "serde_bytes")]
        wrapped_data_key: Vec<u8>,
    }

    /// Derives the wrap subkey from the Space key: `BLAKE3.derive_key
    /// ("filething.keywrap.v1", space_key)` (`docs/format.md §2.1`). The Space
    /// key itself is never used directly as the AEAD key — the KDF subkey is —
    /// so wrap keys never collide with any other use of the Space key.
    fn derive_wrap_key(space_key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(ft_core::CTX_KEYWRAP);
        hasher.update(space_key);
        *hasher.finalize().as_bytes()
    }

    /// Wraps `data_key` with `space_key` (via the derived wrap subkey) into the
    /// canonical CBOR sidecar payload described at the module level. Uses a
    /// fresh random 24-byte nonce every call (wraps are not required to be
    /// deterministic — only the underlying `data_key`, per `§4.4`, is).
    pub fn wrap_data_key(data_key: &[u8; 32], space_key: &[u8; 32]) -> Vec<u8> {
        let kek = derive_wrap_key(space_key);
        let mut nonce_bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = XChaCha20Poly1305::new(&Key::from(kek));
        let wrapped_data_key = cipher
            .encrypt(&XNonce::from(nonce_bytes), data_key.as_slice())
            .expect(
                "wrapping a fixed 32-byte key with a valid 32-byte key/24-byte nonce cannot fail",
            );

        let wire = SidecarWire {
            wrap_alg: WRAP_ALG,
            wrap_nonce: nonce_bytes.to_vec(),
            wrapped_data_key,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&wire, &mut buf)
            .expect("serializing the fixed-shape sidecar struct to CBOR cannot fail");
        buf
    }

    /// Unwraps a `keys/<space_id>/<aa>/<cid>` sidecar's `data_key` using `space_key`.
    ///
    /// Rejects a `wrap_alg` other than [`WRAP_ALG`], a malformed CBOR payload, or
    /// a `wrap_nonce`/`wrapped_data_key` of the wrong length before touching the
    /// AEAD. A wrong `space_key` (hence wrong derived KEK) surfaces as
    /// [`Error::Decrypt`], same as a tampered sidecar — AEAD does not
    /// distinguish the two.
    pub fn unwrap_data_key(sidecar_bytes: &[u8], space_key: &[u8; 32]) -> Result<[u8; 32]> {
        let wire: SidecarWire = ciborium::de::from_reader(sidecar_bytes)
            .map_err(|e| Error::MalformedSidecar(e.to_string()))?;

        if wire.wrap_alg != WRAP_ALG {
            return Err(Error::WrongAlg {
                expected: WRAP_ALG,
                got: wire.wrap_alg,
            });
        }
        if wire.wrap_nonce.len() != 24 {
            return Err(Error::MalformedSidecar(format!(
                "wrap_nonce must be 24 bytes, got {}",
                wire.wrap_nonce.len()
            )));
        }
        if wire.wrapped_data_key.len() != 48 {
            return Err(Error::MalformedSidecar(format!(
                "wrapped_data_key must be 48 bytes, got {}",
                wire.wrapped_data_key.len()
            )));
        }
        // Lengths just checked above, so these conversions cannot fail.
        let nonce_arr: [u8; 24] = wire.wrap_nonce.as_slice().try_into().unwrap();

        let kek = derive_wrap_key(space_key);
        let cipher = XChaCha20Poly1305::new(&Key::from(kek));
        let plaintext = cipher
            .decrypt(&XNonce::from(nonce_arr), wire.wrapped_data_key.as_slice())
            .map_err(|_| Error::Decrypt)?;

        plaintext.as_slice().try_into().map_err(|_| {
            Error::MalformedSidecar(format!(
                "unwrapped data key must be 32 bytes, got {}",
                plaintext.len()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ft_core::{ALG_CLEARTEXT, MAGIC_BLOCK};

    // ----- encode / decode roundtrip -----

    #[test]
    fn encode_decode_roundtrip() {
        let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
        let obj = encode(&payload);
        let (header, decoded) = decode(&obj).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(header.payload_len, payload.len() as u64);
        assert_eq!(header.magic, MAGIC_BLOCK);
        assert_eq!(header.alg, ALG_CLEARTEXT);
    }

    #[test]
    fn encode_decode_roundtrip_empty_payload() {
        let obj = encode(b"");
        assert_eq!(obj.len(), BLOCK_HEADER_LEN);
        let (header, decoded) = decode(&obj).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(header.payload_len, 0);
    }

    #[test]
    fn encoded_object_length_is_header_plus_payload() {
        let payload = vec![0xAB; 1000];
        let obj = encode(&payload);
        assert_eq!(obj.len(), BLOCK_HEADER_LEN + payload.len());
    }

    // ----- header well-formed (magic FTB1, alg=0, payload_len LE) -----

    #[test]
    fn encoded_header_is_well_formed() {
        let payload = vec![1u8; 0x0102]; // 258 bytes -> low byte 0x02, next 0x01.
        let obj = encode(&payload);

        // magic "FTB1".
        assert_eq!(&obj[0..4], b"FTB1");
        assert_eq!(&obj[0..4], &MAGIC_BLOCK);
        // header_version = 1.
        assert_eq!(obj[4], 1);
        // alg = 0 (cleartext).
        assert_eq!(obj[5], ALG_CLEARTEXT);
        assert_eq!(obj[5], 0);
        // flags + reserved byte = 0.
        assert_eq!(obj[6], 0);
        assert_eq!(obj[7], 0);
        // payload_len u64 LE at offset 8.
        assert_eq!(obj[8], 0x02);
        assert_eq!(obj[9], 0x01);
        assert_eq!(&obj[10..16], &[0u8; 6]);
        // nonce (offset 16..40) is 24 zero bytes in the MVP (reserved field).
        assert_eq!(&obj[16..40], &[0u8; 24]);
        // reserved2 (offset 40..64) is 24 zero bytes.
        assert_eq!(&obj[40..64], &[0u8; 24]);
    }

    // ----- MVP: cid == pcid (nonce excluded from the hash) -----

    #[test]
    fn cid_for_equals_pcid_of_in_mvp() {
        // Load-bearing MVP invariant (§4.3): cid_for(payload) hashes the payload
        // alone, so it equals pcid_of(payload). cid == pcid.
        let payload = b"some chunk bytes for the mvp dedup path";
        assert_eq!(
            cid_for(payload).as_bytes(),
            ft_hash::pcid_of(payload).as_bytes()
        );
    }

    #[test]
    fn cid_for_equals_blake3_of_payload_not_nonce_prefixed() {
        // Explicitly: the MVP cid is BLAKE3(payload), NOT BLAKE3(nonce_24 ||
        // payload). With a non-empty zero nonce the two would differ.
        let payload = b"payload";
        let plain = ft_hash::cid_of(payload);
        let mut nonce_prefixed = [0u8; 24].to_vec();
        nonce_prefixed.extend_from_slice(payload);
        let prefixed = ft_hash::cid_of(&nonce_prefixed);
        assert_eq!(cid_for(payload), plain);
        assert_ne!(cid_for(payload), prefixed);
    }

    #[test]
    fn cid_of_object_matches_cid_for_payload() {
        let payload = b"hash the stored payload, nonce excluded in mvp";
        let obj = encode(payload);
        assert_eq!(cid_of_object(&obj).unwrap(), cid_for(payload));
    }

    // ----- verify: success and single-byte corruption detection -----

    #[test]
    fn verify_accepts_a_well_formed_object() {
        let payload = b"verify me";
        let obj = encode(payload);
        let cid = cid_for(payload);
        assert!(verify(&obj, &cid).is_ok());
    }

    #[test]
    fn verify_detects_single_byte_payload_corruption() {
        let payload = vec![0u8; 4096];
        let mut obj = encode(&payload);
        let cid = cid_for(&payload);
        // Flip one bit in the middle of the payload region.
        let mid = BLOCK_HEADER_LEN + payload.len() / 2;
        obj[mid] ^= 0x01;
        match verify(&obj, &cid) {
            Err(Error::CidMismatch { expected, computed }) => {
                assert_eq!(expected, cid);
                assert_ne!(computed, cid);
            }
            other => panic!("expected CidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_wrong_expected_cid() {
        let obj = encode(b"abc");
        let wrong = Cid::new([0xFFu8; 32]);
        assert!(matches!(
            verify(&obj, &wrong),
            Err(Error::CidMismatch { .. })
        ));
    }

    // ----- decode rejects malformed / truncated objects -----

    #[test]
    fn decode_rejects_truncated_object_shorter_than_declared() {
        // Build a valid object, then chop off the last payload byte: the header
        // still declares the old payload_len, so decode must reject it.
        let payload = b"0123456789".to_vec();
        let mut obj = encode(&payload);
        obj.pop(); // drop one payload byte; header.payload_len stays at 10.
        match decode(&obj) {
            Err(Error::PayloadLenMismatch { declared, actual }) => {
                assert_eq!(declared, 10);
                assert_eq!(actual, 9);
            }
            other => panic!("expected PayloadLenMismatch, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_object_with_extra_trailing_bytes() {
        let mut obj = encode(b"abc");
        obj.push(0xFF); // header declares 3 payload bytes, object carries 4.
        assert!(matches!(
            decode(&obj),
            Err(Error::PayloadLenMismatch {
                declared: 3,
                actual: 4
            })
        ));
    }

    #[test]
    fn decode_rejects_buffer_shorter_than_header() {
        let short = vec![0u8; BLOCK_HEADER_LEN - 1];
        // Surfaces as a header error from ft-core (HeaderTooShort).
        assert!(matches!(decode(&short), Err(Error::Header(_))));
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut obj = encode(b"x");
        obj[0] = b'Z';
        assert!(matches!(decode(&obj), Err(Error::Header(_))));
    }

    // ----- Block decode must reject a Manifest-page (FTM1) object -----
    //
    // `ft_core::BlockHeader::decode` accepts BOTH `FTB1` and `FTM1` magics, so a
    // manifest page would otherwise be silently interpreted as a Block. A Block
    // object must require `MAGIC_BLOCK`; an FTM1 object has to be rejected.

    /// Builds an object with an FTM1 (manifest-page) header followed by
    /// `payload`. Valid as a manifest page, but NOT a Block object.
    fn encode_manifest_like(payload: &[u8]) -> Vec<u8> {
        let header = BlockHeader::new_manifest(payload.len() as u64);
        let mut out = Vec::with_capacity(BLOCK_HEADER_LEN + payload.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn decode_rejects_manifest_magic() {
        let payload = b"manifest page payload, not a block";
        let obj = encode_manifest_like(payload);
        match decode(&obj) {
            Err(Error::WrongMagic { expected, got }) => {
                assert_eq!(expected, MAGIC_BLOCK);
                assert_eq!(got, ft_core::MAGIC_MANIFEST);
            }
            other => panic!("expected WrongMagic, got {other:?}"),
        }
    }

    #[test]
    fn cid_of_object_rejects_manifest_magic() {
        let obj = encode_manifest_like(b"manifest payload");
        assert!(matches!(cid_of_object(&obj), Err(Error::WrongMagic { .. })));
    }

    #[test]
    fn verify_rejects_manifest_magic() {
        let payload = b"manifest payload";
        let obj = encode_manifest_like(payload);
        // Even with the "right" cid for the payload, an FTM1 object is not a
        // Block and must be rejected on magic, never reaching the cid check.
        let cid = cid_for(payload);
        assert!(matches!(verify(&obj, &cid), Err(Error::WrongMagic { .. })));
    }

    #[test]
    fn decode_still_accepts_valid_block_magic() {
        // The fix must not regress the happy path: a genuine FTB1 object still
        // decodes/verifies cleanly.
        let payload = b"a genuine block payload";
        let obj = encode(payload);
        let (header, decoded) = decode(&obj).unwrap();
        assert_eq!(header.magic, MAGIC_BLOCK);
        assert_eq!(decoded, payload.to_vec());
        assert!(verify(&obj, &cid_for(payload)).is_ok());
    }

    // ----- unsupported alg (neither 0 nor 1) -----

    #[test]
    fn cid_of_object_rejects_unknown_alg() {
        let payload = b"mystery bytes";
        let mut obj = encode(payload);
        obj[5] = 7; // not a known alg.
        assert!(matches!(cid_of_object(&obj), Err(Error::UnsupportedAlg(7))));
    }

    #[test]
    fn verify_rejects_unknown_alg_object() {
        let payload = b"mystery bytes";
        let mut obj = encode(payload);
        obj[5] = 7;
        let cid = cid_for(payload);
        assert!(matches!(verify(&obj, &cid), Err(Error::UnsupportedAlg(7))));
    }

    // ===== alg=1 (XChaCha20-Poly1305) =====

    const DEDUP_SECRET_A: [u8; 32] = [0x11u8; 32];
    const DEDUP_SECRET_B: [u8; 32] = [0x22u8; 32];
    const SPACE_KEY_A: [u8; 32] = [0xAAu8; 32];
    const SPACE_KEY_B: [u8; 32] = [0xBBu8; 32];

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let payload = b"the quick brown fox jumps over the lazy dog, encrypted this time";
        let (cid, pcid, obj, data_key) = encode_encrypted(payload, &DEDUP_SECRET_A).unwrap();

        assert_eq!(pcid, ft_hash::pcid_of(payload));
        assert!(verify(&obj, &cid).is_ok());

        let decrypted = decode_encrypted(&obj, &data_key).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn encrypted_header_is_well_formed() {
        let payload = b"header shape check";
        let (_, _, obj, _) = encode_encrypted(payload, &DEDUP_SECRET_A).unwrap();
        let header = BlockHeader::decode(&obj).unwrap();
        assert_eq!(header.magic, MAGIC_BLOCK);
        assert_eq!(header.alg, ft_core::ALG_XCHACHA20_POLY1305);
        assert_eq!(header.alg, 1);
        assert_eq!(header.payload_len, payload.len() as u64 + 16); // + Poly1305 tag.
        assert_ne!(
            header.nonce, [0u8; 24],
            "alg=1 nonce must not be the MVP zero nonce"
        );
        assert_eq!(obj.len(), BLOCK_HEADER_LEN + payload.len() + 16);
    }

    #[test]
    fn encrypted_cid_equals_blake3_of_nonce_then_ciphertext() {
        // Locks §4.4's cid formula against the implementation, not just against
        // itself: recompute independently from the object's raw bytes.
        let payload = b"cid formula check";
        let (cid, _, obj, _) = encode_encrypted(payload, &DEDUP_SECRET_A).unwrap();
        let header = BlockHeader::decode(&obj).unwrap();
        let ciphertext = &obj[BLOCK_HEADER_LEN..];
        let mut hashed = header.nonce.to_vec();
        hashed.extend_from_slice(ciphertext);
        assert_eq!(cid, ft_hash::cid_of(&hashed));
        assert_eq!(cid, cid_for_encrypted(&header.nonce, ciphertext));
    }

    #[test]
    fn encrypt_dedup_determinism_same_secret_same_payload() {
        // §4.4: same cleartext + same dedup_secret -> same cid AND same stored
        // bytes (mismo ciphertext), on any Device / any call.
        let payload = b"dedup me twice";
        let (cid1, pcid1, obj1, key1) = encode_encrypted(payload, &DEDUP_SECRET_A).unwrap();
        let (cid2, pcid2, obj2, key2) = encode_encrypted(payload, &DEDUP_SECRET_A).unwrap();
        assert_eq!(cid1, cid2);
        assert_eq!(pcid1, pcid2);
        assert_eq!(obj1, obj2);
        assert_eq!(key1, key2);
    }

    #[test]
    fn encrypt_different_dedup_secret_yields_different_cid() {
        // §4.4: different Account (different dedup_secret) -> different cid for
        // the SAME cleartext -> no cross-account dedup, no convergent encryption.
        let payload = b"same cleartext, different account";
        let (cid_a, _, obj_a, key_a) = encode_encrypted(payload, &DEDUP_SECRET_A).unwrap();
        let (cid_b, _, obj_b, key_b) = encode_encrypted(payload, &DEDUP_SECRET_B).unwrap();
        assert_ne!(cid_a, cid_b);
        assert_ne!(obj_a, obj_b);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn alg0_path_is_unaffected_by_alg1_support() {
        // Regression guard: adding alg=1 must not perturb the alg=0 MVP path.
        let payload = b"still plain cleartext";
        let obj = encode(payload);
        let (header, decoded) = decode(&obj).unwrap();
        assert_eq!(header.alg, ft_core::ALG_CLEARTEXT);
        assert_eq!(decoded, payload);
        assert_eq!(
            cid_for(payload).as_bytes(),
            ft_hash::pcid_of(payload).as_bytes()
        );
        assert!(verify(&obj, &cid_for(payload)).is_ok());
    }

    #[test]
    fn decrypt_fails_on_ciphertext_tamper() {
        let payload = b"tamper the ciphertext";
        let (cid, _, mut obj, data_key) = encode_encrypted(payload, &DEDUP_SECRET_A).unwrap();
        // verify() (no key needed) must still catch this via the cid mismatch.
        let last = obj.len() - 1;
        obj[last] ^= 0x01;
        assert!(matches!(verify(&obj, &cid), Err(Error::CidMismatch { .. })));
        // And decode_encrypted (which authenticates via AEAD) must also reject it.
        assert!(matches!(
            decode_encrypted(&obj, &data_key),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn decrypt_fails_on_header_aad_tamper() {
        // Flipping a header byte (the AAD) must not change payload_len/nonce in
        // a way that breaks framing, but MUST break AEAD authentication.
        let payload = b"tamper the header aad";
        let (_, _, mut obj, data_key) = encode_encrypted(payload, &DEDUP_SECRET_A).unwrap();
        obj[6] ^= 0x01; // flags byte, part of the header/AAD.
        assert!(matches!(
            decode_encrypted(&obj, &data_key),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn decrypt_fails_with_wrong_data_key() {
        let payload = b"wrong key must fail";
        let (_, _, obj, _) = encode_encrypted(payload, &DEDUP_SECRET_A).unwrap();
        let wrong_key = [0x99u8; 32];
        assert!(matches!(
            decode_encrypted(&obj, &wrong_key),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn decode_encrypted_rejects_alg0_object() {
        let obj = encode(b"cleartext, not encrypted");
        let some_key = [0x01u8; 32];
        match decode_encrypted(&obj, &some_key) {
            Err(Error::WrongAlg { expected, got }) => {
                assert_eq!(expected, ft_core::ALG_XCHACHA20_POLY1305);
                assert_eq!(got, ft_core::ALG_CLEARTEXT);
            }
            other => panic!("expected WrongAlg, got {other:?}"),
        }
    }

    #[test]
    fn encrypt_roundtrip_empty_payload() {
        let (cid, pcid, obj, data_key) = encode_encrypted(b"", &DEDUP_SECRET_A).unwrap();
        assert_eq!(obj.len(), BLOCK_HEADER_LEN + 16); // just the Poly1305 tag.
        assert!(verify(&obj, &cid).is_ok());
        assert_eq!(decode_encrypted(&obj, &data_key).unwrap(), b"");
        assert_eq!(pcid, ft_hash::pcid_of(b""));
    }

    // ----- sidecar: wrap / unwrap the data key -----

    #[test]
    fn sidecar_wrap_unwrap_roundtrip() {
        let data_key = [0x77u8; 32];
        let wrapped = sidecar::wrap_data_key(&data_key, &SPACE_KEY_A);
        let unwrapped = sidecar::unwrap_data_key(&wrapped, &SPACE_KEY_A).unwrap();
        assert_eq!(unwrapped, data_key);
    }

    #[test]
    fn sidecar_unwrap_fails_with_wrong_space_key() {
        let data_key = [0x77u8; 32];
        let wrapped = sidecar::wrap_data_key(&data_key, &SPACE_KEY_A);
        assert!(matches!(
            sidecar::unwrap_data_key(&wrapped, &SPACE_KEY_B),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn sidecar_wrap_uses_fresh_nonce_each_call() {
        // Not deterministic by design (only the underlying data_key is, per
        // §4.4); two wraps of the same data_key must differ (fresh random nonce)
        // yet both must unwrap back to the same data_key.
        let data_key = [0x77u8; 32];
        let wrapped1 = sidecar::wrap_data_key(&data_key, &SPACE_KEY_A);
        let wrapped2 = sidecar::wrap_data_key(&data_key, &SPACE_KEY_A);
        assert_ne!(wrapped1, wrapped2);
        assert_eq!(
            sidecar::unwrap_data_key(&wrapped1, &SPACE_KEY_A).unwrap(),
            data_key
        );
        assert_eq!(
            sidecar::unwrap_data_key(&wrapped2, &SPACE_KEY_A).unwrap(),
            data_key
        );
    }

    #[test]
    fn sidecar_is_exact_canonical_cbor_shape() {
        // §4.5: canonical CBOR { wrap_alg, wrap_nonce(24B), wrapped_data_key(48B) }.
        let data_key = [0x01u8; 32];
        let wrapped = sidecar::wrap_data_key(&data_key, &SPACE_KEY_A);

        let value: ciborium::value::Value = ciborium::de::from_reader(&wrapped[..]).unwrap();
        let map = value.as_map().expect("sidecar is a CBOR map");

        // Declaration order == canonical order (see module doc on `sidecar`).
        let keys: Vec<&str> = map.iter().map(|(k, _)| k.as_text().unwrap()).collect();
        assert_eq!(keys, vec!["wrap_alg", "wrap_nonce", "wrapped_data_key"]);

        let get = |name: &str| -> ciborium::value::Value {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(get("wrap_alg").as_integer().unwrap(), 1.into());
        assert_eq!(get("wrap_nonce").as_bytes().unwrap().len(), 24);
        assert_eq!(get("wrapped_data_key").as_bytes().unwrap().len(), 48);
    }

    #[test]
    fn sidecar_unwrap_rejects_unknown_wrap_alg() {
        // Hand-build a sidecar with wrap_alg = 9 (not implemented).
        #[derive(serde::Serialize)]
        struct BadSidecar {
            wrap_alg: u8,
            #[serde(with = "serde_bytes")]
            wrap_nonce: Vec<u8>,
            #[serde(with = "serde_bytes")]
            wrapped_data_key: Vec<u8>,
        }
        let bad = BadSidecar {
            wrap_alg: 9,
            wrap_nonce: vec![0u8; 24],
            wrapped_data_key: vec![0u8; 48],
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&bad, &mut buf).unwrap();

        match sidecar::unwrap_data_key(&buf, &SPACE_KEY_A) {
            Err(Error::WrongAlg { expected, got }) => {
                assert_eq!(expected, sidecar::WRAP_ALG);
                assert_eq!(got, 9);
            }
            other => panic!("expected WrongAlg, got {other:?}"),
        }
    }

    #[test]
    fn sidecar_unwrap_rejects_malformed_cbor() {
        assert!(matches!(
            sidecar::unwrap_data_key(b"not cbor at all \xff\xff", &SPACE_KEY_A),
            Err(Error::MalformedSidecar(_))
        ));
    }

    #[test]
    fn sidecar_unwrap_rejects_wrong_length_fields() {
        #[derive(serde::Serialize)]
        struct BadSidecar {
            wrap_alg: u8,
            #[serde(with = "serde_bytes")]
            wrap_nonce: Vec<u8>,
            #[serde(with = "serde_bytes")]
            wrapped_data_key: Vec<u8>,
        }
        let bad = BadSidecar {
            wrap_alg: sidecar::WRAP_ALG,
            wrap_nonce: vec![0u8; 12], // wrong: must be 24.
            wrapped_data_key: vec![0u8; 48],
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&bad, &mut buf).unwrap();
        assert!(matches!(
            sidecar::unwrap_data_key(&buf, &SPACE_KEY_A),
            Err(Error::MalformedSidecar(_))
        ));
    }
}
