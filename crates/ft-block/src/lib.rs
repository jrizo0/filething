//! ft-block — codec for the content-addressed Block object (`docs/format.md`
//! §4.1–4.3; §4.5 reserved).
//!
//! A Block object is a fixed 64-byte header ([`ft_core::BlockHeader`]) followed
//! by its payload. This crate encodes/decodes that object, computes the
//! addressing [`Cid`], and verifies wire integrity by recomputing the hash and
//! comparing it against an expected `cid`.
//!
//! ## MVP: encryption OFF (`alg=0`)
//!
//! The single load-bearing decision (`docs/format.md §4.3`, resolved for this
//! build): in the MVP the `cid` is computed over the payload **without**
//! prepending the nonce, i.e.
//!
//! ```text
//! cid = ft_hash::cid_of(payload) = BLAKE3-256(payload)
//! ```
//!
//! so that `cid == pcid` (`§4.3`: "en MVP nonce=ceros => cid=pcid"). The entire
//! MVP dedup path depends on this equality. The header still carries 24 nonce
//! bytes — all zero, a reserved field — but those bytes do NOT enter the hash in
//! the MVP. Because the MVP nonce is all-zero, `BLAKE3(payload)` and
//! `BLAKE3(nonce_24 || payload)` would differ; this crate deliberately hashes
//! the payload alone, matching `ft_hash::cid_of` / `ft_hash::pcid_of`.
//!
//! ## Future: encryption ON (`alg=1`) — RESERVED, not implemented
//!
//! Under AEAD the payload is ciphertext and the addressing hash becomes
//! `cid = BLAKE3-256(nonce_24 || ciphertext)` (`§4.4`), with the wrapped data key
//! living in a `keys/<aa>/<cid>` sidecar (`§4.5`). Neither the `alg=1` branch nor
//! the sidecar is implemented here; [`cid_of_object`] returns
//! [`Error::UnsupportedAlg`] for any non-cleartext `alg` so the reserved branch
//! is explicit rather than silently mishashed.

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

    /// The AEAD branch (`alg=1`) is reserved and not implemented in the MVP.
    #[error("unsupported alg {0}: only cleartext (alg=0) is implemented in the MVP")]
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
/// MVP (`alg=0`): `cid = ft_hash::cid_of(payload) = BLAKE3-256(payload)`, so
/// `cid == pcid`. The nonce is NOT prepended in the MVP (`docs/format.md §4.3`).
pub fn cid_for(payload: &[u8]) -> Cid {
    ft_hash::cid_of(payload)
}

/// Decodes a Block object and computes the [`Cid`] of its stored payload
/// according to the header's `alg`.
///
/// - MVP (`alg=0`, [`ft_core::ALG_CLEARTEXT`]): hashes the payload alone
///   (`BLAKE3-256(payload)`), the nonce excluded — matching [`cid_for`].
/// - `alg=1` ([`ft_core::ALG_AEAD`]) and any other value: returns
///   [`Error::UnsupportedAlg`]. The future AEAD rule
///   (`cid = BLAKE3-256(nonce || ciphertext)`) is reserved, not implemented.
pub fn cid_of_object(obj: &[u8]) -> Result<Cid> {
    let (header, payload) = decode(obj)?;
    if header.alg != ft_core::ALG_CLEARTEXT {
        return Err(Error::UnsupportedAlg(header.alg));
    }
    Ok(cid_for(&payload))
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

    // ----- reserved alg=1 branch -----

    #[test]
    fn cid_of_object_rejects_alg1() {
        // Hand-build an otherwise-valid object whose header says alg=1.
        let payload = b"ciphertext-ish";
        let mut obj = encode(payload);
        obj[5] = ft_core::ALG_AEAD; // alg = 1.
        assert!(matches!(cid_of_object(&obj), Err(Error::UnsupportedAlg(1))));
    }

    #[test]
    fn verify_rejects_alg1_object() {
        let payload = b"ciphertext-ish";
        let mut obj = encode(payload);
        obj[5] = ft_core::ALG_AEAD;
        let cid = cid_for(payload);
        assert!(matches!(verify(&obj, &cid), Err(Error::UnsupportedAlg(1))));
    }
}
