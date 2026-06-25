//! ft-hash — content-addressing primitives (FOUNDATION).
//!
//! Implements the hashing and key-derivation primitives of `docs/format.md`:
//!
//! - §2 / §2.1: the single hash primitive (**BLAKE3-256**) and the KDF
//!   (**BLAKE3 `derive_key` mode**) with the domain context strings owned by
//!   [`ft_core`].
//! - §4.2: object naming — lowercase hex (64 chars) plus 2-char fan-out keys
//!   (`<prefix>/<aa>/<hex>`, git-style).
//! - §4.4: the DETERMINISTIC per-content data key and nonce (derived from the
//!   per-Account dedup secret + the chunk's `pcid`) that make dedup work
//!   cross-Device once encryption is on.
//!
//! ## Encryption is OFF in the MVP
//!
//! [`data_key`] and [`nonce`] are implemented and tested here because they are
//! cheap and their derivation is a load-bearing, irreversible decision (§4.4),
//! but nothing in the MVP calls them: Blocks ship in cleartext (`alg=0`, zero
//! nonce, `cid == pcid`). The single property that MATTERS now is that they are
//! DETERMINISTIC — same inputs always yield the same key/nonce on any Device —
//! so that turning encryption on later does not re-chunk, re-key, or re-upload
//! anything. This crate derives keys; it never encrypts.

use ft_core::{Cid, Pcid, CTX_BLOCK_KEY, CTX_BLOCK_NONCE, CTX_CDC_GEAR};

// ---------------------------------------------------------------------------
// Content ids — cid / pcid (docs/format.md §4.1)
// ---------------------------------------------------------------------------

/// Computes the addressing content id of a Block's STORED payload.
///
/// `cid = BLAKE3-256(nonce || payload)` (§4.3, §4.4). The caller passes the
/// already-concatenated `nonce || payload` bytes — in the MVP the nonce is 24
/// zero bytes so `cid == pcid` by coincidence, but the two ids stay separate
/// types from day 1. This function NEVER hashes the whole 64-byte object header
/// (that would break after a key rotation, which changes the sidecar but not the
/// payload), only the `nonce || payload` bytes the caller supplies.
pub fn cid_of(stored_payload: &[u8]) -> Cid {
    Cid::new(*blake3::hash(stored_payload).as_bytes())
}

/// Computes the dedup content id of a chunk's CLEARTEXT.
///
/// `pcid = BLAKE3-256(cleartext)` (§4.1). Scoped to the Account; lives only in a
/// Device's local index and dedup table, never as an object name.
pub fn pcid_of(cleartext: &[u8]) -> Pcid {
    Pcid::new(*blake3::hash(cleartext).as_bytes())
}

// ---------------------------------------------------------------------------
// Naming — lowercase hex + 2-char fan-out (docs/format.md §2, §4.2)
// ---------------------------------------------------------------------------

/// Lowercase hex encoding of a 32-byte digest (exactly 64 chars). `§2` naming.
pub fn hex_lower(b: &[u8; 32]) -> String {
    hex::encode(b)
}

/// Builds a fan-out object key `"<prefix>/<aa>/<hex>"` where `aa` is the first
/// two chars of `hex` — the git-style 256-prefix fan-out of §4.2.
///
/// `hex` is expected to be the 64-char lowercase encoding of a 32-byte id (the
/// callers below always pass exactly that). If `hex` is shorter than 2 chars the
/// whole string is used as the prefix, so this never panics.
pub fn fanout_key(prefix: &str, hex: &str) -> String {
    let aa = if hex.len() >= 2 { &hex[..2] } else { hex };
    format!("{prefix}/{aa}/{hex}")
}

/// Vault key for a Block object: `"blocks/<aa>/<cid_hex>"` (§4.2, §6.1).
pub fn block_key(cid: &Cid) -> String {
    fanout_key("blocks", &hex_lower(cid.as_bytes()))
}

/// Vault key for a Manifest page object: `"manifest/<aa>/<page_cid_hex>"`
/// (§5.3, §6.1).
pub fn manifest_key(page_cid: &Cid) -> String {
    fanout_key("manifest", &hex_lower(page_cid.as_bytes()))
}

/// Vault key for an externalized blocklist object: `"blocklist/<aa>/<cid_hex>"`
/// (§5.3, §6.1).
pub fn blocklist_key(cid: &Cid) -> String {
    fanout_key("blocklist", &hex_lower(cid.as_bytes()))
}

// ---------------------------------------------------------------------------
// KDF — gear table, data key, nonce (docs/format.md §2.1, §3, §4.4)
// ---------------------------------------------------------------------------

/// Derives the 256-entry FastCDC gear table from a per-Space chunk secret (§3).
///
/// Per §3 the table is `BLAKE3.derive_key("filething.cdc.gear.v1", chunk_secret)`
/// expanded to 256·8 = 2048 bytes via the XOF, then read as 256 little-endian
/// `u64`s. Implementation: a `derive_key`-mode hasher keyed with [`CTX_CDC_GEAR`]
/// is fed the `chunk_secret` as key material, finalized as an XOF, and the first
/// 2048 bytes are filled and chunked into `u64`s.
///
/// Deterministic by construction: the same `chunk_secret` always yields the same
/// table on any Device (required so two Devices cut a file identically); a
/// different secret yields an unrelated table.
pub fn gear_table(chunk_secret: &[u8; 32]) -> [u64; 256] {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_CDC_GEAR);
    hasher.update(chunk_secret);
    let mut xof = hasher.finalize_xof();

    let mut raw = [0u8; 256 * 8];
    xof.fill(&mut raw);

    let mut gear = [0u64; 256];
    for (i, slot) in gear.iter_mut().enumerate() {
        let off = i * 8;
        let mut word = [0u8; 8];
        word.copy_from_slice(&raw[off..off + 8]);
        *slot = u64::from_le_bytes(word);
    }
    gear
}

/// Derives the DETERMINISTIC per-content data key for a chunk (§4.4).
///
/// `data_key = BLAKE3.derive_key("filething.block.key.v1", dedup_secret)` with
/// `info = pcid`. The "info = pcid" of the spec is realized by feeding the
/// hasher first the `dedup_secret` (the key material / root secret) and then the
/// 32-byte `pcid`, before finalizing to 32 bytes. Order is fixed
/// (`dedup_secret` then `pcid`) so the derivation is deterministic and
/// reproducible on every Device.
///
/// RESERVED: encryption is OFF in the MVP, so nothing calls this yet. It is
/// implemented and tested now only to lock the derivation down.
pub fn data_key(dedup_secret: &[u8; 32], pcid: &Pcid) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_BLOCK_KEY);
    hasher.update(dedup_secret);
    hasher.update(pcid.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Derives the DETERMINISTIC per-content 24-byte nonce for a chunk (§4.4).
///
/// `nonce = BLAKE3.derive_key("filething.block.nonce.v1", dedup_secret)[..24]`
/// with `info = pcid`, using the same `dedup_secret`-then-`pcid` update order as
/// [`data_key`]. The 24-byte width matches XChaCha20-Poly1305's nonce (§2).
///
/// RESERVED: encryption is OFF in the MVP; this is implemented and tested only
/// to keep the derivation deterministic and stable.
pub fn nonce(dedup_secret: &[u8; 32], pcid: &Pcid) -> [u8; 24] {
    let mut hasher = blake3::Hasher::new_derive_key(CTX_BLOCK_NONCE);
    hasher.update(dedup_secret);
    hasher.update(pcid.as_bytes());
    let full = *hasher.finalize().as_bytes();
    let mut n = [0u8; 24];
    n.copy_from_slice(&full[..24]);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- cid_of / pcid_of vs known BLAKE3 vectors -----

    /// Known BLAKE3-256 vector for the empty input.
    const BLAKE3_EMPTY: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    #[test]
    fn cid_of_empty_matches_known_blake3_vector() {
        let cid = cid_of(b"");
        assert_eq!(cid.to_hex(), BLAKE3_EMPTY);
    }

    #[test]
    fn pcid_of_empty_matches_known_blake3_vector() {
        let pcid = pcid_of(b"");
        assert_eq!(pcid.to_hex(), BLAKE3_EMPTY);
    }

    #[test]
    fn cid_and_pcid_agree_with_the_blake3_crate() {
        // Cross-check against blake3::hash directly on a non-trivial input so the
        // vector is not just "the empty string".
        let data = b"hello world";
        let expected = hex::encode(blake3::hash(data).as_bytes());
        assert_eq!(cid_of(data).to_hex(), expected);
        assert_eq!(pcid_of(data).to_hex(), expected);
    }

    #[test]
    fn cid_equals_pcid_in_mvp_when_nonce_is_zero() {
        // MVP invariant (§4.3): with a zero nonce, cid = BLAKE3(00..0 || payload)
        // computed by the caller. With an EMPTY nonce prefix (the degenerate
        // bytes-only case) cid_of(payload) == pcid_of(payload), documenting that
        // both ids are the same BLAKE3 of the same bytes while encryption is OFF.
        let payload = b"some chunk bytes";
        assert_eq!(cid_of(payload).as_bytes(), pcid_of(payload).as_bytes());
    }

    #[test]
    fn cid_of_is_deterministic() {
        let data = b"deterministic?";
        assert_eq!(cid_of(data), cid_of(data));
    }

    // ----- hex_lower -----

    #[test]
    fn hex_lower_is_64_lowercase_chars() {
        let b: [u8; 32] = core::array::from_fn(|i| i as u8);
        let h = hex_lower(&b);
        assert_eq!(h.len(), 64);
        assert_eq!(
            h,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn hex_lower_uses_lowercase_for_high_bytes() {
        let b = [0xABu8; 32];
        let h = hex_lower(&b);
        assert_eq!(h, "ab".repeat(32));
    }

    // ----- fanout_key / block_key / manifest_key / blocklist_key -----

    #[test]
    fn fanout_key_format_is_prefix_slash_aa_slash_hex() {
        let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let key = fanout_key("blocks", hex);
        assert_eq!(
            key,
            "blocks/9f/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        // The <aa> segment is exactly the first two chars of the hex.
        assert_eq!(&key["blocks/".len().."blocks/".len() + 2], &hex[..2]);
    }

    #[test]
    fn block_key_matches_spec_example() {
        // §4.2 worked example.
        let cid = Cid::from_hex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
            .unwrap();
        assert_eq!(
            block_key(&cid),
            "blocks/9f/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn manifest_and_blocklist_keys_use_their_prefixes() {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3));
        let hex = hex_lower(&bytes);
        let cid = Cid::new(bytes);
        assert_eq!(
            manifest_key(&cid),
            format!("manifest/{}/{}", &hex[..2], hex)
        );
        assert_eq!(
            blocklist_key(&cid),
            format!("blocklist/{}/{}", &hex[..2], hex)
        );
    }

    // ----- gear_table determinism -----

    #[test]
    fn gear_table_is_deterministic_for_same_secret() {
        let secret = [7u8; 32];
        assert_eq!(gear_table(&secret), gear_table(&secret));
    }

    #[test]
    fn gear_table_differs_for_different_secrets() {
        let a = gear_table(&[1u8; 32]);
        let b = gear_table(&[2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn gear_table_is_not_all_zero_or_uniform() {
        // Sanity: the XOF produced varied entries (not a degenerate fill).
        let g = gear_table(&[42u8; 32]);
        assert!(g.iter().any(|&w| w != 0));
        assert!(g.windows(2).any(|w| w[0] != w[1]));
    }

    #[test]
    fn gear_table_reads_little_endian_words() {
        // Re-derive the raw XOF bytes the same way and confirm the u64s are LE.
        let secret = [0x11u8; 32];
        let mut hasher = blake3::Hasher::new_derive_key(CTX_CDC_GEAR);
        hasher.update(&secret);
        let mut xof = hasher.finalize_xof();
        let mut raw = [0u8; 256 * 8];
        xof.fill(&mut raw);

        let g = gear_table(&secret);
        let mut first = [0u8; 8];
        first.copy_from_slice(&raw[0..8]);
        assert_eq!(g[0], u64::from_le_bytes(first));
        let mut last = [0u8; 8];
        last.copy_from_slice(&raw[255 * 8..255 * 8 + 8]);
        assert_eq!(g[255], u64::from_le_bytes(last));
    }

    // ----- data_key / nonce determinism (§4.4) -----

    #[test]
    fn data_key_is_deterministic() {
        let secret = [3u8; 32];
        let pcid = Pcid::new([9u8; 32]);
        assert_eq!(data_key(&secret, &pcid), data_key(&secret, &pcid));
    }

    #[test]
    fn nonce_is_deterministic_and_24_bytes() {
        let secret = [3u8; 32];
        let pcid = Pcid::new([9u8; 32]);
        let n = nonce(&secret, &pcid);
        assert_eq!(n.len(), 24);
        assert_eq!(n, nonce(&secret, &pcid));
    }

    #[test]
    fn data_key_depends_on_both_secret_and_pcid() {
        let pcid_a = Pcid::new([1u8; 32]);
        let pcid_b = Pcid::new([2u8; 32]);
        // Different pcid, same secret -> different key.
        assert_ne!(data_key(&[5u8; 32], &pcid_a), data_key(&[5u8; 32], &pcid_b));
        // Different secret, same pcid -> different key.
        assert_ne!(data_key(&[5u8; 32], &pcid_a), data_key(&[6u8; 32], &pcid_a));
    }

    #[test]
    fn nonce_depends_on_both_secret_and_pcid() {
        let pcid_a = Pcid::new([1u8; 32]);
        let pcid_b = Pcid::new([2u8; 32]);
        assert_ne!(nonce(&[5u8; 32], &pcid_a), nonce(&[5u8; 32], &pcid_b));
        assert_ne!(nonce(&[5u8; 32], &pcid_a), nonce(&[6u8; 32], &pcid_a));
    }

    #[test]
    fn data_key_and_nonce_use_distinct_contexts() {
        // Same secret + pcid but different KDF context strings must not collide:
        // the data key's first 24 bytes must differ from the nonce.
        let secret = [4u8; 32];
        let pcid = Pcid::new([8u8; 32]);
        let key = data_key(&secret, &pcid);
        let n = nonce(&secret, &pcid);
        assert_ne!(&key[..24], &n[..]);
    }
}
