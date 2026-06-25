//! ft-chunker — FastCDC content-defined chunking (16/64/256 KiB).
//!
//! Implements **FastCDC with normalized chunking level 2 (NC-2)** from scratch
//! (`docs/format.md §3`). The rolling hash is the *gear* hash; the gear table of
//! 256 `u64`s is derived per-Space from the `chunk secret` via
//! [`ft_hash::gear_table`], so two Devices that share a Space cut a file
//! identically (a hard requirement: content-addressing means the same bytes must
//! produce the same Blocks on every Device). The min/avg/max bounds are
//! [`ft_core::CHUNK_MIN`] / [`ft_core::CHUNK_AVG`] / [`ft_core::CHUNK_MAX`]
//! (16 / 64 / 256 KiB).
//!
//! # Algorithm (NC-2)
//!
//! The rolling gear hash advances one byte at a time:
//!
//! ```text
//! fp = (fp << 1).wrapping_add(gear[byte])
//! ```
//!
//! A cut is declared at the first position `i` where `fp & mask == 0`. Plain
//! FastCDC uses a single mask with `log2(avg)` bits set; its cut-length
//! distribution has a fat geometric tail toward `max`. **Normalized chunking**
//! removes that bias by using TWO masks around the average:
//!
//! - Before reaching `avg`, a STRICTER mask (`MASK_S`, *more* bits set) makes a
//!   match rarer, so short cuts are suppressed and lengths are pushed UP toward
//!   the average.
//! - After `avg`, a LAXER mask (`MASK_L`, *fewer* bits set) makes a match more
//!   likely, so the chunk is cut sooner and lengths are pulled DOWN, well before
//!   `max`.
//!
//! `min` is a hard floor (the rolling hash is not even evaluated before
//! `CHUNK_MIN` bytes — a cut is never declared earlier), and `max` is a hard
//! ceiling (a cut is forced at `CHUNK_MAX` even if no mask matched). The result
//! is a tight length distribution centered near `avg`, which is what gives real
//! intra-file delta for source code: editing one line re-chunks only the region
//! around the edit and leaves every chunk boundary far from the edit untouched.
//!
//! ## Masks (NC-2, avg = 64 KiB ⇒ `bits = log2(65536) = 16`)
//!
//! NC level 2 spreads the two masks two bits on each side of the base `bits`:
//!
//! - [`MASK_S`] — strict, `bits + 2 = 18` set bits (`0x0005_7baa_0353_0000`).
//! - [`MASK_L`] — lax,   `bits - 2 = 14` set bits (`0x0005_7b00_0353_0000`).
//!
//! Both are grown from the canonical FastCDC spread pattern for a 64 KiB average
//! (the irregular `…0353_0000` low nibbles of Xia et al., USENIX ATC '16, plus
//! mid/high bits added to hit exactly 18 / 14 set bits). The bits sit in the
//! mid-to-high region of the 64-bit word, where the gear fingerprint's entropy
//! concentrates after the repeated `fp << 1` shifts. [`MASK_L`] is a strict
//! subset of [`MASK_S`] (one fewer constraint to satisfy), so the lax mask is
//! genuinely looser — it matches strictly more often than the strict mask, which
//! is exactly the NC-2 invariant. Popcounts are asserted in the test module so
//! the choice is documented and frozen.

use ft_core::{CHUNK_AVG, CHUNK_MAX, CHUNK_MIN};
use ft_hash::gear_table;
use thiserror::Error;

// ---------------------------------------------------------------------------
// NC-2 masks (docs/format.md §3)
// ---------------------------------------------------------------------------

/// Strict mask used while the chunk is still SHORTER than `avg`: more bits set
/// (`bits + 2 = 18` for a 64 KiB average) ⇒ a `fp & MASK_S == 0` match is rarer
/// ⇒ short chunks are suppressed and lengths are pushed up toward `avg`.
///
/// Popcount = 18 (asserted in tests). Grown from the canonical FastCDC 64 KiB
/// spread pattern; a superset of [`MASK_L`].
pub const MASK_S: u64 = 0x0005_7baa_0353_0000;

/// Lax mask used once the chunk has reached `avg`: fewer bits set
/// (`bits - 2 = 14` for a 64 KiB average) ⇒ a `fp & MASK_L == 0` match is more
/// likely ⇒ the chunk is cut sooner, well before `max`.
///
/// Popcount = 14 (asserted in tests). A strict subset of [`MASK_S`], so matching
/// `fp & MASK_L == 0` is strictly easier than `fp & MASK_S == 0`.
pub const MASK_L: u64 = 0x0005_7b00_0353_0000;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that the chunker can surface.
///
/// The chunking itself is infallible over any `&[u8]`; this enum exists so the
/// crate follows the per-crate `thiserror` convention and can grow without an
/// API break. The single variant guards the compile-time mask invariant.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChunkerError {
    /// The configured min/avg/max bounds are not a strictly increasing,
    /// non-zero triple (`0 < min <= avg <= max`). Cannot happen with the
    /// ft-core constants; reserved for future configurable bounds.
    #[error(
        "invalid chunk bounds: expected 0 < min <= avg <= max, got min={min}, avg={avg}, max={max}"
    )]
    InvalidBounds {
        /// The offending minimum.
        min: usize,
        /// The offending average.
        avg: usize,
        /// The offending maximum.
        max: usize,
    },
}

// ---------------------------------------------------------------------------
// Span
// ---------------------------------------------------------------------------

/// A half-open chunk boundary into the input: `data[offset .. offset + len]`.
///
/// The spans returned by [`Chunker::chunk`] cover the whole input with no gaps
/// and no overlaps, in increasing `offset` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    /// Byte offset of the chunk's first byte within `data`.
    pub offset: usize,
    /// Length of the chunk in bytes.
    pub len: usize,
}

impl Span {
    /// The exclusive end offset (`offset + len`).
    #[inline]
    pub const fn end(&self) -> usize {
        self.offset + self.len
    }
}

// ---------------------------------------------------------------------------
// Chunker
// ---------------------------------------------------------------------------

/// A FastCDC NC-2 chunker bound to one Space's gear table.
///
/// Construct with [`Chunker::new`] (derives the gear table from the per-Space
/// `chunk secret` via [`ft_hash::gear_table`]) or [`Chunker::from_gear`] (inject
/// a precomputed table — e.g. when the table is already cached in the local
/// index). The chunker is cheap to clone and holds no mutable state, so a single
/// instance can chunk many files.
#[derive(Clone)]
pub struct Chunker {
    gear: [u64; 256],
}

impl Chunker {
    /// Builds a chunker from a per-Space `chunk_secret`, deriving the 256-entry
    /// gear table via [`ft_hash::gear_table`] (`docs/format.md §3`).
    ///
    /// Two Chunkers built from the SAME secret cut identically — this is the
    /// "two machines, same secret, same cuts" property the format depends on.
    pub fn new(chunk_secret: &[u8; 32]) -> Chunker {
        Chunker {
            gear: gear_table(chunk_secret),
        }
    }

    /// Builds a chunker from an already-derived gear table.
    ///
    /// Useful when the gear table is cached (avoiding re-running the KDF) or in
    /// tests. The table must be the 256-entry table produced by
    /// [`ft_hash::gear_table`] for the Space's secret, or cuts will not match
    /// other Devices.
    pub fn from_gear(gear: [u64; 256]) -> Chunker {
        Chunker { gear }
    }

    /// Borrows the gear table (mainly for tests / introspection).
    #[inline]
    pub fn gear(&self) -> &[u64; 256] {
        &self.gear
    }

    /// Cuts `data` into content-defined chunks and returns their [`Span`]s.
    ///
    /// The spans tile `data` exactly: contiguous, ordered, non-overlapping, and
    /// together covering `0 .. data.len()`. Every chunk satisfies
    /// `CHUNK_MIN <= len <= CHUNK_MAX` EXCEPT the final chunk, which may be
    /// shorter than `CHUNK_MIN` (it is whatever bytes remain). Empty input
    /// yields an empty `Vec`.
    ///
    /// Deterministic: same `data` + same gear table ⇒ identical spans, always.
    pub fn chunk(&self, data: &[u8]) -> Vec<Span> {
        let mut spans = Vec::new();
        let mut offset = 0usize;
        let total = data.len();
        while offset < total {
            let len = self.next_cut(&data[offset..]);
            spans.push(Span { offset, len });
            offset += len;
        }
        spans
    }

    /// Returns the length of the next chunk starting at the front of `buf`,
    /// applying the NC-2 algorithm with the ft-core min/avg/max bounds.
    ///
    /// Invariants enforced here:
    /// - returns `buf.len()` when the remaining input is `<= CHUNK_MIN`
    ///   (the tail is one short chunk; we never cut below `min`);
    /// - never cuts before `CHUNK_MIN` bytes (the hash isn't evaluated there);
    /// - uses [`MASK_S`] in `[min, avg)` and [`MASK_L`] in `[avg, max)`;
    /// - forces a cut at `CHUNK_MAX` if no mask matched.
    fn next_cut(&self, buf: &[u8]) -> usize {
        let remaining = buf.len();

        // Tail / tiny input: nothing left to cut, the whole remainder is one
        // (possibly sub-min) chunk.
        if remaining <= CHUNK_MIN {
            return remaining;
        }

        // The normalized point and the hard ceiling, both clamped to what's
        // actually available so we never index past the end.
        let normal = remaining.min(CHUNK_AVG);
        let ceiling = remaining.min(CHUNK_MAX);

        let mut fp: u64 = 0;

        // Skip the first CHUNK_MIN bytes entirely: no cut may land before min,
        // and FastCDC also does not feed them through the rolling hash. We start
        // hashing at i = CHUNK_MIN.
        let mut i = CHUNK_MIN;

        // Phase 1 — strict mask, lengths in [min, avg): suppress short cuts.
        while i < normal {
            fp = (fp << 1).wrapping_add(self.gear[buf[i] as usize]);
            if fp & MASK_S == 0 {
                return i + 1;
            }
            i += 1;
        }

        // Phase 2 — lax mask, lengths in [avg, max): cut sooner, before max.
        while i < ceiling {
            fp = (fp << 1).wrapping_add(self.gear[buf[i] as usize]);
            if fp & MASK_L == 0 {
                return i + 1;
            }
            i += 1;
        }

        // No content-defined cut found within the window: force a cut at the
        // ceiling (== CHUNK_MAX unless the remainder was shorter, in which case
        // it is the whole remainder).
        ceiling
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed, arbitrary chunk secret so every test is reproducible.
    const SECRET: [u8; 32] = [0x5a; 32];

    // -- small deterministic PRNG (xorshift64*) so the test corpus is identical
    //    on every machine without pulling in `rand` for non-test paths. --
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            // Avoid the all-zero state which xorshift cannot leave.
            Rng(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(n);
            while out.len() < n {
                out.extend_from_slice(&self.next_u64().to_le_bytes());
            }
            out.truncate(n);
            out
        }
    }

    fn corpus(seed: u64, n: usize) -> Vec<u8> {
        Rng::new(seed).bytes(n)
    }

    fn assert_tiling(spans: &[Span], total: usize) {
        if total == 0 {
            assert!(spans.is_empty(), "empty input must yield no spans");
            return;
        }
        assert_eq!(spans[0].offset, 0, "first span must start at 0");
        let mut cursor = 0usize;
        for s in spans {
            assert_eq!(
                s.offset, cursor,
                "spans must be contiguous (no gap/overlap)"
            );
            assert!(s.len > 0, "no zero-length spans");
            cursor = s.end();
        }
        assert_eq!(cursor, total, "spans must cover the whole input");
    }

    // ---- Mask invariants (document/freeze the NC-2 choice, §3) ----

    #[test]
    fn masks_have_the_documented_popcounts() {
        // bits = log2(avg) = log2(65536) = 16. NC-2 spreads ±2 bits.
        assert_eq!(CHUNK_AVG.trailing_zeros(), 16, "avg must be 2^16");
        assert_eq!(
            MASK_S.count_ones(),
            18,
            "strict mask = bits + 2 = 18 set bits"
        );
        assert_eq!(MASK_L.count_ones(), 14, "lax mask = bits - 2 = 14 set bits");
        // Strict really is stricter than lax (more constraints to satisfy).
        assert!(
            MASK_S.count_ones() > MASK_L.count_ones(),
            "strict mask must have more set bits than the lax mask"
        );
        // MASK_L must be a strict subset of MASK_S: every constraint the lax mask
        // imposes is also imposed by the strict mask, so the lax mask matches
        // strictly more often. This is the load-bearing NC-2 invariant.
        assert_eq!(MASK_S & MASK_L, MASK_L, "MASK_L must be a subset of MASK_S");
    }

    #[test]
    fn bounds_are_the_spec_values() {
        assert_eq!(CHUNK_MIN, 16384);
        assert_eq!(CHUNK_AVG, 65536);
        assert_eq!(CHUNK_MAX, 262144);
    }

    // ---- (1) Determinism: same data + same secret -> same spans ----

    #[test]
    fn determinism_same_data_same_secret() {
        let data = corpus(0xC0FFEE, 300 * 1024);
        let a = Chunker::new(&SECRET).chunk(&data);
        let b = Chunker::new(&SECRET).chunk(&data);
        assert_eq!(a, b, "same data + same secret must produce identical spans");
        assert_tiling(&a, data.len());
    }

    #[test]
    fn determinism_repeated_calls_one_instance() {
        let chunker = Chunker::new(&SECRET);
        let data = corpus(7, 200 * 1024);
        assert_eq!(chunker.chunk(&data), chunker.chunk(&data));
    }

    // ---- (4) Two "machines" with the same secret -> same cuts ----

    #[test]
    fn two_machines_same_secret_same_cuts() {
        // Two independently constructed Chunkers from the same secret = two
        // Devices in the same Space. They must agree byte-for-byte.
        let data = corpus(0xABCDEF, 400 * 1024);
        let machine_a = Chunker::new(&SECRET);
        let machine_b = Chunker::new(&SECRET);
        assert_eq!(machine_a.gear(), machine_b.gear(), "gear tables must match");
        assert_eq!(
            machine_a.chunk(&data),
            machine_b.chunk(&data),
            "two Devices sharing a chunk secret must cut identically"
        );
    }

    #[test]
    fn different_secrets_generally_cut_differently() {
        // Not a correctness requirement of the format, but a sanity check that
        // the secret actually seeds the cuts (per-Space dedup boundary, §3).
        let data = corpus(0x1234, 400 * 1024);
        let a = Chunker::new(&[1u8; 32]).chunk(&data);
        let b = Chunker::new(&[2u8; 32]).chunk(&data);
        assert_ne!(a, b, "different chunk secrets should yield different cuts");
    }

    #[test]
    fn from_gear_matches_new() {
        let gear = ft_hash::gear_table(&SECRET);
        let data = corpus(99, 250 * 1024);
        assert_eq!(
            Chunker::new(&SECRET).chunk(&data),
            Chunker::from_gear(gear).chunk(&data),
            "from_gear must reproduce new() for the same table"
        );
    }

    // ---- (3) min <= len <= max for every span except the last ----

    #[test]
    fn bounds_respected_for_all_but_last_span() {
        // Use a sizeable input so there are many interior chunks to check.
        let data = corpus(0x5EED, 2 * 1024 * 1024 + 12345);
        let spans = Chunker::new(&SECRET).chunk(&data);
        assert_tiling(&spans, data.len());
        assert!(spans.len() > 4, "expected several chunks for a 2 MiB input");

        let last = spans.len() - 1;
        for (i, s) in spans.iter().enumerate() {
            assert!(s.len <= CHUNK_MAX, "span {i} exceeds CHUNK_MAX: {}", s.len);
            if i != last {
                assert!(
                    s.len >= CHUNK_MIN,
                    "non-final span {i} is below CHUNK_MIN: {}",
                    s.len
                );
            }
        }
        // The final span may be < min; it must never exceed max.
        assert!(spans[last].len <= CHUNK_MAX);
    }

    #[test]
    fn input_smaller_than_min_is_a_single_span() {
        let data = corpus(1, 1000); // < CHUNK_MIN
        let spans = Chunker::new(&SECRET).chunk(&data);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0],
            Span {
                offset: 0,
                len: 1000
            }
        );
        assert!(spans[0].len < CHUNK_MIN);
    }

    #[test]
    fn empty_input_yields_no_spans() {
        assert!(Chunker::new(&SECRET).chunk(&[]).is_empty());
    }

    #[test]
    fn incompressible_run_is_capped_at_max() {
        // A long run of a single byte rarely (if ever) triggers a content cut,
        // exercising the forced-cut-at-max path. Every interior chunk should be
        // exactly CHUNK_MAX.
        let data = vec![0u8; CHUNK_MAX * 3 + 500];
        let spans = Chunker::new(&SECRET).chunk(&data);
        assert_tiling(&spans, data.len());
        for s in &spans[..spans.len() - 1] {
            assert!(
                s.len >= CHUNK_MIN && s.len <= CHUNK_MAX,
                "interior span out of bounds: {}",
                s.len
            );
        }
    }

    // ---- (2) Intra-file delta: editing 1 byte moves only 1-2 spans ----

    /// Helper: how many spans are byte-identical (same offset AND len) between
    /// two span lists.
    fn identical_spans(a: &[Span], b: &[Span]) -> usize {
        let set: std::collections::HashSet<(usize, usize)> =
            a.iter().map(|s| (s.offset, s.len)).collect();
        b.iter()
            .filter(|s| set.contains(&(s.offset, s.len)))
            .count()
    }

    #[test]
    fn intra_file_delta_substitution_at_256kib_brief_figure() {
        // The brief's exact figure: ~256 KiB of deterministic pseudo-random
        // data. At avg = 64 KiB this is only ~3-4 chunks, so the strong
        // statistical claim lives in `..._large` below; here we just assert the
        // load-bearing fact directly — a 1-byte substitution moves at most the
        // one chunk that straddles the edit (length is unchanged, so following
        // chunks keep their exact offset+len).
        let mut data = corpus(0xDE17A, 256 * 1024);
        let chunker = Chunker::new(&SECRET);
        let before = chunker.chunk(&data);
        assert_tiling(&before, data.len());
        assert!(before.len() >= 3, "need several chunks to show locality");

        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        let after = chunker.chunk(&data);
        assert_tiling(&after, data.len());

        let common = identical_spans(&before, &after);
        let changed = before.len().max(after.len()) - common;
        assert!(
            changed <= 2,
            "a 1-byte substitution should move at most ~2 spans, moved {changed} \
             (before={}, after={}, common={common})",
            before.len(),
            after.len()
        );
    }

    #[test]
    fn intra_file_delta_substitution_large_majority_identical() {
        // A larger corpus (~1.5 MiB ⇒ ~20 chunks) so "the great majority of
        // spans far from the edit are identical" is a strong statistical claim,
        // not an artifact of having only 4 chunks. This is the real proof that
        // editing one byte moves 1-2 Blocks, not all of them.
        let mut data = corpus(0xDE17A, 1_500_000);
        let chunker = Chunker::new(&SECRET);
        let before = chunker.chunk(&data);
        assert_tiling(&before, data.len());
        assert!(
            before.len() >= 15,
            "expected many chunks (~20) for a 1.5 MiB input, got {}",
            before.len()
        );

        // Substitution in the middle keeps total length, so every chunk that does
        // NOT straddle the edit keeps its exact (offset, len).
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        let after = chunker.chunk(&data);
        assert_tiling(&after, data.len());

        let common = identical_spans(&before, &after);
        let changed = before.len().max(after.len()) - common;
        assert!(
            changed <= 2,
            "a 1-byte substitution should move at most ~2 spans, moved {changed} \
             (before={}, after={}, common={common})",
            before.len(),
            after.len()
        );
        // The overwhelming majority of spans must be byte-identical.
        assert!(
            common * 100 >= before.len() * 90,
            "expected >=90% of spans identical, got {common}/{}",
            before.len()
        );
    }

    #[test]
    fn intra_file_delta_insertion_in_the_middle() {
        // Insertion shifts all following bytes by 1 — the classic case that
        // KILLS fixed-size chunking but that content-defined chunking absorbs:
        // the cut boundaries re-align after the edited region, so spans far
        // PAST the edit re-sync to the same content boundary (their offset just
        // shifts by the single inserted byte). Use a larger corpus so there are
        // many boundaries to re-sync.
        let data = corpus(0xBEEF, 1_500_000);
        let chunker = Chunker::new(&SECRET);
        let before = chunker.chunk(&data);
        assert_tiling(&before, data.len());
        assert!(
            before.len() >= 15,
            "expected many chunks for a 1.5 MiB input, got {}",
            before.len()
        );

        let mid = data.len() / 2;
        let mut edited = Vec::with_capacity(data.len() + 1);
        edited.extend_from_slice(&data[..mid]);
        edited.push(0x42); // inserted byte
        edited.extend_from_slice(&data[mid..]);
        let after = chunker.chunk(&edited);
        assert_tiling(&after, edited.len());

        // Spans entirely BEFORE the edit are byte-identical (same offset+len).
        let unchanged_prefix = before
            .iter()
            .zip(after.iter())
            .take_while(|(b, a)| b == a)
            .count();
        assert!(
            unchanged_prefix >= 1,
            "at least the leading chunks before the edit must be untouched"
        );

        // The real CDC win: boundaries re-sync after the edit. Spans whose END
        // is comfortably past the insertion point match a +1-shifted boundary
        // in the edited stream. Count how many distinct chunk boundaries (cut
        // positions) survived, modulo the +1 shift after the edit.
        let cuts_before: std::collections::HashSet<usize> =
            before.iter().map(|s| s.end()).collect();
        // After the edit every boundary strictly greater than `mid` is shifted
        // by +1; boundaries <= mid are unchanged.
        let resynced = after
            .iter()
            .map(|s| s.end())
            .filter(|&e| {
                if e <= mid {
                    cuts_before.contains(&e)
                } else {
                    // shift back by the single inserted byte
                    cuts_before.contains(&(e - 1))
                }
            })
            .count();

        // The overwhelming majority of boundaries must have re-synced; only the
        // 1-2 boundaries adjacent to the edit get rewritten.
        let total_after = after.len();
        assert!(
            resynced + 2 >= total_after,
            "insertion should rewrite at most ~2 boundaries, but only {resynced}/{total_after} \
             re-synced"
        );
        assert!(
            resynced * 10 >= total_after * 9,
            "expected >=90% of boundaries to re-sync after a 1-byte insertion, got \
             {resynced}/{total_after}"
        );
    }
}
