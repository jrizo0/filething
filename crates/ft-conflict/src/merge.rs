//! Three-way textual line merge (`docs/format.md §10`, issue #14 point 4).
//!
//! When two Devices diverge on the SAME path, [`resolve`](crate::resolve)
//! returns [`Resolution::ConflictCopy`](crate::Resolution::ConflictCopy). Before
//! falling back to a conflict copy the engine asks [`merge3`] whether the two
//! divergent edits can be reconciled by CONTENT: a classic diff3 line merge
//! against the common base. Non-overlapping edits (appends at either end, edits
//! in disjoint line regions, or the identical edit made on both sides) merge
//! cleanly; edits that touch the same line region, or any non-text input,
//! decline and leave the engine to write a conflict copy.
//!
//! This module is PURE and panic-free: it takes the three byte buffers and
//! returns a [`Merge3`]. It NEVER writes conflict markers (`<<<<<<<`) into the
//! output — a decline is signalled out-of-band via [`Merge3::Conflict`].
//!
//! Determinism: the line LCS uses a standard `O(n·m)` dynamic-programming table
//! with a fixed forward back-track, so the same three inputs always yield the
//! same bytes.

/// The verdict of a three-way textual merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Merge3 {
    /// The three versions reconciled cleanly; carries the merged bytes (never
    /// containing conflict markers).
    Clean(Vec<u8>),
    /// Both sides edited the same line region with different content (or a
    /// size/line budget was exceeded): decline, let the caller keep both.
    Conflict,
    /// At least one side is not valid UTF-8 text (or carries a NUL byte): no
    /// textual merge is meaningful. The caller keeps both.
    Binary,
}

/// Largest single side (bytes) we will attempt to merge. Beyond this we decline
/// with [`Merge3::Conflict`] rather than pay the diff cost — the engine then
/// writes a conflict copy. A conservative bound that still covers ordinary
/// source/text files (`§10`).
const MAX_MERGE_BYTES: usize = 5 * 1024 * 1024;

/// Window (bytes) scanned for a NUL byte during binary detection. UTF-8 validity
/// is checked over the WHOLE buffer; the NUL scan only needs a prefix to catch
/// the common "text-looking header, binary body" case cheaply.
const NUL_SCAN: usize = 8 * 1024;

/// Largest `base_mid × other_mid` line-count product for which we run the LCS
/// table. The table holds `(n+1)·(m+1)` `u32` cells, so this caps a single LCS
/// at ~16 MB of scratch. Common-prefix/suffix trimming (see [`matching_blocks`])
/// keeps the append/small-edit cases far under this, so only a large wholesale
/// rewrite trips it — and that declines to [`Merge3::Conflict`] (a conflict
/// copy), never a panic or an OOM.
const MAX_LCS_PRODUCT: usize = 4_000_000;

/// Attempts a three-way line merge of `local` and `remote` against their common
/// `base`.
///
/// Returns [`Merge3::Clean`] with the merged bytes when the two sides' edits do
/// not overlap (or are identical), [`Merge3::Conflict`] when they edit the same
/// line region differently (or a size/line budget is exceeded), and
/// [`Merge3::Binary`] when any side is not UTF-8 text.
pub fn merge3(base: &[u8], local: &[u8], remote: &[u8]) -> Merge3 {
    // Size guard first, before any splitting/allocation.
    if base.len() > MAX_MERGE_BYTES
        || local.len() > MAX_MERGE_BYTES
        || remote.len() > MAX_MERGE_BYTES
    {
        return Merge3::Conflict;
    }

    // Binary guard: a single non-text side makes a textual merge meaningless.
    if is_binary(base) || is_binary(local) || is_binary(remote) {
        return Merge3::Binary;
    }

    // Whole-file short-circuits (cheap and deterministic). The engine only calls
    // this when both sides diverged from base by content identity, so in
    // practice none of these fire from the engine; they keep the pure function
    // total and give the unit tests a fast path.
    if local == remote {
        return Merge3::Clean(local.to_vec());
    }
    if local == base {
        return Merge3::Clean(remote.to_vec());
    }
    if remote == base {
        return Merge3::Clean(local.to_vec());
    }

    let b = split_lines(base);
    let l = split_lines(local);
    let r = split_lines(remote);

    // Aligned matching blocks (base↔local and base↔remote). `None` means the LCS
    // budget was exceeded ⇒ decline rather than blow up memory.
    let blocks_l = match matching_blocks(&b, &l) {
        Some(v) => v,
        None => return Merge3::Conflict,
    };
    let blocks_r = match matching_blocks(&b, &r) {
        Some(v) => v,
        None => return Merge3::Conflict,
    };

    // Stable regions: base line ranges that survive UNCHANGED in both sides.
    let sync = find_sync_regions(&blocks_l, &blocks_r);

    let mut out: Vec<u8> = Vec::with_capacity(local.len().max(remote.len()));
    let (mut bp, mut lp, mut rp) = (0usize, 0usize, 0usize);
    for reg in &sync {
        // Unstable gap immediately before this stable region.
        let gap_base = &b[bp..reg.base_start];
        let gap_local = &l[lp..reg.local_start];
        let gap_remote = &r[rp..reg.remote_start];
        if let Some(chunk) = merge_gap(gap_base, gap_local, gap_remote) {
            out.extend_from_slice(&chunk);
        } else {
            return Merge3::Conflict;
        }
        // Stable region: identical in all three, copy verbatim from base.
        extend_lines(&mut out, &b[reg.base_start..reg.base_end]);
        bp = reg.base_end;
        lp = reg.local_end;
        rp = reg.remote_end;
    }

    // Trailing unstable gap after the last stable region (there is no sentinel
    // stable region; the tail is flushed here).
    if let Some(chunk) = merge_gap(&b[bp..], &l[lp..], &r[rp..]) {
        out.extend_from_slice(&chunk);
    } else {
        return Merge3::Conflict;
    }

    Merge3::Clean(out)
}

/// Reconciles one unstable gap (`base`/`local`/`remote` line slices between two
/// stable regions). Returns the chosen bytes, or `None` when both sides changed
/// the gap differently (an overlap ⇒ conflict). An empty gap yields `Some(empty)`.
fn merge_gap(gap_base: &[&[u8]], gap_local: &[&[u8]], gap_remote: &[&[u8]]) -> Option<Vec<u8>> {
    if gap_base.is_empty() && gap_local.is_empty() && gap_remote.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    if gap_local == gap_base {
        // Local left this region at base ⇒ take the remote side.
        extend_lines(&mut out, gap_remote);
        Some(out)
    } else if gap_remote == gap_base {
        // Remote left this region at base ⇒ take the local side.
        extend_lines(&mut out, gap_local);
        Some(out)
    } else if gap_local == gap_remote {
        // Both sides made the identical change ⇒ clean.
        extend_lines(&mut out, gap_local);
        Some(out)
    } else {
        None
    }
}

/// True when `data` is not treatable as UTF-8 text: invalid UTF-8 anywhere, or a
/// NUL byte within the first [`NUL_SCAN`] bytes (conservative binary sniff).
fn is_binary(data: &[u8]) -> bool {
    if std::str::from_utf8(data).is_err() {
        return true;
    }
    let window = data.len().min(NUL_SCAN);
    data[..window].contains(&0)
}

/// Splits `data` into lines, each line INCLUDING its trailing `\n` (and any `\r`
/// before it — CRLF is preserved, never normalized). A final run without a
/// trailing newline becomes its own line. Empty input yields no lines.
fn split_lines(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (i, &byte) in data.iter().enumerate() {
        if byte == b'\n' {
            lines.push(&data[start..=i]);
            start = i + 1;
        }
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

/// Appends the bytes of every line in `lines` to `out`, in order.
fn extend_lines(out: &mut Vec<u8>, lines: &[&[u8]]) {
    for line in lines {
        out.extend_from_slice(line);
    }
}

/// One aligned stable region shared by all three versions.
#[derive(Debug, Clone, Copy)]
struct SyncRegion {
    base_start: usize,
    base_end: usize,
    local_start: usize,
    local_end: usize,
    remote_start: usize,
    remote_end: usize,
}

/// Intersects the base ranges of the two matching-block lists to find the
/// regions that are aligned (unchanged) in BOTH sides — the diff3 synchronization
/// points. Blocks are `(base_start, other_start, len)`, sorted by base.
fn find_sync_regions(
    la: &[(usize, usize, usize)],
    lb: &[(usize, usize, usize)],
) -> Vec<SyncRegion> {
    let mut out = Vec::new();
    let (mut ia, mut ib) = (0usize, 0usize);
    while ia < la.len() && ib < lb.len() {
        let (abase, amatch, alen) = la[ia];
        let (bbase, bmatch, blen) = lb[ib];
        // Overlap of the two base ranges [abase, abase+alen) ∩ [bbase, bbase+blen).
        let i = abase.max(bbase);
        let j = (abase + alen).min(bbase + blen);
        if i < j {
            let ls = amatch + (i - abase);
            let rs = bmatch + (i - bbase);
            out.push(SyncRegion {
                base_start: i,
                base_end: j,
                local_start: ls,
                local_end: ls + (j - i),
                remote_start: rs,
                remote_end: rs + (j - i),
            });
        }
        // Advance whichever block ends first in base.
        if abase + alen < bbase + blen {
            ia += 1;
        } else {
            ib += 1;
        }
    }
    out
}

/// Matching blocks between `base` and `other` as `(base_start, other_start, len)`
/// runs, sorted by base. Trims the common prefix/suffix first (so an append or a
/// small edit needs a tiny LCS), then runs the line LCS on the differing middle.
///
/// Returns `None` when the middle LCS table would exceed [`MAX_LCS_PRODUCT`]
/// cells — the caller declines to [`Merge3::Conflict`] rather than allocate an
/// unbounded table.
fn matching_blocks(base: &[&[u8]], other: &[&[u8]]) -> Option<Vec<(usize, usize, usize)>> {
    let nb = base.len();
    let no = other.len();

    // Common prefix.
    let mut p = 0;
    while p < nb && p < no && base[p] == other[p] {
        p += 1;
    }
    // Common suffix (never overlapping the prefix).
    let mut s = 0;
    while s < (nb - p) && s < (no - p) && base[nb - 1 - s] == other[no - 1 - s] {
        s += 1;
    }

    let mid_base = &base[p..nb - s];
    let mid_other = &other[p..no - s];

    // Bound the DP table.
    match mid_base.len().checked_mul(mid_other.len()) {
        Some(product) if product <= MAX_LCS_PRODUCT => {}
        _ => return None,
    }

    let mid_pairs = lcs_pairs(mid_base, mid_other);

    // Full pair list: prefix (identity), middle LCS (offset by p), suffix.
    let mut pairs: Vec<(usize, usize)> = Vec::with_capacity(p + mid_pairs.len() + s);
    for k in 0..p {
        pairs.push((k, k));
    }
    for (bi, oi) in mid_pairs {
        pairs.push((p + bi, p + oi));
    }
    for k in 0..s {
        pairs.push((nb - s + k, no - s + k));
    }

    Some(coalesce(pairs))
}

/// Coalesces sorted matching pairs into maximal `(base_start, other_start, len)`
/// blocks: a run of pairs that both increment by one.
fn coalesce(pairs: Vec<(usize, usize)>) -> Vec<(usize, usize, usize)> {
    let mut blocks = Vec::new();
    let mut it = pairs.into_iter();
    if let Some((b0, o0)) = it.next() {
        let (mut sb, mut so, mut len) = (b0, o0, 1usize);
        let (mut pb, mut po) = (b0, o0);
        for (b, o) in it {
            if b == pb + 1 && o == po + 1 {
                len += 1;
            } else {
                blocks.push((sb, so, len));
                sb = b;
                so = o;
                len = 1;
            }
            pb = b;
            po = o;
        }
        blocks.push((sb, so, len));
    }
    blocks
}

/// Longest common subsequence of two line sequences, as matched index pairs
/// `(a_index, b_index)` in increasing order. Standard `O(n·m)` DP + a
/// deterministic forward back-track.
fn lcs_pairs(a: &[&[u8]], b: &[&[u8]]) -> Vec<(usize, usize)> {
    let n = a.len();
    let m = b.len();
    if n == 0 || m == 0 {
        return Vec::new();
    }
    let w = m + 1;
    // dp[i*w + j] = LCS length of a[i..] and b[j..].
    let mut dp = vec![0u32; (n + 1) * w];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i * w + j] = if a[i] == b[j] {
                dp[(i + 1) * w + (j + 1)] + 1
            } else {
                dp[(i + 1) * w + j].max(dp[i * w + (j + 1)])
            };
        }
    }
    let mut pairs = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            pairs.push((i, j));
            i += 1;
            j += 1;
        } else if dp[(i + 1) * w + j] >= dp[i * w + (j + 1)] {
            i += 1;
        } else {
            j += 1;
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(m: Merge3) -> Vec<u8> {
        match m {
            Merge3::Clean(v) => v,
            other => panic!("expected Clean, got {other:?}"),
        }
    }

    #[test]
    fn append_at_both_ends_non_overlapping_is_clean() {
        let base = b"l1\nl2\n";
        let local = b"HEAD\nl1\nl2\n";
        let remote = b"l1\nl2\nTAIL\n";
        assert_eq!(
            clean(merge3(base, local, remote)),
            b"HEAD\nl1\nl2\nTAIL\n".to_vec()
        );
    }

    #[test]
    fn append_only_on_one_side_is_clean() {
        let base = b"a\nb\nc\n";
        let local = b"a\nb\nc\nd\n";
        let remote = b"a\nb\nc\n"; // remote unchanged from base
                                   // remote == base short-circuit path is NOT hit here because we call
                                   // through the general routine via distinct local; remote==base arm:
        assert_eq!(clean(merge3(base, local, remote)), b"a\nb\nc\nd\n".to_vec());
    }

    #[test]
    fn edits_on_distinct_lines_merge_clean() {
        let base = b"a\nb\nc\nd\ne\n";
        // Local edits line 2; remote edits line 4. Disjoint regions.
        let local = b"a\nB!\nc\nd\ne\n";
        let remote = b"a\nb\nc\nD!\ne\n";
        assert_eq!(
            clean(merge3(base, local, remote)),
            b"a\nB!\nc\nD!\ne\n".to_vec()
        );
    }

    #[test]
    fn same_line_edited_differently_conflicts() {
        let base = b"a\nb\nc\n";
        let local = b"a\nBL\nc\n";
        let remote = b"a\nBR\nc\n";
        assert_eq!(merge3(base, local, remote), Merge3::Conflict);
    }

    #[test]
    fn identical_change_on_both_sides_is_clean() {
        let base = b"a\nb\nc\n";
        let both = b"a\nCHANGED\nc\n";
        assert_eq!(clean(merge3(base, both, both)), both.to_vec());
    }

    #[test]
    fn adjacent_line_edits_with_no_stable_line_between_conflict() {
        // Local edits line 2, remote edits line 3 — ADJACENT, with no line that
        // stays unchanged on BOTH sides between them. Standard diff3 (GNU
        // `diff3 -m` and `git merge-file`) treats this as one conflict hunk, and
        // so do we: without a shared anchor the two changes cannot be ordered.
        let base = b"a\nb\nc\nd\n";
        let local = b"a\nB\nc\nd\n";
        let remote = b"a\nb\nC\nd\n";
        assert_eq!(merge3(base, local, remote), Merge3::Conflict);
    }

    #[test]
    fn distant_line_edits_with_a_stable_line_between_are_clean() {
        // Local edits line 2, remote edits line 4, with line 3 ("c") unchanged on
        // both sides as an anchor between them ⇒ clean merge.
        let base = b"a\nb\nc\nd\ne\n";
        let local = b"a\nB\nc\nd\ne\n";
        let remote = b"a\nb\nc\nD\ne\n";
        assert_eq!(
            clean(merge3(base, local, remote)),
            b"a\nB\nc\nD\ne\n".to_vec()
        );
    }

    #[test]
    fn insertions_at_the_same_point_conflict() {
        // Both insert different lines after "a" — overlapping region ⇒ conflict.
        let base = b"a\nb\n";
        let local = b"a\nX\nb\n";
        let remote = b"a\nY\nb\n";
        assert_eq!(merge3(base, local, remote), Merge3::Conflict);
    }

    #[test]
    fn binary_non_utf8_is_binary() {
        let base = b"a\nb\n";
        let local = &[0xff, 0xfe, 0x00, 0x01][..]; // invalid UTF-8
        let remote = b"a\nb\nc\n";
        assert_eq!(merge3(base, local, remote), Merge3::Binary);
    }

    #[test]
    fn nul_byte_is_binary() {
        let base = b"a\nb\n";
        let local = b"a\x00b\n"; // valid UTF-8 but carries a NUL
        let remote = b"a\nb\nc\n";
        assert_eq!(merge3(base, local, remote), Merge3::Binary);
    }

    #[test]
    fn empty_base_with_two_different_contents_conflicts() {
        let base = b"";
        let local = b"x\n";
        let remote = b"y\n";
        assert_eq!(merge3(base, local, remote), Merge3::Conflict);
    }

    #[test]
    fn empty_base_with_identical_content_is_clean() {
        let base = b"";
        let both = b"x\n";
        assert_eq!(clean(merge3(base, both, both)), both.to_vec());
    }

    #[test]
    fn no_trailing_newline_append_is_clean() {
        // base ends without a newline; local appends a new final line, remote
        // prepends. The last base line "b" has no terminator and is preserved.
        let base = b"a\nb";
        let local = b"a\nb\nc\n";
        let remote = b"PRE\na\nb";
        assert_eq!(
            clean(merge3(base, local, remote)),
            b"PRE\na\nb\nc\n".to_vec()
        );
    }

    #[test]
    fn crlf_terminators_are_preserved() {
        let base = b"a\r\nb\r\n";
        let local = b"HEAD\r\na\r\nb\r\n";
        let remote = b"a\r\nb\r\nTAIL\r\n";
        assert_eq!(
            clean(merge3(base, local, remote)),
            b"HEAD\r\na\r\nb\r\nTAIL\r\n".to_vec()
        );
    }

    #[test]
    fn last_line_edit_on_both_sides_conflicts() {
        let base = b"a\nb\nc";
        let local = b"a\nb\nLOCAL";
        let remote = b"a\nb\nREMOTE";
        assert_eq!(merge3(base, local, remote), Merge3::Conflict);
    }

    #[test]
    fn delete_region_on_one_side_edit_elsewhere_on_other_is_clean() {
        // Local deletes line "b"; remote edits distant line "d".
        let base = b"a\nb\nc\nd\n";
        let local = b"a\nc\nd\n";
        let remote = b"a\nb\nc\nD!\n";
        assert_eq!(clean(merge3(base, local, remote)), b"a\nc\nD!\n".to_vec());
    }

    #[test]
    fn deterministic_repeated_calls() {
        let base = b"one\ntwo\nthree\nfour\n";
        let local = b"one\ntwoL\nthree\nfour\nfive\n";
        let remote = b"zero\none\ntwo\nthree\nfour\n";
        let a = merge3(base, local, remote);
        let b = merge3(base, local, remote);
        assert_eq!(a, b);
        assert_eq!(clean(a), b"zero\none\ntwoL\nthree\nfour\nfive\n".to_vec());
    }

    #[test]
    fn oversized_side_declines_to_conflict() {
        let big = vec![b'a'; MAX_MERGE_BYTES + 1];
        assert_eq!(merge3(b"a\n", &big, b"b\n"), Merge3::Conflict);
    }
}
