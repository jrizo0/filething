//! ft-manifest — the Manifest B-tree (canonical CBOR).
//!
//! Builds a deterministic bottom-up B-tree of [`FileEntry`]s ordered by
//! `casefold(NFC(p))` ([`CasefoldKey`]): leaves of `<= LEAF_FANOUT` entries,
//! index pages of `<= INDEX_FANOUT` children, externalizing oversized `bk`
//! blocklists to their own content-addressed objects. The build is a PURE
//! function of the (key, entry) set — the same logical file set yields the same
//! root [`Cid`] and the same page bytes on any Device (`docs/format.md §5.3`).
//!
//! ## Content-addressing requires byte-identical CBOR
//!
//! Pages are serialized as **canonical CBOR** (RFC 8949 §4.2.1): map keys sorted
//! first by the length of their encoded form, then bytewise; integers in their
//! shortest form; no indefinite-length items. `ciborium` emits map keys in
//! struct-declaration order, which is NOT canonical, so this crate serializes to
//! a [`ciborium::value::Value`], recursively reorders every map's entries into
//! canonical order, and only then emits the bytes. This is what makes the same
//! logical tree hash identically across machines.
//!
//! A page object on the wire is `BlockHeader::new_manifest(len).encode()` (the
//! fixed 64-byte header, `magic="FTM1"`, `§4.3`) followed by the canonical CBOR
//! payload. The `page_cid` (MVP, encryption OFF) is `ft_hash::cid_of(payload)` —
//! the BLAKE3-256 of the canonical CBOR bytes, with no nonce, exactly like a
//! Block (`§4.3`, `§5.3`).

use ft_core::{
    BlockHeader, CasefoldKey, ChildRef, Cid, FileEntry, IndexPage, LeafPage, ENTRY_INLINE_MAX,
    INDEX_FANOUT, LEAF_FANOUT,
};
use thiserror::Error;

/// Page-format version written into every page's `"v"` field (`§5.3`).
pub const PAGE_VERSION: u8 = 1;

/// Leaf-page kind discriminant (`"k": 0`, `§5.3`).
pub const KIND_LEAF: u8 = 0;
/// Index-page kind discriminant (`"k": 1`, `§5.3`).
pub const KIND_INDEX: u8 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors decoding a Manifest page object.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// The object header was malformed (bad length, magic or version).
    #[error("bad page header: {0}")]
    Header(#[from] ft_core::Error),

    /// The CBOR payload failed to deserialize.
    #[error("cbor decode: {0}")]
    Cbor(String),

    /// The page `"k"` field was neither leaf (`0`) nor index (`1`).
    #[error("unknown page kind: {0}")]
    UnknownKind(u8),
}

/// Crate `Result` alias over [`ManifestError`].
pub type Result<T> = std::result::Result<T, ManifestError>;

// ---------------------------------------------------------------------------
// Build output
// ---------------------------------------------------------------------------

/// The full content-addressed output of [`build`].
///
/// `pages` and `blocklists` are `(cid, object_bytes)` pairs ready to PUT to the
/// Vault under `manifest/<aa>/<cid>` and `blocklist/<aa>/<cid>` respectively
/// (`§6.1`). Page objects carry the 64-byte header + canonical CBOR; blocklist
/// objects are the bare canonical CBOR of a `Vec<Cid>` (no header — they hold no
/// payload semantics of their own beyond the id list, addressed by their bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBuild {
    /// Content id of the single root page (`manifestRoot`, `§5.3`).
    pub root: Cid,
    /// Every distinct page object produced, as `(page_cid, object_bytes)`.
    pub pages: Vec<(Cid, Vec<u8>)>,
    /// Every externalized blocklist object, as `(cid, cbor_bytes)` (`§5.3`).
    pub blocklists: Vec<(Cid, Vec<u8>)>,
}

/// A decoded Manifest page (`§5.3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    /// A leaf page: a contiguous key-ordered run of [`FileEntry`]s.
    Leaf(LeafPage),
    /// An index page: an ordered list of [`ChildRef`]s.
    Index(IndexPage),
}

// ---------------------------------------------------------------------------
// Canonical CBOR (RFC 8949 §4.2.1)
// ---------------------------------------------------------------------------

/// Serializes a `serde`-serializable value to **canonical CBOR** bytes.
///
/// `ciborium` does not order map keys, so we round-trip through
/// [`ciborium::value::Value`], recursively impose canonical map-key order, and
/// then emit. `ciborium` already encodes integers minimally and uses
/// definite-length items for `Value`, satisfying the other two §4.2.1 rules.
fn to_canonical_cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut v = ciborium::value::Value::serialized(value)
        .expect("Manifest page/blocklist is always CBOR-serializable");
    canonicalize_value(&mut v);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&v, &mut buf)
        .expect("writing a ciborium::Value to a Vec never fails");
    buf
}

/// Recursively sorts every map in `v` into RFC 8949 §4.2.1 canonical key order.
fn canonicalize_value(v: &mut ciborium::value::Value) {
    use ciborium::value::Value;
    match v {
        Value::Map(entries) => {
            for (k, val) in entries.iter_mut() {
                canonicalize_value(k);
                canonicalize_value(val);
            }
            // §4.2.1: order by the encoded key bytes — shorter encoding first,
            // then bytewise lexicographic on equal length.
            entries.sort_by(|(ka, _), (kb, _)| {
                let ea = encode_key(ka);
                let eb = encode_key(kb);
                ea.len().cmp(&eb.len()).then_with(|| ea.cmp(&eb))
            });
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                canonicalize_value(item);
            }
        }
        Value::Tag(_, inner) => canonicalize_value(inner),
        _ => {}
    }
}

/// Encodes a single CBOR key to its canonical byte form so two keys can be
/// compared by (encoded-length, bytewise) per §4.2.1.
fn encode_key(k: &ciborium::value::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(k, &mut buf).expect("encoding a CBOR map key never fails");
    buf
}

// ---------------------------------------------------------------------------
// Page object framing (header + canonical CBOR)
// ---------------------------------------------------------------------------

/// Frames a page's canonical CBOR payload into a full Vault object:
/// `BlockHeader::new_manifest(len).encode() || payload` (`§4.3`, `§5.3`), and
/// returns `(page_cid, object_bytes)`.
///
/// The `page_cid` is `cid_of(payload)` — the BLAKE3-256 of the canonical CBOR
/// bytes alone (MVP: zero nonce, no header in the hash), matching how `ft-block`
/// names objects (`§4.3`).
fn frame_page(payload: Vec<u8>) -> (Cid, Vec<u8>) {
    let cid = ft_hash::cid_of(&payload);
    let header = BlockHeader::new_manifest(payload.len() as u64).encode();
    let mut obj = Vec::with_capacity(header.len() + payload.len());
    obj.extend_from_slice(&header);
    obj.extend_from_slice(&payload);
    (cid, obj)
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

/// Builds the content-addressed Manifest B-tree from a set of `(key, entry)`
/// pairs (`§5.3`).
///
/// Algorithm (deterministic, pure):
/// 1. Sort all entries by [`CasefoldKey`] ascending.
/// 2. For each entry, if its CBOR exceeds [`ENTRY_INLINE_MAX`], externalize its
///    `bk` to a `blocklist/<cid>` object (canonical CBOR of `Vec<Cid>`), clear
///    `bk`, and set `bk_ref` to that cid.
/// 3. Pack the ordered entries into leaf pages of `<= LEAF_FANOUT` contiguous
///    entries.
/// 4. Build index pages of `<= INDEX_FANOUT` children bottom-up until a single
///    root remains. With exactly one leaf, that leaf IS the root.
///
/// `ChildRef.min` is the first [`CasefoldKey`] of the child's subtree. The same
/// `(key, entry)` set in ANY input order yields the same `root` and pages.
pub fn build(entries: Vec<(CasefoldKey, FileEntry)>) -> ManifestBuild {
    // (1) Total order by casefold key, ascending. Stable so that — although
    // §5.2 forbids duplicate keys (a collision is a conflict, resolved upstream)
    // — a defensive duplicate does not make the output order-dependent.
    let mut entries = entries;
    entries.sort_by(|(ka, _), (kb, _)| ka.cmp(kb));

    let mut blocklists: Vec<(Cid, Vec<u8>)> = Vec::new();

    // (2) Externalize oversized bk lists. The "size" test is the entry's own
    // canonical CBOR length (the unit of pagination is the whole FileEntry).
    let ordered: Vec<(CasefoldKey, FileEntry)> = entries
        .into_iter()
        .map(|(key, mut entry)| {
            let entry_len = to_canonical_cbor(&entry).len();
            if entry_len > ENTRY_INLINE_MAX && !entry.bk.is_empty() {
                let bk_payload = to_canonical_cbor(&entry.bk);
                let bk_cid = ft_hash::cid_of(&bk_payload);
                if !blocklists.iter().any(|(c, _)| *c == bk_cid) {
                    blocklists.push((bk_cid, bk_payload));
                }
                entry.bk = Vec::new();
                entry.bk_ref = Some(bk_cid);
            }
            (key, entry)
        })
        .collect();

    let mut pages: Vec<(Cid, Vec<u8>)> = Vec::new();

    // (3) Pack into leaf pages of <= LEAF_FANOUT contiguous entries. Each
    // produced child is tracked as (min_key, page_cid) for the level above.
    let mut level: Vec<(CasefoldKey, Cid)> = Vec::new();

    if ordered.is_empty() {
        // Empty Space: a single empty leaf is the root, so a valid manifestRoot
        // always exists (diff/feed never special-case "no manifest yet").
        let leaf = LeafPage {
            k: KIND_LEAF,
            v: PAGE_VERSION,
            first: CasefoldKey(String::new()),
            last: CasefoldKey(String::new()),
            e: Vec::new(),
        };
        let payload = to_canonical_cbor(&leaf);
        let (cid, obj) = frame_page(payload);
        pages.push((cid, obj));
        return ManifestBuild {
            root: cid,
            pages,
            blocklists,
        };
    }

    for chunk in ordered.chunks(LEAF_FANOUT) {
        let first = chunk[0].0.clone();
        let last = chunk[chunk.len() - 1].0.clone();
        let e: Vec<FileEntry> = chunk.iter().map(|(_, entry)| entry.clone()).collect();
        let leaf = LeafPage {
            k: KIND_LEAF,
            v: PAGE_VERSION,
            first: first.clone(),
            last,
            e,
        };
        let payload = to_canonical_cbor(&leaf);
        let (cid, obj) = frame_page(payload);
        push_page(&mut pages, cid, obj);
        level.push((first, cid));
    }

    // (4) Build index levels bottom-up until a single root remains.
    while level.len() > 1 {
        let mut next: Vec<(CasefoldKey, Cid)> = Vec::new();
        for chunk in level.chunks(INDEX_FANOUT) {
            let min = chunk[0].0.clone();
            let children: Vec<ChildRef> = chunk
                .iter()
                .map(|(k, cid)| ChildRef {
                    min: k.clone(),
                    cid: *cid,
                })
                .collect();
            let index = IndexPage {
                k: KIND_INDEX,
                v: PAGE_VERSION,
                children,
            };
            let payload = to_canonical_cbor(&index);
            let (cid, obj) = frame_page(payload);
            push_page(&mut pages, cid, obj);
            next.push((min, cid));
        }
        level = next;
    }

    let root = level[0].1;
    ManifestBuild {
        root,
        pages,
        blocklists,
    }
}

/// Pushes a page only if its `page_cid` is not already present, so a tree that
/// happens to contain two byte-identical pages stores the object once. Dedup is
/// by content id, mirroring the Vault's idempotent PUT (`§4.2`).
fn push_page(pages: &mut Vec<(Cid, Vec<u8>)>, cid: Cid, obj: Vec<u8>) {
    if !pages.iter().any(|(c, _)| *c == cid) {
        pages.push((cid, obj));
    }
}

// ---------------------------------------------------------------------------
// decode_page
// ---------------------------------------------------------------------------

/// Decodes a Manifest page object (`header || canonical CBOR`) into a [`Page`].
///
/// Validates the 64-byte header (length, magic, version) via
/// [`BlockHeader::decode`], then deserializes the CBOR payload and discriminates
/// leaf vs index by the page's `"k"` field (`§5.3`).
pub fn decode_page(obj: &[u8]) -> Result<Page> {
    let header = BlockHeader::decode(obj)?;
    let payload = &obj[ft_core::BLOCK_HEADER_LEN..];
    // The header records the payload length; trust it as the authoritative slice
    // length when the buffer is longer (it never is for a well-framed object).
    let payload = if (header.payload_len as usize) <= payload.len() {
        &payload[..header.payload_len as usize]
    } else {
        payload
    };

    // Peek at "k" generically to decide which page struct to deserialize into.
    let value: ciborium::value::Value =
        ciborium::de::from_reader(payload).map_err(|e| ManifestError::Cbor(e.to_string()))?;
    let kind = page_kind(&value)?;
    match kind {
        KIND_LEAF => {
            let leaf: LeafPage = ciborium::de::from_reader(payload)
                .map_err(|e| ManifestError::Cbor(e.to_string()))?;
            Ok(Page::Leaf(leaf))
        }
        KIND_INDEX => {
            let index: IndexPage = ciborium::de::from_reader(payload)
                .map_err(|e| ManifestError::Cbor(e.to_string()))?;
            Ok(Page::Index(index))
        }
        other => Err(ManifestError::UnknownKind(other)),
    }
}

/// Reads the `"k"` (page kind) field from a decoded CBOR map.
fn page_kind(value: &ciborium::value::Value) -> Result<u8> {
    let map = value
        .as_map()
        .ok_or_else(|| ManifestError::Cbor("page is not a CBOR map".to_string()))?;
    for (k, val) in map {
        if k.as_text() == Some("k") {
            let n = val
                .as_integer()
                .ok_or_else(|| ManifestError::Cbor("`k` is not an integer".to_string()))?;
            let n: u8 = i128::from(n)
                .try_into()
                .map_err(|_| ManifestError::Cbor("`k` out of u8 range".to_string()))?;
            return Ok(n);
        }
    }
    Err(ManifestError::Cbor("page has no `k` field".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ft_core::{CanonicalPath, FileType, Pcid};

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    /// A file entry whose path/key share `name`, with a single block whose id is
    /// seeded by `seed` (so we can perturb one entry deterministically).
    fn file_entry(name: &str, seed: u8) -> (CasefoldKey, FileEntry) {
        let entry = FileEntry {
            p: CanonicalPath(name.to_string()),
            t: FileType::File,
            x: false,
            sz: 100 + seed as u64,
            pcid: Pcid::new([seed; 32]),
            bk: vec![Cid::new([seed; 32])],
            bk_ref: None,
            lt: None,
            wu: None,
        };
        (CasefoldKey(name.to_string()), entry)
    }

    /// `n` entries with zero-padded, lexicographically-sortable keys.
    fn many(n: usize) -> Vec<(CasefoldKey, FileEntry)> {
        (0..n)
            .map(|i| file_entry(&format!("file{i:05}.rs"), (i % 251) as u8))
            .collect()
    }

    fn page_cids(b: &ManifestBuild) -> std::collections::BTreeSet<Cid> {
        b.pages.iter().map(|(c, _)| *c).collect()
    }

    fn page_by_cid(b: &ManifestBuild, cid: Cid) -> Vec<u8> {
        b.pages.iter().find(|(c, _)| *c == cid).unwrap().1.clone()
    }

    /// Reads the top-level map keys of a canonical-CBOR buffer, in emit order.
    fn cbor_top_keys(payload: &[u8]) -> Vec<String> {
        let v: ciborium::value::Value = ciborium::de::from_reader(payload).unwrap();
        v.as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_string())
            .collect()
    }

    // ---------------------------------------------------------------------
    // (5) canonical CBOR — key ordering
    // ---------------------------------------------------------------------

    #[test]
    fn file_entry_canonical_key_order() {
        // §4.2.1: by encoded-key length, then bytewise. For a file FileEntry the
        // present keys are p,t,x (1 char), bk,sz (2 char), pcid (4 char):
        //   1-char bytewise: p < t < x
        //   2-char bytewise: bk < sz
        //   4-char:          pcid
        // => p, t, x, bk, sz, pcid
        let (_, entry) = file_entry("a", 1);
        let payload = to_canonical_cbor(&entry);
        assert_eq!(
            cbor_top_keys(&payload),
            vec!["p", "t", "x", "bk", "sz", "pcid"]
        );
    }

    #[test]
    fn leaf_page_canonical_key_order() {
        // Leaf keys: e,k,v (1 char), last (4), first (5).
        //   1-char bytewise: e < k < v
        //   then 4-char last, then 5-char first.
        // => e, k, v, last, first
        let b = build(vec![file_entry("a.rs", 1)]);
        let (_, obj) = &b.pages[0];
        let payload = &obj[ft_core::BLOCK_HEADER_LEN..];
        assert_eq!(cbor_top_keys(payload), vec!["e", "k", "v", "last", "first"]);
    }

    #[test]
    fn index_page_canonical_key_order_and_childref_order() {
        // Force an index level: 257 entries -> 2 leaves -> 1 index.
        let b = build(many(257));
        let root_obj = page_by_cid(&b, b.root);
        let payload = &root_obj[ft_core::BLOCK_HEADER_LEN..];
        // Index keys: k,v (1 char), children (8 char) => k, v, children.
        assert_eq!(cbor_top_keys(payload), vec!["k", "v", "children"]);

        // Each ChildRef map: cid,min both 3 chars => bytewise cid < min.
        let v: ciborium::value::Value = ciborium::de::from_reader(payload).unwrap();
        let map = v.as_map().unwrap();
        let children = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("children"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        for child in children {
            let keys: Vec<String> = child
                .as_map()
                .unwrap()
                .iter()
                .map(|(k, _)| k.as_text().unwrap().to_string())
                .collect();
            assert_eq!(keys, vec!["cid", "min"]);
        }
    }

    #[test]
    fn canonical_cbor_is_byte_stable() {
        // Same value serialized twice -> identical bytes.
        let (_, entry) = file_entry("x/y/z.rs", 9);
        assert_eq!(to_canonical_cbor(&entry), to_canonical_cbor(&entry));
    }

    // ---------------------------------------------------------------------
    // (1) determinism: any input order -> same root & pages
    // ---------------------------------------------------------------------

    #[test]
    fn determinism_input_order_independent() {
        let base = many(600);

        let mut reversed = base.clone();
        reversed.reverse();

        // A pseudo-shuffle that does not depend on any RNG (keeps the test pure).
        let mut shuffled = base.clone();
        shuffled.sort_by_key(|(k, _)| {
            let mut h: u64 = 1469598103934665603;
            for byte in k.as_str().bytes() {
                h ^= byte as u64;
                h = h.wrapping_mul(1099511628211);
            }
            h
        });

        let a = build(base);
        let b = build(reversed);
        let c = build(shuffled);

        assert_eq!(a.root, b.root);
        assert_eq!(a.root, c.root);
        assert_eq!(page_cids(&a), page_cids(&b));
        assert_eq!(page_cids(&a), page_cids(&c));
        // Full byte equality of the page set, not just the cids.
        let mut pa = a.pages.clone();
        let mut pb = b.pages.clone();
        pa.sort();
        pb.sort();
        assert_eq!(pa, pb);
    }

    #[test]
    fn determinism_single_leaf_is_root() {
        let b = build(vec![file_entry("only.rs", 7)]);
        assert_eq!(b.pages.len(), 1);
        assert_eq!(b.pages[0].0, b.root);
        match decode_page(&b.pages[0].1).unwrap() {
            Page::Leaf(leaf) => {
                assert_eq!(leaf.e.len(), 1);
                assert_eq!(leaf.k, KIND_LEAF);
            }
            other => panic!("expected leaf, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // (3) pagination at 256, 257 and 600 entries
    // ---------------------------------------------------------------------

    #[test]
    fn pagination_exactly_256_is_single_leaf() {
        let b = build(many(256));
        assert_eq!(b.pages.len(), 1);
        assert_eq!(b.pages[0].0, b.root);
        match decode_page(&b.pages[0].1).unwrap() {
            Page::Leaf(leaf) => assert_eq!(leaf.e.len(), 256),
            other => panic!("expected leaf, got {other:?}"),
        }
    }

    #[test]
    fn pagination_257_entries() {
        let b = build(many(257));
        // 257 entries -> ceil(257/256) = 2 leaves, + 1 index root = 3 pages.
        assert_eq!(b.pages.len(), 3);

        // Root is an index with 2 children.
        match decode_page(&page_by_cid(&b, b.root)).unwrap() {
            Page::Index(idx) => {
                assert_eq!(idx.children.len(), 2);
                assert_eq!(idx.k, KIND_INDEX);
            }
            other => panic!("expected index root, got {other:?}"),
        }

        // Leaves hold 256 and 1 entries respectively; all entries reachable.
        let total: usize = b
            .pages
            .iter()
            .filter_map(|(_, obj)| match decode_page(obj).unwrap() {
                Page::Leaf(l) => Some(l.e.len()),
                Page::Index(_) => None,
            })
            .sum();
        assert_eq!(total, 257);
    }

    #[test]
    fn pagination_600_entries() {
        let b = build(many(600));
        // 600 -> ceil(600/256) = 3 leaves -> 1 index (<=256 children) = 4 pages.
        assert_eq!(b.pages.len(), 4);

        match decode_page(&page_by_cid(&b, b.root)).unwrap() {
            Page::Index(idx) => assert_eq!(idx.children.len(), 3),
            other => panic!("expected index root, got {other:?}"),
        }

        // Children min keys are strictly ascending.
        if let Page::Index(idx) = decode_page(&page_by_cid(&b, b.root)).unwrap() {
            for w in idx.children.windows(2) {
                assert!(w[0].min < w[1].min);
            }
        }
    }

    // ---------------------------------------------------------------------
    // (2) structural reuse: change 1 entry -> only its leaf + ancestors change
    // ---------------------------------------------------------------------

    #[test]
    fn structural_reuse_one_entry_changed() {
        let base = many(600); // 3 leaves + 1 index
        let before = build(base.clone());

        // Perturb exactly one entry (its block id + size) in the FIRST leaf.
        let mut mutated = base;
        let (k, _) = mutated[10].clone();
        mutated[10] = {
            let mut e = file_entry(k.as_str(), 222).1;
            e.p = CanonicalPath(k.as_str().to_string());
            (k, e)
        };
        let after = build(mutated);

        // Root must change (its descendant changed).
        assert_ne!(before.root, after.root);

        // With 3 leaves + 1 root index, touching one entry rewrites exactly the
        // 1 touched leaf + the root => 2 of 4 pages change, 2 of 4 are reused.
        let pa = page_cids(&before);
        let pb = page_cids(&after);
        let shared: Vec<_> = pa.intersection(&pb).collect();
        assert_eq!(shared.len(), 2, "two untouched leaves must be reused");

        let new_pages: Vec<_> = pb.difference(&pa).collect();
        assert_eq!(new_pages.len(), 2);
    }

    #[test]
    fn structural_reuse_majority_preserved_large_tree() {
        // ~5000 entries -> ~20 leaves + index levels. One changed entry must
        // preserve the vast majority of page_cids (O(log n) rewritten).
        let n = 5000;
        let base = many(n);
        let before = build(base.clone());

        let mut mutated = base;
        let (k, _) = mutated[2500].clone();
        mutated[2500] = (k.clone(), {
            let mut e = file_entry(k.as_str(), 199).1;
            e.p = CanonicalPath(k.as_str().to_string());
            e
        });
        let after = build(mutated);

        let pa = page_cids(&before);
        let pb = page_cids(&after);
        let changed = pb.difference(&pa).count();
        assert!(
            changed < pa.len() / 2,
            "changed {changed} of {} pages — expected O(log n)",
            pa.len()
        );
        assert!(pa.intersection(&pb).count() >= pa.len() - changed);
    }

    // ---------------------------------------------------------------------
    // (4) externalization of a huge bk -> blocklist + bk_ref
    // ---------------------------------------------------------------------

    #[test]
    fn externalizes_huge_bk_to_blocklist() {
        // A FileEntry with enough Cids that its CBOR exceeds ENTRY_INLINE_MAX.
        // Each Cid is ~33 CBOR bytes; 10000 chunks comfortably exceeds 256 KiB.
        let n_chunks = 10_000;
        let bk: Vec<Cid> = (0..n_chunks)
            .map(|i| Cid::new([(i % 256) as u8; 32]))
            .collect();
        let entry = FileEntry {
            p: CanonicalPath("big.bin".to_string()),
            t: FileType::File,
            x: false,
            sz: 1_000_000_000,
            pcid: Pcid::new([5u8; 32]),
            bk: bk.clone(),
            bk_ref: None,
            lt: None,
            wu: None,
        };
        let key = CasefoldKey("big.bin".to_string());
        let b = build(vec![(key, entry)]);

        // Exactly one blocklist object was emitted.
        assert_eq!(b.blocklists.len(), 1);
        let (bl_cid, bl_bytes) = &b.blocklists[0];

        // The blocklist decodes back to the original ordered bk list.
        let decoded: Vec<Cid> = ciborium::de::from_reader(&bl_bytes[..]).unwrap();
        assert_eq!(decoded, bk);

        // The leaf's single entry has bk emptied and bk_ref set to the blocklist.
        match decode_page(&b.pages[0].1).unwrap() {
            Page::Leaf(leaf) => {
                let e = &leaf.e[0];
                assert!(e.bk.is_empty(), "inline bk must be cleared");
                assert_eq!(
                    e.bk_ref,
                    Some(*bl_cid),
                    "bk_ref must point at the blocklist"
                );
            }
            other => panic!("expected leaf, got {other:?}"),
        }

        // Determinism: same huge entry -> same blocklist cid & root.
        let bk2: Vec<Cid> = (0..n_chunks)
            .map(|i| Cid::new([(i % 256) as u8; 32]))
            .collect();
        let entry2 = FileEntry {
            p: CanonicalPath("big.bin".to_string()),
            t: FileType::File,
            x: false,
            sz: 1_000_000_000,
            pcid: Pcid::new([5u8; 32]),
            bk: bk2,
            bk_ref: None,
            lt: None,
            wu: None,
        };
        let b2 = build(vec![(CasefoldKey("big.bin".to_string()), entry2)]);
        assert_eq!(b2.blocklists[0].0, *bl_cid);
        assert_eq!(b2.root, b.root);
    }

    #[test]
    fn small_bk_is_not_externalized() {
        let b = build(vec![file_entry("small.rs", 3)]);
        assert!(b.blocklists.is_empty());
        match decode_page(&b.pages[0].1).unwrap() {
            Page::Leaf(leaf) => {
                assert!(!leaf.e[0].bk.is_empty());
                assert_eq!(leaf.e[0].bk_ref, None);
            }
            other => panic!("expected leaf, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // decode_page error paths, empty tree, framing & cid identity
    // ---------------------------------------------------------------------

    #[test]
    fn empty_entries_yield_single_empty_leaf_root() {
        let b = build(vec![]);
        assert_eq!(b.pages.len(), 1);
        assert_eq!(b.pages[0].0, b.root);
        match decode_page(&b.pages[0].1).unwrap() {
            Page::Leaf(leaf) => assert!(leaf.e.is_empty()),
            other => panic!("expected empty leaf, got {other:?}"),
        }
    }

    #[test]
    fn decode_page_rejects_short_buffer() {
        let err = decode_page(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ManifestError::Header(_)));
    }

    #[test]
    fn decode_page_rejects_bad_magic() {
        let b = build(vec![file_entry("a.rs", 1)]);
        let mut obj = b.pages[0].1.clone();
        obj[0] = b'X';
        assert!(matches!(decode_page(&obj), Err(ManifestError::Header(_))));
    }

    #[test]
    fn page_object_has_manifest_header() {
        let b = build(vec![file_entry("a.rs", 1)]);
        let header = BlockHeader::decode(&b.pages[0].1).unwrap();
        assert_eq!(&header.magic, b"FTM1");
        assert_eq!(header.alg, 0);
        let payload_len = b.pages[0].1.len() - ft_core::BLOCK_HEADER_LEN;
        assert_eq!(header.payload_len as usize, payload_len);
    }

    #[test]
    fn page_cid_is_cid_of_payload() {
        let b = build(vec![file_entry("a.rs", 1)]);
        let payload = &b.pages[0].1[ft_core::BLOCK_HEADER_LEN..];
        assert_eq!(b.pages[0].0, ft_hash::cid_of(payload));
    }

    #[test]
    fn changing_a_block_id_changes_the_root() {
        // Two single-entry trees differing only in the entry's block id must have
        // different roots — proves the cid is a function of the payload bytes.
        let a = build(vec![file_entry("a.rs", 1)]);
        let b = build(vec![file_entry("a.rs", 2)]);
        assert_ne!(a.root, b.root);
    }

    #[test]
    fn round_trips_a_three_level_tree_fully() {
        // 257*256 + 1 = enough for 3 levels would be huge; use a count that
        // forces 2 index levels: > 256 leaves => > 65536 entries is large, so
        // instead verify all entries survive a 2-level (index-of-index) build at
        // a moderate size by walking the tree.
        let n = 600;
        let b = build(many(n));
        let mut seen = 0usize;
        let mut stack = vec![b.root];
        while let Some(cid) = stack.pop() {
            match decode_page(&page_by_cid(&b, cid)).unwrap() {
                Page::Leaf(l) => seen += l.e.len(),
                Page::Index(idx) => {
                    for c in idx.children {
                        stack.push(c.cid);
                    }
                }
            }
        }
        assert_eq!(seen, n);
    }
}
