//! ft-index — local SQLite index per Device (`docs/format.md §9`).
//!
//! Persistence ONLY. Owns the exact §9 schema — `space_state`, `local_entry`
//! (with `idx_casefold` and `idx_pcid`), `local_block` and `dedup_local` — behind
//! a typed API built on `ft-core`'s vocabulary types ([`Cid`], [`Pcid`],
//! [`CanonicalPath`], [`CasefoldKey`], [`FileType`]).
//!
//! What this crate does:
//! - per-Space state ([`SpaceState`]): `last_synced_seq`/`last_synced_root`, the
//!   FastCDC `chunk_secret`, the optional Account `dedup_secret`, and the
//!   `local_root_path`;
//! - per-path entries ([`LocalEntry`]) keyed by `(space_id, path)`, with the
//!   ordered `{pcid, cid}` Block list of §9 stored CBOR-encoded in the `blocks`
//!   BLOB column;
//! - dedup lookup by `pcid` scoped to the Account (`dedup_local`, §1);
//! - casefold-collision queries via `idx_casefold` (§5.2);
//! - the set of locally-present Block [`Cid`]s (`local_block`).
//!
//! What this crate does NOT do (per `docs/BUILD-PLAN.md §3`): no sync, dedup,
//! conflict or re-scan LOGIC lives here — only the storage those subsystems read
//! and write. Schema is created with `CREATE TABLE IF NOT EXISTS` on open, so
//! opening an existing DB is a no-op migration.

use std::path::Path;

use ft_core::{CanonicalPath, CasefoldKey, Cid, FileType, Pcid};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors (one thiserror enum per crate; BUILD-PLAN §3)
// ---------------------------------------------------------------------------

/// Errors raised by the local index.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying SQLite failure (open, prepare, exec, row decode).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A foundation (`ft-core`) error surfaced while decoding a stored id.
    #[error("core error: {0}")]
    Core(#[from] ft_core::Error),

    /// The `blocks` BLOB column failed to CBOR-encode.
    #[error("failed to encode blocks blob: {0}")]
    EncodeBlocks(String),

    /// The `blocks` BLOB column failed to CBOR-decode.
    #[error("failed to decode blocks blob: {0}")]
    DecodeBlocks(String),

    /// A BLOB column holding a 32-byte id had the wrong length.
    #[error("invalid id blob length: expected 32 bytes, got {0}")]
    InvalidIdBlobLength(usize),

    /// A `type` column held a value that is not a valid [`FileType`].
    #[error("invalid FileType discriminant in row: {0}")]
    InvalidFileType(u8),
}

/// Crate-wide `Result` alias over the local index [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

/// Per-Space state on this Device (`space_state` table, §9).
///
/// Mirrors the columns one-to-one: `last_synced_seq`/`last_synced_root` are the
/// base Revision of the last sync (for the next diff), `chunk_secret` is the
/// local copy of the Space's FastCDC secret, `dedup_secret` is the Account dedup
/// secret (NULL in the cleartext MVP), and `local_root_path` is the folder mapped
/// to this Space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceState {
    /// Space identifier (primary key).
    pub space_id: String,
    /// `seq` of the base Revision of the last successful sync.
    pub last_synced_seq: i64,
    /// `manifestRootCid` of that base Revision (for diffing the next head).
    pub last_synced_root: Cid,
    /// Local copy of the Space's FastCDC chunk secret.
    pub chunk_secret: Vec<u8>,
    /// Local copy of the Account dedup secret. `None` in the cleartext MVP.
    pub dedup_secret: Option<Vec<u8>>,
    /// Absolute local folder mapped to this Space.
    pub local_root_path: String,
}

/// One ordered chunk Block reference inside a [`LocalEntry::blocks`] list (§9).
///
/// The list is stored CBOR-encoded in the `blocks` BLOB column. `pcid` is the
/// plaintext-content id of the chunk (dedup key), `cid` is its addressing id in
/// the Vault. In the MVP `cid == pcid` (cleartext) but they stay separate types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRef {
    /// Plaintext content id of the chunk (dedup key). `§5.1`/`§9` field `pcid`.
    pub pcid: Pcid,
    /// Addressing content id of the chunk's stored Block. `§9` field `cid`.
    pub cid: Cid,
}

/// One synced path on this Device (`local_entry` table, §9).
///
/// Keyed by `(space_id, path)`. The `pcid` is the whole-file plaintext content id
/// (dedup + echo-suppression + conflict detection) and is nullable in the schema
/// (e.g. derived/local-only rows), hence `Option`. `mtime` is the REAL FS mtime
/// after applying — used only to skip re-hashing on re-scan, NEVER for conflict
/// resolution (§9, §10). `base_seq` is the per-path base Revision for the 3-way
/// merge. `blocks` is the ordered `{pcid, cid}` chunk list (CBOR in the BLOB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEntry {
    /// Canonical Space-relative path (forward slash, NFC). The §9 `path` column.
    pub path: CanonicalPath,
    /// `casefold(NFC(path))` — case/NFC collision key (indexed by `idx_casefold`).
    pub casefold_key: CasefoldKey,
    /// File type (`0=file, 1=symlink, 2=derived`).
    pub file_type: FileType,
    /// Executable bit.
    pub exec: bool,
    /// Cleartext size in bytes.
    pub size: u64,
    /// REAL FS mtime after applying. Re-scan only; never used for conflicts.
    pub mtime: i64,
    /// Whole-file plaintext content id. `None` when not tracked (local-only).
    pub pcid: Option<Pcid>,
    /// Per-path base Revision `seq` for the 3-way merge (§10).
    pub base_seq: i64,
    /// Ordered chunk Block references; stored CBOR-encoded in the `blocks` BLOB.
    pub blocks: Vec<BlockRef>,
    /// `true` for a materialized symlink / non-synced derived path (§9).
    pub local_only: bool,
}

// ---------------------------------------------------------------------------
// Schema (docs/format.md §9 — verbatim, with CREATE TABLE IF NOT EXISTS)
// ---------------------------------------------------------------------------

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS space_state (
  space_id        TEXT PRIMARY KEY,
  last_synced_seq INTEGER NOT NULL,
  last_synced_root TEXT NOT NULL,
  chunk_secret    BLOB NOT NULL,
  dedup_secret    BLOB,
  local_root_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS local_entry (
  space_id     TEXT NOT NULL,
  path         TEXT NOT NULL,
  casefold_key TEXT NOT NULL,
  type         INTEGER NOT NULL,
  exec         INTEGER NOT NULL,
  size         INTEGER NOT NULL,
  mtime        INTEGER NOT NULL,
  pcid         BLOB,
  base_seq     INTEGER NOT NULL,
  blocks       BLOB,
  local_only   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (space_id, path)
);
CREATE INDEX IF NOT EXISTS idx_casefold ON local_entry(space_id, casefold_key);
CREATE INDEX IF NOT EXISTS idx_pcid     ON local_entry(space_id, pcid);

CREATE TABLE IF NOT EXISTS local_block (
  space_id TEXT NOT NULL,
  cid      BLOB NOT NULL,
  PRIMARY KEY (space_id, cid)
);

CREATE TABLE IF NOT EXISTS dedup_local (
  account_id TEXT NOT NULL,
  pcid       BLOB NOT NULL,
  cid        BLOB NOT NULL,
  PRIMARY KEY (account_id, pcid)
);
"#;

// ---------------------------------------------------------------------------
// Index
// ---------------------------------------------------------------------------

/// A Device's local index: a thin typed wrapper over a `rusqlite::Connection`
/// holding the §9 schema.
pub struct Index {
    conn: Connection,
}

impl Index {
    /// Opens (creating if absent) the local index at `path` and ensures the §9
    /// schema exists.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Opens an in-memory index (for tests) with the §9 schema applied.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Borrows the underlying connection (escape hatch for adjacent crates that
    /// need a read-only handle; this crate keeps all writes typed).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    // ---- space_state ----

    /// Inserts or replaces the [`SpaceState`] row for its `space_id`.
    pub fn upsert_space_state(&self, state: &SpaceState) -> Result<()> {
        self.conn.execute(
            "INSERT INTO space_state \
               (space_id, last_synced_seq, last_synced_root, chunk_secret, dedup_secret, local_root_path) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(space_id) DO UPDATE SET \
               last_synced_seq = excluded.last_synced_seq, \
               last_synced_root = excluded.last_synced_root, \
               chunk_secret = excluded.chunk_secret, \
               dedup_secret = excluded.dedup_secret, \
               local_root_path = excluded.local_root_path",
            params![
                state.space_id,
                state.last_synced_seq,
                state.last_synced_root.to_hex(),
                state.chunk_secret,
                state.dedup_secret,
                state.local_root_path,
            ],
        )?;
        Ok(())
    }

    /// Fetches the [`SpaceState`] for `space_id`, or `None` if absent.
    pub fn get_space_state(&self, space_id: &str) -> Result<Option<SpaceState>> {
        self.conn
            .query_row(
                "SELECT space_id, last_synced_seq, last_synced_root, chunk_secret, dedup_secret, local_root_path \
                 FROM space_state WHERE space_id = ?1",
                params![space_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(space_id, last_synced_seq, root_hex, chunk_secret, dedup_secret, local_root_path)| {
                    Ok(SpaceState {
                        space_id,
                        last_synced_seq,
                        last_synced_root: Cid::from_hex(&root_hex)?,
                        chunk_secret,
                        dedup_secret,
                        local_root_path,
                    })
                },
            )
            .transpose()
    }

    // ---- local_entry ----

    /// Inserts or replaces a [`LocalEntry`] for `(space_id, entry.path)`.
    pub fn upsert_entry(&self, space_id: &str, entry: &LocalEntry) -> Result<()> {
        let blocks_blob = encode_blocks(&entry.blocks)?;
        self.conn.execute(
            "INSERT INTO local_entry \
               (space_id, path, casefold_key, type, exec, size, mtime, pcid, base_seq, blocks, local_only) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
             ON CONFLICT(space_id, path) DO UPDATE SET \
               casefold_key = excluded.casefold_key, \
               type = excluded.type, \
               exec = excluded.exec, \
               size = excluded.size, \
               mtime = excluded.mtime, \
               pcid = excluded.pcid, \
               base_seq = excluded.base_seq, \
               blocks = excluded.blocks, \
               local_only = excluded.local_only",
            params![
                space_id,
                entry.path.as_str(),
                entry.casefold_key.as_str(),
                entry.file_type.as_u8() as i64,
                entry.exec as i64,
                entry.size as i64,
                entry.mtime,
                entry.pcid.map(|p| p.as_bytes().to_vec()),
                entry.base_seq,
                blocks_blob,
                entry.local_only as i64,
            ],
        )?;
        Ok(())
    }

    /// Fetches the [`LocalEntry`] at `(space_id, path)`, or `None` if absent.
    pub fn get_entry(&self, space_id: &str, path: &CanonicalPath) -> Result<Option<LocalEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, casefold_key, type, exec, size, mtime, pcid, base_seq, blocks, local_only \
             FROM local_entry WHERE space_id = ?1 AND path = ?2",
        )?;
        let mut rows = stmt.query(params![space_id, path.as_str()])?;
        match rows.next()? {
            Some(row) => Ok(Some(row_to_entry(row)?)),
            None => Ok(None),
        }
    }

    /// Deletes the entry at `(space_id, path)`. Returns the number of rows removed
    /// (`0` if it did not exist).
    pub fn delete_entry(&self, space_id: &str, path: &CanonicalPath) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM local_entry WHERE space_id = ?1 AND path = ?2",
            params![space_id, path.as_str()],
        )?;
        Ok(n)
    }

    /// Lists every entry for `space_id`, ordered by `casefold_key` (the §5.2 total
    /// order over paths).
    pub fn list_entries(&self, space_id: &str) -> Result<Vec<LocalEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, casefold_key, type, exec, size, mtime, pcid, base_seq, blocks, local_only \
             FROM local_entry WHERE space_id = ?1 ORDER BY casefold_key, path",
        )?;
        let mut rows = stmt.query(params![space_id])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(row_to_entry(row)?);
        }
        Ok(out)
    }

    /// Returns every entry in `space_id` sharing the given `casefold_key` — the
    /// cheap case/NFC collision probe of §5.2 (via `idx_casefold`). More than one
    /// result signals a collision the caller must treat as a conflict.
    pub fn find_by_casefold(&self, space_id: &str, key: &CasefoldKey) -> Result<Vec<LocalEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT path, casefold_key, type, exec, size, mtime, pcid, base_seq, blocks, local_only \
             FROM local_entry WHERE space_id = ?1 AND casefold_key = ?2 ORDER BY path",
        )?;
        let mut rows = stmt.query(params![space_id, key.as_str()])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(row_to_entry(row)?);
        }
        Ok(out)
    }

    // ---- dedup_local (scope = Account, §1) ----

    /// Looks up the addressing [`Cid`] already known for `pcid` in `account_id`,
    /// or `None`. NEVER crosses Accounts (the primary key is `(account_id, pcid)`).
    pub fn dedup_get(&self, account_id: &str, pcid: &Pcid) -> Result<Option<Cid>> {
        self.conn
            .query_row(
                "SELECT cid FROM dedup_local WHERE account_id = ?1 AND pcid = ?2",
                params![account_id, pcid.as_bytes().to_vec()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|bytes| cid_from_blob(&bytes))
            .transpose()
    }

    /// Records `pcid -> cid` in the Account-scoped dedup cache (insert or replace).
    pub fn dedup_put(&self, account_id: &str, pcid: &Pcid, cid: &Cid) -> Result<()> {
        self.conn.execute(
            "INSERT INTO dedup_local (account_id, pcid, cid) VALUES (?1, ?2, ?3) \
             ON CONFLICT(account_id, pcid) DO UPDATE SET cid = excluded.cid",
            params![
                account_id,
                pcid.as_bytes().to_vec(),
                cid.as_bytes().to_vec()
            ],
        )?;
        Ok(())
    }

    // ---- local_block ("what do I already have") ----

    /// Returns whether `cid`'s Block is recorded as present locally for `space_id`.
    pub fn has_block(&self, space_id: &str, cid: &Cid) -> Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM local_block WHERE space_id = ?1 AND cid = ?2",
                params![space_id, cid.as_bytes().to_vec()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Marks `cid`'s Block as present locally for `space_id` (idempotent).
    pub fn put_block(&self, space_id: &str, cid: &Cid) -> Result<()> {
        self.conn.execute(
            "INSERT INTO local_block (space_id, cid) VALUES (?1, ?2) \
             ON CONFLICT(space_id, cid) DO NOTHING",
            params![space_id, cid.as_bytes().to_vec()],
        )?;
        Ok(())
    }

    /// Lists every locally-present Block [`Cid`] for `space_id`.
    pub fn list_blocks(&self, space_id: &str) -> Result<Vec<Cid>> {
        let mut stmt = self
            .conn
            .prepare("SELECT cid FROM local_block WHERE space_id = ?1")?;
        let mut rows = stmt.query(params![space_id])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let bytes: Vec<u8> = row.get(0)?;
            out.push(cid_from_blob(&bytes)?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Row / blob helpers
// ---------------------------------------------------------------------------

/// Decodes a `local_entry` row into a [`LocalEntry`]. Column order MUST match the
/// `SELECT` lists above: path, casefold_key, type, exec, size, mtime, pcid,
/// base_seq, blocks, local_only.
fn row_to_entry(row: &rusqlite::Row<'_>) -> Result<LocalEntry> {
    let path: String = row.get(0)?;
    let casefold_key: String = row.get(1)?;
    let type_u8: i64 = row.get(2)?;
    let exec: i64 = row.get(3)?;
    let size: i64 = row.get(4)?;
    let mtime: i64 = row.get(5)?;
    let pcid_blob: Option<Vec<u8>> = row.get(6)?;
    let base_seq: i64 = row.get(7)?;
    let blocks_blob: Option<Vec<u8>> = row.get(8)?;
    let local_only: i64 = row.get(9)?;

    let file_type =
        FileType::from_u8(type_u8 as u8).map_err(|_| Error::InvalidFileType(type_u8 as u8))?;
    let pcid = match pcid_blob {
        Some(bytes) => Some(pcid_from_blob(&bytes)?),
        None => None,
    };
    let blocks = match blocks_blob {
        Some(bytes) => decode_blocks(&bytes)?,
        None => Vec::new(),
    };

    Ok(LocalEntry {
        path: CanonicalPath(path),
        casefold_key: CasefoldKey(casefold_key),
        file_type,
        exec: exec != 0,
        size: size as u64,
        mtime,
        pcid,
        base_seq,
        blocks,
        local_only: local_only != 0,
    })
}

/// CBOR-encodes the ordered `{pcid, cid}` Block list for the `blocks` BLOB column.
fn encode_blocks(blocks: &[BlockRef]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(blocks, &mut buf).map_err(|e| Error::EncodeBlocks(e.to_string()))?;
    Ok(buf)
}

/// CBOR-decodes the `blocks` BLOB column back into the ordered Block list.
fn decode_blocks(bytes: &[u8]) -> Result<Vec<BlockRef>> {
    ciborium::de::from_reader(bytes).map_err(|e| Error::DecodeBlocks(e.to_string()))
}

/// Converts a 32-byte BLOB into a [`Cid`], validating length.
fn cid_from_blob(bytes: &[u8]) -> Result<Cid> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidIdBlobLength(bytes.len()))?;
    Ok(Cid::new(arr))
}

/// Converts a 32-byte BLOB into a [`Pcid`], validating length.
fn pcid_from_blob(bytes: &[u8]) -> Result<Pcid> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidIdBlobLength(bytes.len()))?;
    Ok(Pcid::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> SpaceState {
        SpaceState {
            space_id: "space-1".to_string(),
            last_synced_seq: 42,
            last_synced_root: Cid::new([7u8; 32]),
            chunk_secret: vec![1, 2, 3, 4],
            dedup_secret: None,
            local_root_path: "/home/dev/space-1".to_string(),
        }
    }

    fn sample_entry(path: &str, casefold: &str) -> LocalEntry {
        LocalEntry {
            path: CanonicalPath(path.to_string()),
            casefold_key: CasefoldKey(casefold.to_string()),
            file_type: FileType::File,
            exec: true,
            size: 12873,
            mtime: 1_700_000_000,
            pcid: Some(Pcid::new([9u8; 32])),
            base_seq: 5,
            blocks: vec![
                BlockRef {
                    pcid: Pcid::new([1u8; 32]),
                    cid: Cid::new([1u8; 32]),
                },
                BlockRef {
                    pcid: Pcid::new([2u8; 32]),
                    cid: Cid::new([2u8; 32]),
                },
            ],
            local_only: false,
        }
    }

    // ----- open -----

    #[test]
    fn open_in_memory_creates_schema() {
        let idx = Index::open_in_memory().unwrap();
        // All four §9 tables must exist.
        let count: i64 = idx
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' \
                 AND name IN ('space_state','local_entry','local_block','dedup_local')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 4);
    }

    #[test]
    fn open_creates_the_two_local_entry_indexes() {
        let idx = Index::open_in_memory().unwrap();
        let count: i64 = idx
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' \
                 AND name IN ('idx_casefold','idx_pcid')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn open_on_disk_then_reopen_is_a_noop_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.sqlite");
        {
            let idx = Index::open(&path).unwrap();
            idx.upsert_space_state(&sample_state()).unwrap();
        }
        // Reopening must not error (CREATE TABLE IF NOT EXISTS) and must keep data.
        let idx2 = Index::open(&path).unwrap();
        let got = idx2.get_space_state("space-1").unwrap().unwrap();
        assert_eq!(got, sample_state());
    }

    // ----- space_state roundtrip -----

    #[test]
    fn space_state_roundtrip() {
        let idx = Index::open_in_memory().unwrap();
        let state = sample_state();
        idx.upsert_space_state(&state).unwrap();
        let got = idx.get_space_state("space-1").unwrap().unwrap();
        assert_eq!(got, state);
    }

    #[test]
    fn space_state_with_dedup_secret_roundtrip() {
        let idx = Index::open_in_memory().unwrap();
        let mut state = sample_state();
        state.dedup_secret = Some(vec![10, 20, 30]);
        idx.upsert_space_state(&state).unwrap();
        let got = idx.get_space_state("space-1").unwrap().unwrap();
        assert_eq!(got.dedup_secret, Some(vec![10, 20, 30]));
    }

    #[test]
    fn space_state_upsert_overwrites() {
        let idx = Index::open_in_memory().unwrap();
        idx.upsert_space_state(&sample_state()).unwrap();
        let mut updated = sample_state();
        updated.last_synced_seq = 99;
        updated.last_synced_root = Cid::new([0xFEu8; 32]);
        idx.upsert_space_state(&updated).unwrap();
        let got = idx.get_space_state("space-1").unwrap().unwrap();
        assert_eq!(got.last_synced_seq, 99);
        assert_eq!(got.last_synced_root, Cid::new([0xFEu8; 32]));
    }

    #[test]
    fn get_missing_space_state_is_none() {
        let idx = Index::open_in_memory().unwrap();
        assert!(idx.get_space_state("nope").unwrap().is_none());
    }

    // ----- local_entry roundtrip -----

    #[test]
    fn local_entry_roundtrip() {
        let idx = Index::open_in_memory().unwrap();
        let entry = sample_entry("src/main.rs", "src/main.rs");
        idx.upsert_entry("space-1", &entry).unwrap();
        let got = idx
            .get_entry("space-1", &CanonicalPath("src/main.rs".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(got, entry);
    }

    #[test]
    fn local_entry_with_null_pcid_and_empty_blocks() {
        let idx = Index::open_in_memory().unwrap();
        let entry = LocalEntry {
            path: CanonicalPath("node_modules".to_string()),
            casefold_key: CasefoldKey("node_modules".to_string()),
            file_type: FileType::Derived,
            exec: false,
            size: 0,
            mtime: 0,
            pcid: None,
            base_seq: 0,
            blocks: vec![],
            local_only: true,
        };
        idx.upsert_entry("space-1", &entry).unwrap();
        let got = idx
            .get_entry("space-1", &CanonicalPath("node_modules".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(got, entry);
        assert!(got.pcid.is_none());
        assert!(got.blocks.is_empty());
        assert!(got.local_only);
    }

    #[test]
    fn local_entry_symlink_roundtrip() {
        let idx = Index::open_in_memory().unwrap();
        let entry = LocalEntry {
            path: CanonicalPath("link".to_string()),
            casefold_key: CasefoldKey("link".to_string()),
            file_type: FileType::Symlink,
            exec: false,
            size: 0,
            mtime: 123,
            pcid: Some(Pcid::new([3u8; 32])),
            base_seq: 1,
            blocks: vec![],
            local_only: false,
        };
        idx.upsert_entry("space-1", &entry).unwrap();
        let got = idx
            .get_entry("space-1", &CanonicalPath("link".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(got.file_type, FileType::Symlink);
        assert_eq!(got, entry);
    }

    #[test]
    fn upsert_entry_overwrites_same_path() {
        let idx = Index::open_in_memory().unwrap();
        let mut entry = sample_entry("a.txt", "a.txt");
        idx.upsert_entry("space-1", &entry).unwrap();
        entry.size = 555;
        entry.mtime = 999;
        entry.blocks = vec![BlockRef {
            pcid: Pcid::new([4u8; 32]),
            cid: Cid::new([4u8; 32]),
        }];
        idx.upsert_entry("space-1", &entry).unwrap();
        let got = idx
            .get_entry("space-1", &CanonicalPath("a.txt".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(got.size, 555);
        assert_eq!(got.mtime, 999);
        assert_eq!(got.blocks.len(), 1);
        // Only one row for that path.
        let n: i64 = idx
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM local_entry WHERE space_id='space-1' AND path='a.txt'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn delete_entry_removes_row() {
        let idx = Index::open_in_memory().unwrap();
        let entry = sample_entry("gone.txt", "gone.txt");
        idx.upsert_entry("space-1", &entry).unwrap();
        let removed = idx
            .delete_entry("space-1", &CanonicalPath("gone.txt".to_string()))
            .unwrap();
        assert_eq!(removed, 1);
        assert!(idx
            .get_entry("space-1", &CanonicalPath("gone.txt".to_string()))
            .unwrap()
            .is_none());
        // Deleting again removes nothing.
        let removed2 = idx
            .delete_entry("space-1", &CanonicalPath("gone.txt".to_string()))
            .unwrap();
        assert_eq!(removed2, 0);
    }

    #[test]
    fn list_entries_is_scoped_and_ordered_by_casefold() {
        let idx = Index::open_in_memory().unwrap();
        idx.upsert_entry("space-1", &sample_entry("Zeta.txt", "zeta.txt"))
            .unwrap();
        idx.upsert_entry("space-1", &sample_entry("alpha.txt", "alpha.txt"))
            .unwrap();
        idx.upsert_entry("space-1", &sample_entry("Mid.txt", "mid.txt"))
            .unwrap();
        // A different Space must not leak in.
        idx.upsert_entry("space-2", &sample_entry("other.txt", "other.txt"))
            .unwrap();

        let entries = idx.list_entries("space-1").unwrap();
        let keys: Vec<&str> = entries.iter().map(|e| e.casefold_key.as_str()).collect();
        assert_eq!(keys, vec!["alpha.txt", "mid.txt", "zeta.txt"]);
        assert_eq!(idx.list_entries("space-2").unwrap().len(), 1);
    }

    // ----- find_by_casefold collision detection (§5.2) -----

    #[test]
    fn find_by_casefold_returns_collisions() {
        let idx = Index::open_in_memory().unwrap();
        // Two distinct paths that fold to the same key (case difference).
        idx.upsert_entry("space-1", &sample_entry("README.md", "readme.md"))
            .unwrap();
        idx.upsert_entry("space-1", &sample_entry("readme.md", "readme.md"))
            .unwrap();
        // Unrelated entry that must NOT match.
        idx.upsert_entry("space-1", &sample_entry("other.md", "other.md"))
            .unwrap();

        let hits = idx
            .find_by_casefold("space-1", &CasefoldKey("readme.md".to_string()))
            .unwrap();
        assert_eq!(hits.len(), 2, "both colliding paths must come back");
        let paths: Vec<&str> = hits.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"README.md"));
        assert!(paths.contains(&"readme.md"));
    }

    #[test]
    fn find_by_casefold_no_collision_returns_single() {
        let idx = Index::open_in_memory().unwrap();
        idx.upsert_entry("space-1", &sample_entry("unique.md", "unique.md"))
            .unwrap();
        let hits = idx
            .find_by_casefold("space-1", &CasefoldKey("unique.md".to_string()))
            .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn find_by_casefold_is_space_scoped() {
        let idx = Index::open_in_memory().unwrap();
        idx.upsert_entry("space-1", &sample_entry("a.md", "shared"))
            .unwrap();
        idx.upsert_entry("space-2", &sample_entry("b.md", "shared"))
            .unwrap();
        let hits = idx
            .find_by_casefold("space-1", &CasefoldKey("shared".to_string()))
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path.as_str(), "a.md");
    }

    // ----- dedup_local (scope = Account, §1) -----

    #[test]
    fn dedup_put_get_roundtrip() {
        let idx = Index::open_in_memory().unwrap();
        let pcid = Pcid::new([5u8; 32]);
        let cid = Cid::new([6u8; 32]);
        assert!(idx.dedup_get("acct-1", &pcid).unwrap().is_none());
        idx.dedup_put("acct-1", &pcid, &cid).unwrap();
        assert_eq!(idx.dedup_get("acct-1", &pcid).unwrap(), Some(cid));
    }

    #[test]
    fn dedup_is_scoped_to_account_never_cross_account() {
        let idx = Index::open_in_memory().unwrap();
        let pcid = Pcid::new([5u8; 32]);
        let cid = Cid::new([6u8; 32]);
        idx.dedup_put("acct-1", &pcid, &cid).unwrap();
        // Same pcid, different account -> miss.
        assert!(idx.dedup_get("acct-2", &pcid).unwrap().is_none());
    }

    #[test]
    fn dedup_put_overwrites_cid_for_same_pcid() {
        let idx = Index::open_in_memory().unwrap();
        let pcid = Pcid::new([5u8; 32]);
        idx.dedup_put("acct-1", &pcid, &Cid::new([1u8; 32]))
            .unwrap();
        idx.dedup_put("acct-1", &pcid, &Cid::new([2u8; 32]))
            .unwrap();
        assert_eq!(
            idx.dedup_get("acct-1", &pcid).unwrap(),
            Some(Cid::new([2u8; 32]))
        );
    }

    // ----- local_block -----

    #[test]
    fn has_block_put_block_roundtrip() {
        let idx = Index::open_in_memory().unwrap();
        let cid = Cid::new([8u8; 32]);
        assert!(!idx.has_block("space-1", &cid).unwrap());
        idx.put_block("space-1", &cid).unwrap();
        assert!(idx.has_block("space-1", &cid).unwrap());
    }

    #[test]
    fn put_block_is_idempotent() {
        let idx = Index::open_in_memory().unwrap();
        let cid = Cid::new([8u8; 32]);
        idx.put_block("space-1", &cid).unwrap();
        idx.put_block("space-1", &cid).unwrap();
        assert_eq!(idx.list_blocks("space-1").unwrap().len(), 1);
    }

    #[test]
    fn has_block_is_space_scoped() {
        let idx = Index::open_in_memory().unwrap();
        let cid = Cid::new([8u8; 32]);
        idx.put_block("space-1", &cid).unwrap();
        assert!(!idx.has_block("space-2", &cid).unwrap());
    }

    #[test]
    fn list_blocks_returns_all_present() {
        let idx = Index::open_in_memory().unwrap();
        idx.put_block("space-1", &Cid::new([1u8; 32])).unwrap();
        idx.put_block("space-1", &Cid::new([2u8; 32])).unwrap();
        idx.put_block("space-2", &Cid::new([3u8; 32])).unwrap();
        let mut got = idx.list_blocks("space-1").unwrap();
        got.sort();
        assert_eq!(got, vec![Cid::new([1u8; 32]), Cid::new([2u8; 32])]);
    }

    // ----- CBOR serialization of the `blocks` column -----

    #[test]
    fn blocks_blob_is_cbor_and_preserves_order() {
        // The ordered {pcid, cid} list must survive the BLOB roundtrip with order
        // intact (the order IS the file content, §5.1).
        let blocks = vec![
            BlockRef {
                pcid: Pcid::new([0xAA; 32]),
                cid: Cid::new([0x01; 32]),
            },
            BlockRef {
                pcid: Pcid::new([0xBB; 32]),
                cid: Cid::new([0x02; 32]),
            },
            BlockRef {
                pcid: Pcid::new([0xCC; 32]),
                cid: Cid::new([0x03; 32]),
            },
        ];
        let blob = encode_blocks(&blocks).unwrap();
        let back = decode_blocks(&blob).unwrap();
        assert_eq!(back, blocks);

        // Confirm it is genuine CBOR (decodes generically as an array of maps with
        // bytestring values for pcid/cid).
        let val: ciborium::value::Value = ciborium::de::from_reader(&blob[..]).unwrap();
        let arr = val.as_array().expect("blocks blob is a CBOR array");
        assert_eq!(arr.len(), 3);
        let first = arr[0].as_map().expect("each block is a CBOR map");
        for (_k, v) in first {
            assert!(v.as_bytes().is_some(), "pcid/cid serialize as bytestrings");
        }
    }

    #[test]
    fn blocks_blob_roundtrips_through_a_local_entry() {
        let idx = Index::open_in_memory().unwrap();
        let entry = sample_entry("file.bin", "file.bin");
        idx.upsert_entry("space-1", &entry).unwrap();
        let got = idx
            .get_entry("space-1", &CanonicalPath("file.bin".to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(got.blocks, entry.blocks);
        assert_eq!(got.blocks[0].pcid, Pcid::new([1u8; 32]));
        assert_eq!(got.blocks[1].cid, Cid::new([2u8; 32]));
    }

    // ----- defensive decode -----

    #[test]
    fn cid_from_blob_rejects_wrong_length() {
        assert!(matches!(
            cid_from_blob(&[0u8; 31]),
            Err(Error::InvalidIdBlobLength(31))
        ));
    }
}
