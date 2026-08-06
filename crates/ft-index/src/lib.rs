//! ft-index — local SQLite index per Device (`docs/format.md §9`).
//!
//! Persistence ONLY. Owns the exact §9 schema — `space_state`, `local_entry`
//! (with `idx_casefold` and `idx_pcid`), `local_block` and `dedup_local` — behind
//! a typed API built on `ft-core`'s vocabulary types ([`Cid`], [`Pcid`],
//! [`CanonicalPath`], [`CasefoldKey`], [`FileType`]).
//!
//! What this crate does:
//! - per-Space state ([`SpaceState`]): `last_synced_seq`/`last_synced_root`, the
//!   optional `last_synced_revision_id` (the head's Revision id, for the
//!   `behind?` check `§7`), the FastCDC `chunk_secret`, the optional Account
//!   `dedup_secret`, and the `local_root_path`;
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
//! opening an existing DB is a no-op migration. The one additive migration —
//! the `space_state.last_synced_revision_id` column — is applied with an
//! idempotent `ALTER TABLE ADD COLUMN` (see [`Index::init`]) because
//! `CREATE TABLE IF NOT EXISTS` never alters a table that already exists.
//!
//! Two processes share one file: the daemon holds the index open while a one-shot
//! `filething status`/`sync` opens the same path, so the connection runs in WAL
//! with a busy timeout ([`Index::init`]) and the batch writers take ONE
//! transaction. The schema shape is stamped in `PRAGMA user_version`
//! ([`SCHEMA_VERSION`]) so a DB written by a NEWER filething is refused loudly
//! instead of silently misread — `filething update` is manual, so two Devices on
//! different versions is normal.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

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

    /// The DB's stamped schema version is newer than this binary understands.
    /// Opening it anyway would read the §9 tables with the wrong shape, so the
    /// open is refused before ANY statement touches the file.
    #[error(
        "this Space's local index was written by a newer filething \
         (index schema v{found}, this build understands v{supported}); \
         run `filething update`"
    )]
    SchemaTooNew {
        /// Version found in `PRAGMA user_version`.
        found: i64,
        /// Highest version this binary can read ([`SCHEMA_VERSION`]).
        supported: i64,
    },
}

/// Crate-wide `Result` alias over the local index [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

/// Per-Space state on this Device (`space_state` table, §9).
///
/// Mirrors the columns one-to-one: `last_synced_seq`/`last_synced_root` are the
/// base Revision of the last sync (for the next diff), `last_synced_revision_id`
/// is that base Revision's id (the `expected_base` of the next commit's CAS and
/// the value `status` compares against the remote head, `§7`), `chunk_secret` is
/// the local copy of the Space's FastCDC secret, `dedup_secret` is the Account
/// dedup secret (NULL in the cleartext MVP), and `local_root_path` is the folder
/// mapped to this Space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceState {
    /// Space identifier (primary key).
    pub space_id: String,
    /// `seq` of the base Revision of the last successful sync.
    pub last_synced_seq: i64,
    /// `manifestRootCid` of that base Revision (for diffing the next head).
    pub last_synced_root: Cid,
    /// `RevisionId` of that base Revision, as the raw Convex id string. `None`
    /// when no base is committed yet (a fresh/just-cloned Space) or for a DB
    /// migrated before this column existed and not yet re-synced. Kept as
    /// `Option<String>` so `ft-index` stays decoupled from `ft-coordinator`'s
    /// `RevisionId`; the engine wraps/unwraps it (`§7`/`§9`).
    pub last_synced_revision_id: Option<String>,
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
  last_synced_revision_id TEXT,
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

/// Shape of the §9 schema this binary reads and writes, stamped in
/// `PRAGMA user_version`. Bump ONLY together with a migration step in
/// [`Index::init`].
///
/// `0` is not a version: SQLite reports it both for a brand-new file and for a DB
/// written by a filething from before the stamp existed (≤0.3.0). The §9 DDL is
/// idempotent, so it doubles as the `0 -> 1` migration for both.
pub const SCHEMA_VERSION: i64 = 1;

/// How long a write waits for a lock the OTHER process holds before giving up.
/// The daemon and a one-shot CLI command open the same file, so contention is
/// normal and must WAIT rather than surface `database is locked` to the user.
///
/// Longer than the 5 s `rusqlite` happens to install by default, on purpose:
/// [`Index::upsert_entries`] holds the write lock for a whole scan, which on a big
/// tree is seconds, and waiting out the daemon beats failing next to it. Set
/// explicitly so the behaviour is ours and not a default that could change.
const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// The one-row `local_entry` upsert, shared by [`Index::upsert_entry`] and
/// [`Index::upsert_entries`] so a batch write can never drift from a single one.
const UPSERT_ENTRY_SQL: &str = "INSERT INTO local_entry \
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
       local_only = excluded.local_only";

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
    ///
    /// Fails with [`Error::SchemaTooNew`] if the file was written by a newer
    /// filething.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        // The index holds every synced path NAME, so it must not be readable by
        // other users of the machine — same rule as the CLI's `credentials.json`.
        // Runs BEFORE `init` switches on WAL because SQLite derives the mode of the
        // `-wal`/`-shm` sidecars from the DB file's mode.
        #[cfg(unix)]
        restrict_to_owner(path);
        Self::init(conn)
    }

    /// Opens an in-memory index (for tests) with the §9 schema applied.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        // Only the busy timeout may precede the version gate: it is a per-CONNECTION
        // setting that writes nothing to the file, and the gate's own `PRAGMA
        // user_version` read must wait rather than fail if the other process holds
        // the lock.
        conn.busy_timeout(BUSY_TIMEOUT)?;

        // Version gate BEFORE any DDL, write, or FILE-FORMAT change: a DB stamped
        // by a newer filething may hold columns/tables this binary would
        // half-migrate or misread, so we do not touch it at all. That is why
        // `apply_pragmas` runs AFTER and not before: `journal_mode=WAL` is
        // PERSISTENT — it rewrites the header of the database file and spawns the
        // `-wal`/`-shm` sidecars — so applying it first would have modified the very
        // file this error claims to leave untouched (and, on a DB the newer build
        // deliberately kept in rollback-journal mode, changed its format behind its
        // back).
        let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if found > SCHEMA_VERSION {
            return Err(Error::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }

        // The version is accepted: now the connection can be configured for real.
        Self::apply_pragmas(&conn)?;

        conn.execute_batch(SCHEMA)?;
        // Additive migration: `CREATE TABLE IF NOT EXISTS` never touches a table
        // that already exists, so a DB created before `last_synced_revision_id`
        // existed would be missing that column. Add it idempotently — SQLite
        // raises a "duplicate column name" error if the column is already there
        // (fresh DBs, where the CREATE above made it), which we swallow. Any
        // OTHER SQLite error still propagates.
        if let Err(e) = conn.execute(
            "ALTER TABLE space_state ADD COLUMN last_synced_revision_id TEXT",
            [],
        ) {
            if !is_duplicate_column(&e) {
                return Err(e.into());
            }
        }

        // Everything above is the `0 -> 1` forward migration (fresh file OR a
        // pre-stamp DB), so stamping it now is what makes the gate meaningful next
        // time. A future v2 adds its own steps keyed off `found` — or fails as
        // loudly as the too-new case if it cannot migrate. Crashing between the
        // DDL and the stamp is benign: `found` stays 0 and the next open replays
        // the same idempotent statements.
        if found != SCHEMA_VERSION {
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        Ok(Self { conn })
    }

    /// Connection settings that must be in place before the first statement that
    /// reads or writes the `§9` tables — but AFTER the schema-version gate, since
    /// `journal_mode=WAL` is a persistent file-format change (see [`Self::init`]).
    /// The busy timeout is the one exception and is set by `init` itself, ahead of
    /// the gate's read; setting it again here is idempotent and keeps this function
    /// a complete description of the connection.
    ///
    /// WAL plus a busy timeout is what makes the daemon + one-shot-CLI pair work:
    /// WAL lets a reader run while the other process commits, and the timeout
    /// turns the remaining write-write overlap into a short WAIT instead of a raw
    /// `database is locked` error in the user's face. `synchronous=NORMAL` is the
    /// standard companion to WAL — a power loss can lose the last commits but
    /// never corrupt the file, and this index is a rebuildable cache of the FS +
    /// Coordinator (a lost tail only costs a re-scan).
    fn apply_pragmas(conn: &Connection) -> Result<()> {
        // First, so that everything after it — including the switch into WAL, which
        // wants a brief exclusive lock, and the DDL in `init` — waits rather than
        // failing when the other process got there first.
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // `PRAGMA journal_mode` RETURNS the resulting mode, so it must be queried,
        // not executed. An in-memory DB can only be `memory` and silently stays
        // there — nothing shares it, so that is fine.
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // The §9 schema declares no FOREIGN KEY today; enforcement is per
        // connection and OFF by default, so turning it on now means any future one
        // is enforced from its first release rather than silently ignored.
        conn.pragma_update(None, "foreign_keys", true)?;
        Ok(())
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
               (space_id, last_synced_seq, last_synced_root, last_synced_revision_id, chunk_secret, dedup_secret, local_root_path) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(space_id) DO UPDATE SET \
               last_synced_seq = excluded.last_synced_seq, \
               last_synced_root = excluded.last_synced_root, \
               last_synced_revision_id = excluded.last_synced_revision_id, \
               chunk_secret = excluded.chunk_secret, \
               dedup_secret = excluded.dedup_secret, \
               local_root_path = excluded.local_root_path",
            params![
                state.space_id,
                state.last_synced_seq,
                state.last_synced_root.to_hex(),
                state.last_synced_revision_id,
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
                "SELECT space_id, last_synced_seq, last_synced_root, last_synced_revision_id, chunk_secret, dedup_secret, local_root_path \
                 FROM space_state WHERE space_id = ?1",
                params![space_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(
                    space_id,
                    last_synced_seq,
                    root_hex,
                    last_synced_revision_id,
                    chunk_secret,
                    dedup_secret,
                    local_root_path,
                )| {
                    Ok(SpaceState {
                        space_id,
                        last_synced_seq,
                        last_synced_root: Cid::from_hex(&root_hex)?,
                        last_synced_revision_id,
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
        let mut stmt = self.conn.prepare_cached(UPSERT_ENTRY_SQL)?;
        upsert_entry_with(&mut stmt, space_id, entry)
    }

    /// Inserts or replaces MANY entries in one transaction — the shape a full scan
    /// or a pull's apply pass writes.
    ///
    /// One `upsert_entry` per row is one durable transaction (one fsync) per row,
    /// which dominates the cost of a large scan; batching makes it one. Also
    /// all-or-nothing: a scan that fails halfway leaves the previous consistent
    /// state rather than a half-written one, and the next scan redoes it.
    pub fn upsert_entries(&self, space_id: &str, entries: &[LocalEntry]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(UPSERT_ENTRY_SQL)?;
            for entry in entries {
                upsert_entry_with(&mut stmt, space_id, entry)?;
            }
        }
        tx.commit()?;
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
    //
    // ADVISORY cache, and today write-ONLY: `pull`/`commit` fill it but nothing in
    // the wired paths reads it back — commit deliberately does HEAD-before-PUT
    // instead, because GC can delete a Block this table still claims (ADR 0012 §4).
    // So a missing row only ever costs a HEAD or a re-download, never correctness,
    // which is what makes [`Index::prune_blocks`] safe. The table stays because it
    // is normative §9 and is what a future "what am I missing" pass would read.

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

    /// Marks many Blocks as present locally for `space_id` in ONE transaction —
    /// the shape a pull's apply pass and a commit's upload pass write (they loop
    /// over every Block of every changed file).
    pub fn put_blocks(&self, space_id: &str, cids: &[Cid]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO local_block (space_id, cid) VALUES (?1, ?2) \
                 ON CONFLICT(space_id, cid) DO NOTHING",
            )?;
            for cid in cids {
                stmt.execute(params![space_id, cid.as_bytes().to_vec()])?;
            }
        }
        tx.commit()?;
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

    /// Drops the `local_block` rows of `space_id` whose Block is referenced by no
    /// `local_entry` in that Space, returning how many went away.
    ///
    /// Nothing prunes this table otherwise, so it accumulates a row for every
    /// Block ever pulled or uploaded — including every superseded version of every
    /// rewritten file — for the life of the Space. Pruning is safe because the
    /// table is advisory (see the section note): dropping a row that a concurrent
    /// pull just added costs at most a re-download.
    ///
    /// Rows for OTHER Spaces are never touched (the key is `(space_id, cid)`).
    pub fn prune_blocks(&self, space_id: &str) -> Result<usize> {
        // Reads and deletes share one transaction so the "referenced" set and the
        // rows we judge against it come from the same snapshot.
        let tx = self.conn.unchecked_transaction()?;

        // The referenced set lives in the CBOR `blocks` BLOBs, which SQL cannot
        // look inside, so it has to be decoded here rather than expressed as a join.
        let mut referenced: HashSet<[u8; 32]> = HashSet::new();
        {
            let mut stmt = tx.prepare("SELECT blocks FROM local_entry WHERE space_id = ?1")?;
            let mut rows = stmt.query(params![space_id])?;
            while let Some(row) = rows.next()? {
                if let Some(bytes) = row.get::<_, Option<Vec<u8>>>(0)? {
                    for block in decode_blocks(&bytes)? {
                        referenced.insert(*block.cid.as_bytes());
                    }
                }
            }
        }

        let mut stale: Vec<Vec<u8>> = Vec::new();
        {
            let mut stmt = tx.prepare("SELECT cid FROM local_block WHERE space_id = ?1")?;
            let mut rows = stmt.query(params![space_id])?;
            while let Some(row) = rows.next()? {
                let bytes: Vec<u8> = row.get(0)?;
                // A wrong-length blob cannot match any BlockRef, so it is stale by
                // definition — pruning it also cleans up the corruption.
                let keep = <[u8; 32]>::try_from(&bytes[..])
                    .map(|arr| referenced.contains(&arr))
                    .unwrap_or(false);
                if !keep {
                    stale.push(bytes);
                }
            }
        }

        let mut removed = 0usize;
        {
            let mut stmt =
                tx.prepare_cached("DELETE FROM local_block WHERE space_id = ?1 AND cid = ?2")?;
            for cid in &stale {
                removed += stmt.execute(params![space_id, cid])?;
            }
        }
        tx.commit()?;
        Ok(removed)
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

/// Binds one [`LocalEntry`] to an already-prepared [`UPSERT_ENTRY_SQL`] statement.
/// Taking the statement lets the batch path prepare and bind once per transaction.
fn upsert_entry_with(
    stmt: &mut rusqlite::Statement<'_>,
    space_id: &str,
    entry: &LocalEntry,
) -> Result<()> {
    let blocks_blob = encode_blocks(&entry.blocks)?;
    stmt.execute(params![
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
    ])?;
    Ok(())
}

/// Restricts the index file to its owner (`0600`), overriding the `0644 & ~umask`
/// `Connection::open` would leave behind.
///
/// Best-effort on purpose: a Space can live on a volume with no POSIX modes
/// (exFAT, SMB), where `chmod` fails and where a mode could not protect anything
/// anyway — refusing to open the Space there would be a worse bug than the
/// permissive mode. The index is metadata (path names), not key material.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
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

/// `true` when `e` is the "duplicate column name" error SQLite raises from
/// `ALTER TABLE ... ADD COLUMN` when the column already exists. The C API
/// reports this as a generic `SQLITE_ERROR` (no dedicated extended code), so we
/// match on the message text — but ONLY that text, so any other failure of the
/// migration still surfaces. Lets the additive migration in [`Index::init`] run
/// unconditionally on both fresh DBs (column already created) and old ones.
fn is_duplicate_column(e: &rusqlite::Error) -> bool {
    e.to_string().contains("duplicate column name")
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
            last_synced_revision_id: Some("rev-abc123".to_string()),
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

    fn user_version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
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

    #[test]
    fn migration_adds_revision_id_column_to_a_pre_migration_db() {
        // Simulate a DB created BEFORE `last_synced_revision_id` existed: the old
        // `space_state` shape with a row already in it. Then open it through the
        // normal path and confirm the additive ALTER TABLE runs (no "duplicate
        // column" panic), the column reads NULL as `None`, and re-syncing writes
        // a real id. This is the `~/.filething-{mac,vps}` upgrade case.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE space_state (
                   space_id        TEXT PRIMARY KEY,
                   last_synced_seq INTEGER NOT NULL,
                   last_synced_root TEXT NOT NULL,
                   chunk_secret    BLOB NOT NULL,
                   dedup_secret    BLOB,
                   local_root_path TEXT NOT NULL
                 );",
            )
            .unwrap();
            // `last_synced_root` is a 32-byte Cid hex (64 chars), as the real
            // schema stores it.
            let root_hex = Cid::new([7u8; 32]).to_hex();
            conn.execute(
                "INSERT INTO space_state \
                   (space_id, last_synced_seq, last_synced_root, chunk_secret, dedup_secret, local_root_path) \
                 VALUES ('space-1', 7, ?1, x'0102', NULL, '/tmp/space-1')",
                params![root_hex],
            )
            .unwrap();
        }

        // Opening migrates the schema in place and must not error.
        let idx = Index::open(&path).unwrap();
        let got = idx.get_space_state("space-1").unwrap().unwrap();
        // The pre-existing row's new column is NULL -> None.
        assert_eq!(got.last_synced_revision_id, None);
        assert_eq!(got.last_synced_seq, 7);

        // A subsequent sync writes a real id into the migrated column.
        let mut updated = got;
        updated.last_synced_revision_id = Some("rev-after-migration".to_string());
        idx.upsert_space_state(&updated).unwrap();
        let reread = idx.get_space_state("space-1").unwrap().unwrap();
        assert_eq!(
            reread.last_synced_revision_id,
            Some("rev-after-migration".to_string())
        );

        // Reopening the (now-migrated) DB must still be a no-op — the ALTER is
        // swallowed because the column already exists.
        drop(idx);
        let idx2 = Index::open(&path).unwrap();
        assert_eq!(
            idx2.get_space_state("space-1")
                .unwrap()
                .unwrap()
                .last_synced_revision_id,
            Some("rev-after-migration".to_string())
        );
    }

    // ----- concurrency, durability and permissions of the open connection -----

    #[test]
    fn open_on_disk_uses_wal_a_busy_timeout_and_synchronous_normal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.sqlite");
        let idx = Index::open(&path).unwrap();
        let conn = idx.connection();

        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal", "daemon + CLI need reader/writer concurrency");
        // Ours, not the 5000 `rusqlite` installs by default.
        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(timeout, BUSY_TIMEOUT.as_millis() as i64);
        // 1 = NORMAL.
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(synchronous, 1);
        let foreign_keys: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
    }

    #[test]
    fn a_second_writer_waits_for_the_lock_instead_of_failing_with_database_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.sqlite");
        let held = Index::open(&path).unwrap();
        // Take and HOLD the write lock, the way the daemon does mid-scan.
        let tx = held.connection().unchecked_transaction().unwrap();
        held.upsert_entry("space-1", &sample_entry("held.txt", "held.txt"))
            .unwrap();

        // The other process (a one-shot `filething sync`) writes meanwhile.
        let other_path = path.clone();
        let other = std::thread::spawn(move || {
            let idx = Index::open(&other_path).unwrap();
            idx.upsert_entry("space-1", &sample_entry("waited.txt", "waited.txt"))
        });

        // Long enough for it to hit the lock and start waiting on it.
        std::thread::sleep(Duration::from_millis(250));
        tx.commit().unwrap();

        other
            .join()
            .unwrap()
            .expect("the second writer must WAIT for the lock, not surface `database is locked`");
        assert!(held
            .get_entry("space-1", &CanonicalPath("waited.txt".to_string()))
            .unwrap()
            .is_some());
    }

    #[cfg(unix)]
    #[test]
    fn the_index_file_and_its_wal_sidecar_are_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.sqlite");
        let idx = Index::open(&path).unwrap();
        // A committed write forces the `-wal` sidecar into existence.
        idx.upsert_space_state(&sample_state()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "index holds every synced path name, got {mode:o}"
        );
        let wal = dir.path().join("index.sqlite-wal");
        let wal_mode = std::fs::metadata(&wal).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            wal_mode & 0o077,
            0,
            "the -wal sidecar holds the same names, got {wal_mode:o}"
        );
    }

    // ----- schema version gate (§9) -----

    #[test]
    fn a_fresh_database_is_stamped_with_the_current_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.sqlite");
        let idx = Index::open(&path).unwrap();
        assert_eq!(user_version(idx.connection()), SCHEMA_VERSION);
    }

    #[test]
    fn opening_an_index_stamped_by_a_newer_filething_fails_without_touching_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 7)
                .unwrap();
        }
        // The mode the newer build left the file in. `journal_mode` is PERSISTENT
        // (it lives in the file header), so this is part of the file's state.
        let mode_before: String = {
            let conn = Connection::open(&path).unwrap();
            conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(mode_before, "delete", "sanity: a fresh DB is not in WAL");

        let err = match Index::open(&path) {
            Ok(_) => panic!("a too-new index must not open"),
            Err(e) => e,
        };
        assert!(
            matches!(&err, Error::SchemaTooNew { found, supported }
                if *found == SCHEMA_VERSION + 7 && *supported == SCHEMA_VERSION),
            "{err:?}"
        );
        // The message must tell the user what to DO about it.
        assert!(err.to_string().contains("filething update"), "{err}");

        // And the newer DB must be left exactly as it was: no §9 table created
        // under it, no re-stamp — and no FILE-FORMAT change either. Switching the
        // journal mode to WAL rewrites the file header and creates the `-wal`/`-shm`
        // sidecars, so doing it before the gate would modify the very file this
        // error promises not to touch.
        let conn = Connection::open(&path).unwrap();
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
        assert_eq!(user_version(&conn), SCHEMA_VERSION + 7);
        let mode_after: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            mode_after, mode_before,
            "the refused DB's journal mode must be untouched"
        );
        assert!(
            !path.with_extension("sqlite-wal").exists(),
            "a refused open must not leave a -wal sidecar behind"
        );
    }

    #[test]
    fn an_unversioned_database_is_migrated_forward_and_stamped_without_losing_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unstamped.sqlite");
        {
            // What a ≤0.3.0 binary leaves behind: the right shape, no stamp.
            let idx = Index::open(&path).unwrap();
            idx.upsert_space_state(&sample_state()).unwrap();
            idx.upsert_entry("space-1", &sample_entry("kept.txt", "kept.txt"))
                .unwrap();
            idx.connection()
                .pragma_update(None, "user_version", 0)
                .unwrap();
        }

        let idx = Index::open(&path).unwrap();
        assert_eq!(user_version(idx.connection()), SCHEMA_VERSION);
        assert_eq!(
            idx.get_space_state("space-1").unwrap().unwrap(),
            sample_state()
        );
        assert_eq!(idx.list_entries("space-1").unwrap().len(), 1);
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
    fn space_state_revision_id_roundtrips_some_and_none() {
        let idx = Index::open_in_memory().unwrap();
        // Some(...) survives the roundtrip.
        let mut state = sample_state();
        state.last_synced_revision_id = Some("rev-XYZ".to_string());
        idx.upsert_space_state(&state).unwrap();
        let got = idx.get_space_state("space-1").unwrap().unwrap();
        assert_eq!(got.last_synced_revision_id, Some("rev-XYZ".to_string()));
        assert_eq!(got, state);

        // None (the fresh/just-cloned convention) round-trips and OVERWRITES the
        // previous Some — the upsert must null the column, not leave it stale.
        state.last_synced_revision_id = None;
        idx.upsert_space_state(&state).unwrap();
        let got = idx.get_space_state("space-1").unwrap().unwrap();
        assert_eq!(got.last_synced_revision_id, None);
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
    fn upsert_entries_writes_every_row_of_the_batch() {
        let idx = Index::open_in_memory().unwrap();
        let batch = vec![
            sample_entry("a.txt", "a.txt"),
            sample_entry("b.txt", "b.txt"),
            sample_entry("c.txt", "c.txt"),
        ];
        idx.upsert_entries("space-1", &batch).unwrap();
        assert_eq!(idx.list_entries("space-1").unwrap(), batch);

        // Re-running the batch upserts (as a re-scan does) instead of failing on
        // the primary key.
        let mut again = batch.clone();
        again[1].size = 4242;
        idx.upsert_entries("space-1", &again).unwrap();
        assert_eq!(idx.list_entries("space-1").unwrap().len(), 3);
        assert_eq!(
            idx.get_entry("space-1", &CanonicalPath("b.txt".to_string()))
                .unwrap()
                .unwrap()
                .size,
            4242
        );

        // An empty batch is a no-op, not an error (a scan with no changes).
        idx.upsert_entries("space-1", &[]).unwrap();
        assert_eq!(idx.list_entries("space-1").unwrap().len(), 3);
    }

    #[test]
    fn upsert_entries_rolls_back_the_whole_batch_when_one_row_fails() {
        let idx = Index::open_in_memory().unwrap();
        // Two paths sharing a casefold_key is LEGAL in §9 (that is the collision
        // case), so make it illegal for this test only to get a mid-batch failure.
        idx.connection()
            .execute_batch(
                "CREATE UNIQUE INDEX tmp_unique_casefold ON local_entry(space_id, casefold_key)",
            )
            .unwrap();

        let batch = vec![
            sample_entry("ok.txt", "ok.txt"),
            sample_entry("README.md", "readme.md"),
            sample_entry("readme.md", "readme.md"),
        ];
        assert!(idx.upsert_entries("space-1", &batch).is_err());
        // One transaction ⇒ the rows written before the failure went with it.
        assert!(idx.list_entries("space-1").unwrap().is_empty());
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

    #[test]
    fn put_blocks_marks_every_block_present_and_is_idempotent() {
        let idx = Index::open_in_memory().unwrap();
        let cids = [
            Cid::new([1u8; 32]),
            Cid::new([2u8; 32]),
            Cid::new([3u8; 32]),
        ];
        idx.put_blocks("space-1", &cids).unwrap();
        idx.put_blocks("space-1", &cids).unwrap();
        let mut got = idx.list_blocks("space-1").unwrap();
        got.sort();
        assert_eq!(got, cids.to_vec());
        assert!(!idx.has_block("space-2", &cids[0]).unwrap());
        idx.put_blocks("space-1", &[]).unwrap();
        assert_eq!(idx.list_blocks("space-1").unwrap().len(), 3);
    }

    #[test]
    fn prune_blocks_drops_only_the_blocks_no_entry_references() {
        let idx = Index::open_in_memory().unwrap();
        // `sample_entry` references Blocks 1 and 2; 0xEE is left over from a
        // superseded version of some file.
        idx.upsert_entry("space-1", &sample_entry("kept.bin", "kept.bin"))
            .unwrap();
        idx.put_blocks(
            "space-1",
            &[
                Cid::new([1u8; 32]),
                Cid::new([2u8; 32]),
                Cid::new([0xEE; 32]),
            ],
        )
        .unwrap();
        // Another Space's rows are off limits even for the same cid.
        idx.put_block("space-2", &Cid::new([0xEE; 32])).unwrap();

        assert_eq!(idx.prune_blocks("space-1").unwrap(), 1);
        let mut got = idx.list_blocks("space-1").unwrap();
        got.sort();
        assert_eq!(got, vec![Cid::new([1u8; 32]), Cid::new([2u8; 32])]);
        assert!(idx.has_block("space-2", &Cid::new([0xEE; 32])).unwrap());
        // Nothing left to reclaim on a second pass.
        assert_eq!(idx.prune_blocks("space-1").unwrap(), 0);
    }

    #[test]
    fn prune_blocks_reclaims_the_rows_of_a_deleted_entry() {
        let idx = Index::open_in_memory().unwrap();
        idx.upsert_entry("space-1", &sample_entry("gone.bin", "gone.bin"))
            .unwrap();
        idx.put_blocks("space-1", &[Cid::new([1u8; 32]), Cid::new([2u8; 32])])
            .unwrap();
        idx.delete_entry("space-1", &CanonicalPath("gone.bin".to_string()))
            .unwrap();
        assert_eq!(idx.prune_blocks("space-1").unwrap(), 2);
        assert!(idx.list_blocks("space-1").unwrap().is_empty());
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
