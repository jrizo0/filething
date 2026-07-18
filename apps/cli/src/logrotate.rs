//! `logrotate` — a tiny size-based rotating file writer for the daemon's log
//! (GitHub #22: `daemon.log` grew to 2.6 MB / 64k lines in days because macOS
//! launchd redirected the daemon's stderr to one unrotated file).
//!
//! On macOS the daemon now OWNS its log file (rather than letting launchd append
//! forever) and rotates it here: at most `max_bytes` per file, keeping `keep`
//! generations (`daemon.log`, `daemon.log.1`, … `daemon.log.{keep-1}`). Linux
//! keeps using journald, which rotates itself, so this only kicks in under
//! launchd or when `FILETHING_LOG_TO_FILE` is set (see [`crate::main`]).
//!
//! The writer is deliberately best-effort: a failed rotation (unlinkable backup,
//! un-renamable live file, …) must never panic or kill the daemon, so it degrades
//! to appending to the current file and tries again on the next write.
//!
//! [`SharedRotatingWriter`] wraps it in an `Arc<Mutex<…>>` and implements
//! `tracing_subscriber::fmt::MakeWriter`, so the daemon's fmt subscriber can write
//! through it directly.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// A file writer that rotates the target path once a write would push it past
/// `max_bytes`, keeping `keep` total generations (the live file plus `keep - 1`
/// numbered backups). Tracks the live file's size so rotation needs no `stat` per
/// write; the size is seeded from the file's metadata at open, so reopening an
/// existing log continues appending rather than starting the count at zero.
pub struct RotatingFileWriter {
    /// The live log path (backups are this path with `.1`, `.2`, … appended).
    path: PathBuf,
    /// Rotate before a write that would take the live file past this many bytes.
    max_bytes: u64,
    /// Total generations to keep, including the live file. `3` ⇒ live + `.1` + `.2`.
    keep: usize,
    /// The currently-open live file (append mode).
    file: File,
    /// Bytes in the live file: metadata length at open plus everything written
    /// since. Reset to zero after a successful rotation.
    current_size: u64,
}

impl RotatingFileWriter {
    /// Open (creating if needed) `path` for appending, seeding the tracked size
    /// from its current length so an existing log keeps growing from where it was
    /// rather than being treated as empty.
    pub fn new(path: PathBuf, max_bytes: u64, keep: usize) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let current_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            max_bytes,
            keep: keep.max(1),
            file,
            current_size,
        })
    }

    /// `self.path` with `.{n}` appended, e.g. `daemon.log` → `daemon.log.1`.
    fn indexed_path(&self, n: usize) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    /// Shift the generations down and start a fresh live file: delete the oldest
    /// backup (`.{keep-1}`), rename `.{i}` → `.{i+1}` down to `live` → `.1`, then
    /// recreate the live file empty. With `keep == 1` there are no backups, so
    /// this just removes and recreates the live file (dropping its old contents).
    ///
    /// Returns `Err` on the first IO failure; callers treat that as "keep
    /// appending to the current file" — no data is lost, the file just grows past
    /// the limit until a later rotation succeeds.
    fn rotate(&mut self) -> io::Result<()> {
        // Flush anything buffered into the live file before we move it.
        let _ = self.file.flush();

        if self.keep >= 2 {
            // Drop the oldest backup (missing is fine — first rotations have none).
            let oldest = self.indexed_path(self.keep - 1);
            match std::fs::remove_file(&oldest) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            // Shift the surviving backups down: .{i} -> .{i+1}, highest first.
            for i in (1..self.keep - 1).rev() {
                let from = self.indexed_path(i);
                if from.exists() {
                    std::fs::rename(&from, self.indexed_path(i + 1))?;
                }
            }
            // The live file becomes .1. A missing live file is fine (someone
            // deleted it externally while we held the old inode open): skip the
            // rename and just recreate it below — otherwise this rotation would
            // fail `NotFound` forever and the daemon would keep appending to the
            // deleted, invisible inode.
            match std::fs::rename(&self.path, self.indexed_path(1)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        } else {
            // keep == 1: no backups — drop the old contents so the fresh open
            // below starts an empty file. (append+truncate is an invalid
            // OpenOptions combination, so remove instead of truncating.)
            match std::fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }

        // Fresh, empty live file (the path is gone by now in every branch), in
        // append mode like the initial open.
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.current_size = 0;
        Ok(())
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Rotate only a non-empty file: a single write larger than `max_bytes`
        // would otherwise rotate forever without ever making progress.
        if self.current_size > 0
            && self.current_size.saturating_add(buf.len() as u64) > self.max_bytes
        {
            // Best effort: a failed rotation degrades to appending, never panics.
            let _ = self.rotate();
        }
        let n = self.file.write(buf)?;
        self.current_size = self.current_size.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// A cheaply-clonable handle around a [`RotatingFileWriter`] that implements both
/// `io::Write` (by locking) and `tracing_subscriber`'s `MakeWriter`, so it can be
/// handed straight to `fmt().with_writer(…)`. A poisoned lock is recovered rather
/// than propagated — a logging mutex must never take the daemon down.
#[derive(Clone)]
pub struct SharedRotatingWriter(Arc<Mutex<RotatingFileWriter>>);

impl SharedRotatingWriter {
    pub fn new(writer: RotatingFileWriter) -> Self {
        Self(Arc::new(Mutex::new(writer)))
    }
}

impl Write for SharedRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedRotatingWriter {
    type Writer = SharedRotatingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    fn read(path: &std::path::Path) -> String {
        let mut s = String::new();
        File::open(path).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    /// Test-only helper mirroring [`RotatingFileWriter::indexed_path`] for assertions.
    fn indexed(path: &std::path::Path, n: usize) -> PathBuf {
        let mut s = path.to_path_buf().into_os_string();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    /// Writes that stay under the limit all land in the live file; no backups appear.
    #[test]
    fn writes_below_limit_stay_in_live_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let mut w = RotatingFileWriter::new(path.clone(), 1024, 3).unwrap();
        w.write_all(b"hello ").unwrap();
        w.write_all(b"world").unwrap();
        w.flush().unwrap();
        assert_eq!(read(&path), "hello world");
        assert!(!indexed(&path, 1).exists());
    }

    /// Crossing the limit rotates: the live file's old contents move to `.1` and
    /// the new write starts a fresh live file.
    #[test]
    fn crossing_limit_rotates_old_content_to_dot_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let mut w = RotatingFileWriter::new(path.clone(), 10, 3).unwrap();
        w.write_all(b"aaaaaaaa").unwrap(); // 8 bytes, under 10
        w.write_all(b"bbbb").unwrap(); // would reach 12 > 10 -> rotate first
        w.flush().unwrap();
        let backup = indexed(&path, 1);
        assert_eq!(read(&backup), "aaaaaaaa", "old content lands in .1");
        assert_eq!(read(&path), "bbbb", "new write starts a fresh live file");
    }

    /// With keep = 3, a fourth generation deletes the oldest (`.2`): only the live
    /// file, `.1`, and `.2` survive, holding the three most recent generations.
    #[test]
    fn keep_three_drops_oldest_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let mut w = RotatingFileWriter::new(path.clone(), 4, 3).unwrap();
        // Each 4-byte write fills the file; the next write rotates first.
        w.write_all(b"g0__").unwrap(); // live = g0
        w.write_all(b"g1__").unwrap(); // rotate: .1=g0, live=g1
        w.write_all(b"g2__").unwrap(); // rotate: .2=g0, .1=g1, live=g2
        w.write_all(b"g3__").unwrap(); // rotate: drop old .2(g0); .2=g1, .1=g2, live=g3
        w.flush().unwrap();
        assert_eq!(read(&path), "g3__");
        assert_eq!(read(&indexed(&path, 1)), "g2__");
        assert_eq!(read(&indexed(&path, 2)), "g1__");
        // The oldest generation (g0) was dropped: no .3 exists.
        assert!(!indexed(&path, 3).exists());
    }

    /// Reopening an existing file continues appending and counts the bytes already
    /// on disk, so the size threshold accounts for pre-existing content.
    #[test]
    fn reopen_continues_appending_and_counts_existing_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        {
            let mut w = RotatingFileWriter::new(path.clone(), 10, 3).unwrap();
            w.write_all(b"aaaaaaaa").unwrap(); // 8 bytes
            w.flush().unwrap();
        }
        // Reopen: existing size is 8, so a 4-byte write (would reach 12 > 10) rotates.
        let mut w = RotatingFileWriter::new(path.clone(), 10, 3).unwrap();
        w.write_all(b"bbbb").unwrap();
        w.flush().unwrap();
        assert_eq!(read(&indexed(&path, 1)), "aaaaaaaa");
        assert_eq!(read(&path), "bbbb");
    }

    /// A single write larger than `max_bytes` on an EMPTY live file goes straight
    /// through without rotating (rotating first would loop forever making no
    /// progress); the next write then rotates the oversized file away.
    #[test]
    fn oversized_single_write_lands_then_rotates_next() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let mut w = RotatingFileWriter::new(path.clone(), 4, 3).unwrap();
        w.write_all(b"oversized-line").unwrap(); // 14 bytes > 4: no rotation loop
        w.flush().unwrap();
        assert_eq!(read(&path), "oversized-line");
        assert!(!indexed(&path, 1).exists());
        w.write_all(b"next").unwrap(); // over the limit now: rotates first
        w.flush().unwrap();
        assert_eq!(read(&indexed(&path, 1)), "oversized-line");
        assert_eq!(read(&path), "next");
    }

    /// REGRESSION: if the live file is deleted externally while the writer holds
    /// its inode open, rotation must still succeed (skip the rename of the
    /// now-missing path and recreate a fresh live file) — not fail `NotFound`
    /// forever while the daemon appends to an invisible deleted inode.
    #[test]
    fn external_deletion_of_live_file_recovers_on_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let mut w = RotatingFileWriter::new(path.clone(), 4, 3).unwrap();
        w.write_all(b"old_").unwrap(); // fills the live file to the limit
        w.flush().unwrap();
        std::fs::remove_file(&path).unwrap(); // an external `rm daemon.log`
        w.write_all(b"new_").unwrap(); // triggers rotation: must recreate the path
        w.flush().unwrap();
        assert_eq!(read(&path), "new_", "the live path must reappear on disk");
        assert!(
            !indexed(&path, 1).exists(),
            "nothing to back up — the old live file was deleted externally"
        );
    }
}
