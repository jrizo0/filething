//! A compact, single-line progress renderer for one-shot commands (issue #16).
//!
//! The engine reports upload/download progress as INFO tracing events that carry
//! a `total` field (and, on periodic updates, a `completed` one). One-shot
//! commands run with those internal targets silenced (WARN, see `main.rs`), which
//! would also hide the progress a human genuinely wants during `init`/`clone`/
//! `sync`. This tracing [`Layer`] re-renders just those events as ONE rewriting
//! line on stderr — `uploading blocks 150/291` — instead of a log line per batch.
//!
//! It is purely presentational and never load-bearing: it reads the same events
//! the fmt layer would, matched by their (stable, in-repo) messages. If the
//! engine ever stops emitting them the line simply never appears — nothing breaks.
//! The layer is installed (by `main`) only when stderr is a TTY and the run is
//! neither verbose nor driven by an explicit `RUST_LOG`.

use std::io::Write as _;
use std::sync::Mutex;

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// The engine's progress "phase" messages. Each appears first as a START event
/// (only `total`) and then as periodic UPDATE events (`completed` + `total`).
/// COUPLED to the exact strings in `ft-engine` (`commit.rs`, `pull.rs`).
const PHASES: &[&str] = &[
    "uploading blocks",
    "uploading manifest pages and blocklists",
    "fast-forwarding changes",
    "reconcile materializing winners",
];

/// The engine's matching "phase done" messages. Seeing one completes the active
/// line to `total/total` and terminates it with a newline. COUPLED to `ft-engine`.
const DONE: &[&str] = &[
    "blocks uploaded",
    "manifest uploaded",
    "fast-forward applied",
    "reconcile materialized",
];

/// Shared render state. `active` is the phase label currently shown on the open
/// (newline-less) line; `total` and `last_len` let a later update or the finish
/// overwrite it cleanly. Process-global because the tracing layer is installed
/// once for the whole process and [`finish`] must reach the same line.
struct State {
    active: Option<&'static str>,
    total: u64,
    last_len: usize,
}

static PROGRESS: Mutex<State> = Mutex::new(State {
    active: None,
    total: 0,
    last_len: 0,
});

/// Writes `line` to stderr on the current row (`\r`), padding with spaces to
/// erase any longer previous render. With `newline` it terminates the row and
/// resets, so the next stdout write starts clean.
fn write_line(state: &mut State, line: &str, newline: bool) {
    let pad = state.last_len.saturating_sub(line.len());
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "\r{line}{blank:pad$}", blank = "", pad = pad);
    if newline {
        let _ = err.write_all(b"\n");
        state.last_len = 0;
        state.active = None;
    } else {
        state.last_len = line.len();
    }
    let _ = err.flush();
}

/// Terminates any open progress line with a newline. Called by `main` on the
/// error path, where a phase may have been interrupted mid-flight before its
/// DONE event, so the following error message does not land on the same row.
pub fn finish() {
    let mut state = PROGRESS.lock().expect("progress mutex poisoned");
    if let Some(label) = state.active {
        let total = state.total;
        write_line(&mut state, &format!("{label} {total}/{total}"), true);
    }
}

/// The fields a progress event may carry.
#[derive(Default)]
struct Fields {
    total: Option<u64>,
    completed: Option<u64>,
    message: Option<String>,
}

impl Visit for Fields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "total" => self.total = Some(value),
            "completed" => self.completed = Some(value),
            _ => {}
        }
    }

    // `usize`/`i64`-typed counters arrive here on some tracing versions.
    fn record_i64(&mut self, field: &Field, value: i64) {
        if value >= 0 {
            self.record_u64(field, value as u64);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }
}

/// The tracing layer. A zero-sized type: all its state is the process-global
/// [`PROGRESS`]. Install it filtered to `ft-engine` INFO events (see `main`).
pub struct ProgressLayer;

impl<S: Subscriber> Layer<S> for ProgressLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        // The `message` field is recorded via `record_debug`; a static string
        // formats without quotes, but trim any just in case.
        let message = fields
            .message
            .as_deref()
            .map(|m| m.trim().trim_matches('"'))
            .unwrap_or("");

        if let Some(label) = PHASES.iter().find(|p| **p == message) {
            let total = fields.total.unwrap_or(0);
            let completed = fields.completed.unwrap_or(0);
            let mut state = PROGRESS.lock().expect("progress mutex poisoned");
            // A new phase starting while another is open: close the old row first.
            if state.active.is_some() && state.active != Some(*label) {
                let prev_total = state.total;
                let prev = state.active.unwrap();
                write_line(
                    &mut state,
                    &format!("{prev} {prev_total}/{prev_total}"),
                    true,
                );
            }
            state.active = Some(label);
            state.total = total;
            write_line(&mut state, &format!("{label} {completed}/{total}"), false);
        } else if DONE.contains(&message) {
            let mut state = PROGRESS.lock().expect("progress mutex poisoned");
            if let Some(label) = state.active {
                let total = state.total;
                write_line(&mut state, &format!("{label} {total}/{total}"), true);
            }
        }
    }
}
