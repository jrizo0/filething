//! Human-facing rendering of command errors (issue #11).
//!
//! The crates below the CLI return TYPED errors, and their `Display` reads like
//! plumbing ("space not found: [Request ID …] …", "diff: content mismatch for
//! …"). Here each one the user can actually act on becomes a [`Diagnosis`]: one
//! line of what happened plus ONE concrete next step. Everything else falls back
//! to `anyhow`'s own chain, so nothing is ever hidden.
//!
//! All of this text is USER-FACING and this CLI, its `--help` and the README are
//! in English, so these messages are too (they were Spanish until this pass — the
//! only Spanish left in the product is the conflict-copy filename marker in
//! `ft-conflict`, whose recognizer is keyed to that exact literal).
//!
//! An error usually reaches `main` wrapped several layers deep: `ft-engine` folds
//! the crate error into an [`EngineError`] variant and the command adds `anyhow`
//! context on top. [`diagnose`] walks the whole cause chain, so the phrasing is
//! found regardless of how many layers wrap it; [`find_coordinator_error`] is the
//! same idea for the one case `commands` needs INLINE (its `status` output).
//!
//! The raw detail (message + the Convex Request ID it embeds) is shown only in
//! verbose mode — the `-v/--verbose` flag OR `RUST_LOG` requesting `debug`/
//! `trace` (`main` computes the signal; `RUST_LOG=error` asks for less noise, not
//! more). We only ever SUGGEST `-v`: see [`VERBOSE_HINT`].

use anyhow::Error;
use ft_coordinator::CoordinatorError;
use ft_core::Error as CoreError;
use ft_engine::EngineError;
use ft_index::Error as IndexError;
use ft_manifest::ManifestError;

/// What the user is told when a command fails: one line of what happened, plus
/// the single next step that has a chance of fixing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    /// One-line human message.
    pub message: String,
    /// The concrete next step (printed after an arrow).
    pub next_step: String,
}

impl Diagnosis {
    fn new(message: impl Into<String>, next_step: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            next_step: next_step.into(),
        }
    }
}

/// The footer shown when the run was not verbose. It names `-v` and ONLY `-v`:
/// `RUST_LOG=debug` (which this line used to suggest) turns on debug logging in
/// the third-party crates too, and `convex`'s websocket writer logs every outgoing
/// message — including the Space key and the Convex JWT in cleartext. `main`'s
/// `log_filter` now caps those targets regardless of what the user asks for; this
/// line is the other half of that fix, since the leak was reached by FOLLOWING
/// this hint. `-v` is `info` for our own targets and leaks neither.
const VERBOSE_HINT: &str =
    "(run with -v for the technical detail, including any Coordinator Request ID)";

/// A human message + suggested next step for a typed Coordinator error. `None`
/// for variants with no phrasing better than their `Display` (transport, bad
/// response shapes, unmapped function errors) — those fall back to the raw
/// chain so nothing is hidden.
pub fn explain(err: &CoordinatorError) -> Option<(&'static str, &'static str)> {
    match err {
        // The backend deliberately does not distinguish "no such Space" from
        // "someone else's Space" (it must not leak which Spaces exist), so
        // neither do we: one message covers both.
        CoordinatorError::SpaceNotFound { .. } | CoordinatorError::NotAuthorized { .. } => Some((
            "Space not found, or this Account does not have access to it.",
            "Check the Space id — `filething spaces` lists the ones this Account can see.",
        )),
        CoordinatorError::NotAuthenticated { .. } => Some((
            "You are not signed in, or your session has expired.",
            "Run `filething login` and retry.",
        )),
        CoordinatorError::VaultUnavailable { .. } => Some((
            "The Coordinator cannot reach the Vault (object storage) right now.",
            "Retry in a few seconds; if it persists, tell whoever operates the Coordinator.",
        )),
        CoordinatorError::Conflict { .. } => Some((
            "The Space head moved while you were working.",
            "Run `filething sync` to reconcile, then retry.",
        )),
        _ => None,
    }
}

/// The first [`CoordinatorError`] in an `anyhow` cause chain, if any.
pub fn find_coordinator_error(err: &Error) -> Option<&CoordinatorError> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<CoordinatorError>())
}

/// A one-line human headline for a typed Coordinator error, for INLINE output
/// (e.g. `status`'s "remote head: unavailable (…)"). Falls back to the `Display`
/// for variants [`explain`] does not phrase.
pub fn headline(err: &CoordinatorError) -> String {
    match explain(err) {
        Some((msg, _)) => msg.to_string(),
        None => err.to_string(),
    }
}

/// The best [`Diagnosis`] for a failed command: walks the `anyhow` cause chain
/// outermost-first and takes the first cause any classifier recognizes. `None`
/// when nothing does — [`report`] then prints the raw chain.
pub fn diagnose(err: &Error) -> Option<Diagnosis> {
    err.chain().find_map(diagnose_cause)
}

/// Classifies ONE link of the chain. Typed downcasts first; a cause a typed
/// classifier does not phrase still goes through [`diagnose_by_message`], because
/// a wrapper's `Display` inlines its source (`EngineError`'s `"diff: {0}"`).
fn diagnose_cause(cause: &(dyn std::error::Error + 'static)) -> Option<Diagnosis> {
    if let Some(e) = cause.downcast_ref::<CoordinatorError>() {
        if let Some((message, next_step)) = explain(e) {
            return Some(Diagnosis::new(message, next_step));
        }
    }
    if let Some(d) = cause
        .downcast_ref::<EngineError>()
        .and_then(explain_engine)
        .or_else(|| cause.downcast_ref::<IndexError>().and_then(explain_index))
        .or_else(|| {
            cause
                .downcast_ref::<ManifestError>()
                .and_then(explain_manifest)
        })
        .or_else(|| cause.downcast_ref::<CoreError>().and_then(explain_core))
    {
        return Some(d);
    }
    diagnose_by_message(&cause.to_string())
}

/// Phrasing for the engine's own guards.
fn explain_engine(err: &EngineError) -> Option<Diagnosis> {
    match err {
        // A safety guard declined a destructive operation (e.g. a gc that found no
        // reachability roots and would have swept the whole Vault). The variant's
        // payload already says WHAT was refused and why, so it leads the message.
        EngineError::Refused(why) => Some(Diagnosis::new(
            format!("filething refused a destructive operation: {why}"),
            "Nothing was deleted or overwritten. That guard only fires when the operation would \
             be unsafe: fix what it reports (`filething status` shows each Space's state) and \
             retry.",
        )),
        // Another process holds the Space's flock(2). One-shot commands fail fast
        // rather than blocking, so the user must know WHO has it and that the
        // holder is usually the background daemon doing the same work.
        EngineError::SpaceLocked { root, holder } => Some(Diagnosis::new(
            format!("Another filething process is already syncing {root} ({holder})."),
            "Wait for it to finish and retry — that is usually the background daemon, which \
             syncs continuously anyway (`filething service status`).",
        )),
        _ => None,
    }
}

/// Phrasing for the local index.
fn explain_index(err: &IndexError) -> Option<Diagnosis> {
    match err {
        // The index carries its own "run `filething update`" sentence, but as one
        // cause among many it ends up buried mid-line; restate it as the next step.
        IndexError::SchemaTooNew { found, supported } => Some(version_skew(format!(
            "This Space's local index was written by a newer filething (index schema v{found}; \
             this build understands v{supported})."
        ))),
        _ => None,
    }
}

/// Phrasing for Manifest decoding.
fn explain_manifest(err: &ManifestError) -> Option<Diagnosis> {
    match err {
        ManifestError::PageCidMismatch { expected, computed } => Some(integrity_failure(&format!(
            "the Manifest page stored as {expected} hashes to {computed}"
        ))),
        // A page kind only a NEWER filething writes (`docs/format.md §5`).
        ManifestError::UnknownKind(kind) => Some(version_skew(format!(
            "This Space's Manifest uses a page kind ({kind}) this filething build does not \
             understand."
        ))),
        _ => None,
    }
}

/// Phrasing for the foundation types.
fn explain_core(err: &CoreError) -> Option<Diagnosis> {
    match err {
        // The inbound trust boundary rejected a path (`CanonicalPath::
        // validate_untrusted`). This is a SECURITY event, not a bad-input nit: a
        // Manifest is remote data, and a `p` like `../../.ssh/authorized_keys` means
        // the Space's data is under someone else's control.
        CoreError::UnsafePath { path, reason } => Some(untrusted_space_data(&format!(
            "a Manifest entry asked to write to {path:?} ({reason})"
        ))),
        // Object/page formats this build has no code for: written by a newer
        // filething (`docs/format.md §4.2`).
        CoreError::UnsupportedHeaderVersion(v) => Some(version_skew(format!(
            "This Space's objects use header version {v}, which this filething build does not \
             understand."
        ))),
        CoreError::InvalidFileType(discriminant) => Some(version_skew(format!(
            "This Space's Manifest contains an entry type ({discriminant}) this filething build \
             does not understand."
        ))),
        _ => None,
    }
}

/// Classifies the read-path failures of the two engine crates the CLI does not
/// depend on (`ft-diff`, `ft-block`) by their `Display` text, keyed on the stable
/// in-repo phrasing of the variants that matter to a human.
///
/// Same deliberate coupling as `crate::progress` has to the engine's progress
/// messages, and it degrades the same way: an unrecognized error simply falls
/// back to the raw chain, which is what the user got before any of this existed.
/// The match slices FROM the marker so the wrapper prefixes ("diff: block error:
/// …") stay out of the human message.
fn diagnose_by_message(text: &str) -> Option<Diagnosis> {
    // Integrity: the bytes the Vault returned are not the ones the Manifest
    // promised — `ft_diff::Error::ContentMismatch` (a reassembled file failing its
    // `pcid`, the check that catches an alg=1 -> alg=0 downgrade),
    // `BlocklistCidMismatch`, `ft_block::Error::CidMismatch` (`docs/format.md
    // §4.3`/`§5.1`).
    for marker in [
        "content mismatch for ",
        "cid mismatch: expected ",
        "blocklist cid mismatch at ",
    ] {
        if let Some(detail) = from_marker(text, marker) {
            return Some(integrity_failure(detail));
        }
    }
    // A hostile/corrupt Manifest entry: `ft_diff::Error::UnsafeEntry` (which wraps
    // the `CoreError::UnsafePath` above but is NOT a `#[source]`, so the typed
    // classifier cannot see it) and `OutsideSpaceRoot`.
    if let Some(detail) = from_marker(text, "unsafe manifest entry: ") {
        return Some(untrusted_space_data(detail));
    }
    if text.contains("does not resolve inside the Space root") {
        return Some(untrusted_space_data(
            from_marker(text, "manifest path ").unwrap_or(text),
        ));
    }
    // `ft_diff::Error::SymlinkedParent` — a LOCAL refusal, not remote tampering:
    // the symlink is the user's own (the scanner keeps local-only symlinks out of
    // the Manifest, `§5.1`), so only they can decide what happens to it.
    if text.contains("the intermediate component") && text.contains("is a symlink") {
        return Some(Diagnosis::new(
            from_marker(text, "refusing to write ").unwrap_or(text),
            "Replace that symlink with a real folder, or move it out of the Space, then re-run \
             `filething sync`.",
        ));
    }
    // `ft_diff::Error::PageDepthExceeded` — a real Manifest tree is shallow.
    if let Some(detail) = from_marker(text, "manifest page tree deeper than ") {
        return Some(Diagnosis::new(
            format!("This Space's Manifest is nested implausibly deep ({detail})."),
            "Nothing was written. A real Manifest is shallow, so treat this Space's data as \
             corrupt or tampered with and report it to whoever operates the Coordinator/Vault.",
        ));
    }
    None
}

/// The text from `marker` onward, or `None` when it does not occur.
fn from_marker<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    text.find(marker).map(|i| &text[i..])
}

/// Shared phrasing for a content-integrity failure (`docs/format.md §4.3`). The
/// mismatched bytes are never applied, so the reassuring half — the user's files
/// are untouched — matters as much as the failure itself.
fn integrity_failure(detail: &str) -> Diagnosis {
    Diagnosis::new(
        format!("Integrity check failed: {detail}."),
        "Nothing was written to your files. Retry once; if it repeats, that stored object is \
         corrupt or was tampered with — report it to whoever operates the Vault/Coordinator.",
    )
}

/// Shared phrasing for a Manifest that tried to escape the Space root. Deliberately
/// says the Space's DATA cannot be trusted rather than just printing the path: a
/// healthy Coordinator/Vault pair cannot produce this, so the next step is to
/// verify what this Device is talking to, not to retry.
fn untrusted_space_data(detail: &str) -> Diagnosis {
    Diagnosis::new(
        format!("This Space's data cannot be trusted: {detail}; filething refused to apply it."),
        "Nothing was written outside the Space. A healthy Space never contains such a path: check \
         that this Device points at the Coordinator/Vault you expect, and report it to whoever \
         operates them before syncing this Space again.",
    )
}

/// Shared phrasing for version skew: an OLDER binary meeting data a NEWER one
/// wrote. Nothing is wrong with the Space, so the next step is always the
/// self-updater — retrying or re-syncing fails identically.
fn version_skew(message: String) -> Diagnosis {
    Diagnosis::new(
        message,
        "Run `filething update` to upgrade this Device, then retry.",
    )
}

/// Render a top-level command error for the user on stderr. When any classifier
/// recognizes a cause, prints its human message + next step; otherwise prints
/// `anyhow`'s own chain (de-duplicated). `verbose` (the `-v` flag or RUST_LOG at
/// debug/trace) appends the raw cause chain, which carries the Convex Request ID
/// for support.
pub fn report(err: &Error, verbose: bool) {
    if let Some(d) = diagnose(err) {
        eprintln!("error: {}", d.message);
        eprintln!("  \u{2192} {}", d.next_step);
        if verbose {
            eprintln!("\ntechnical detail:");
            for cause in dedup_chain(err) {
                eprintln!("  - {cause}");
            }
        } else {
            eprintln!("  {VERBOSE_HINT}");
        }
        return;
    }
    // No mapping: anyhow's chain, de-duplicated (see [`dedup_chain`]).
    eprintln!("error: {}", dedup_chain(err).join(": "));
}

/// The `anyhow` cause chain as strings, dropping any cause whose text is already
/// contained in the previously kept one. A `thiserror` variant that interpolates
/// its `#[source]` inline — e.g. `EngineError`'s `#[error("vault: {0}")]` — makes
/// anyhow print the wrapper (which already embeds the source message) AND then
/// the source again verbatim; that redundant second line is what this collapses
/// (issue #21).
fn dedup_chain(err: &Error) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for cause in err.chain() {
        let s = cause.to_string();
        if out.last().is_some_and(|prev| prev.contains(&s)) {
            continue;
        }
        out.push(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_not_found_and_not_authorized_share_one_message() {
        let a = CoordinatorError::SpaceNotFound {
            message: "no such Space".into(),
        };
        let b = CoordinatorError::NotAuthorized {
            message: "another Account".into(),
        };
        assert_eq!(explain(&a), explain(&b));
        assert!(explain(&a)
            .unwrap()
            .0
            .contains("not found, or this Account"));
    }

    #[test]
    fn each_mapped_variant_has_a_next_step() {
        for e in [
            CoordinatorError::NotAuthenticated {
                message: "x".into(),
            },
            CoordinatorError::VaultUnavailable {
                message: "x".into(),
            },
            CoordinatorError::Conflict {
                message: "x".into(),
            },
        ] {
            let (msg, hint) = explain(&e).expect("mapped variant");
            assert!(!msg.is_empty());
            assert!(!hint.is_empty());
        }
    }

    /// This CLI, its `--help` and the README are English; the renderer was the one
    /// Spanish surface left. Checks the function words that would come back with a
    /// copy-pasted Spanish string (accents alone would miss "Corre"/"no tienes").
    #[test]
    fn every_message_and_next_step_is_in_english() {
        let spanish = [
            "Corre ",
            "Verifica",
            "no tienes",
            "detalle",
            "usa -v",
            "reintenta",
            "Reintenta",
            "expiró",
            "está",
            "avisa",
        ];
        let mut texts: Vec<String> = vec![VERBOSE_HINT.to_string()];
        for e in [
            CoordinatorError::SpaceNotFound {
                message: "x".into(),
            },
            CoordinatorError::NotAuthorized {
                message: "x".into(),
            },
            CoordinatorError::NotAuthenticated {
                message: "x".into(),
            },
            CoordinatorError::VaultUnavailable {
                message: "x".into(),
            },
            CoordinatorError::Conflict {
                message: "x".into(),
            },
        ] {
            let (msg, hint) = explain(&e).expect("mapped variant");
            texts.push(msg.to_string());
            texts.push(hint.to_string());
        }
        for text in texts {
            for word in spanish {
                assert!(
                    !text.contains(word),
                    "Spanish {word:?} left in user-facing text: {text:?}"
                );
            }
        }
    }

    /// The non-verbose footer must not send the user to `RUST_LOG=debug`: that
    /// turns on third-party debug logging, which has written the Space key and the
    /// auth JWT into the log.
    #[test]
    fn verbose_hint_suggests_dash_v_and_never_rust_log() {
        assert!(VERBOSE_HINT.contains("-v"));
        assert!(!VERBOSE_HINT.contains("RUST_LOG"));
    }

    #[test]
    fn unmapped_variant_falls_back_to_display() {
        let e = CoordinatorError::Transport("socket closed".into());
        assert!(explain(&e).is_none());
        // headline still yields something usable (the Display).
        assert!(headline(&e).contains("socket closed"));
    }

    #[test]
    fn find_coordinator_error_walks_wrapped_anyhow_chain() {
        // Simulates the real path: a CoordinatorError buried under anyhow context
        // (as ft-engine + the command's `.context()` layers would produce).
        let base = anyhow::Error::new(CoordinatorError::SpaceNotFound {
            message: "no such Space".into(),
        });
        let wrapped = base.context("clone_space").context("cloning Space");
        let found = find_coordinator_error(&wrapped).expect("should recover the typed error");
        assert!(matches!(found, CoordinatorError::SpaceNotFound { .. }));
    }

    #[test]
    fn find_coordinator_error_returns_none_when_absent() {
        let err = anyhow::anyhow!("some unrelated failure").context("doing a thing");
        assert!(find_coordinator_error(&err).is_none());
    }

    #[test]
    fn dedup_chain_drops_a_cause_contained_in_its_wrapper() {
        // Mirrors the real gc failure (issue #21): the inner VaultError, then a
        // wrapper whose Display inlines it ("vault: {0}"), then a command context.
        let inner = anyhow::anyhow!("s3 vault error at blocks/: signed vault cannot list");
        let err = inner
            .context("vault: s3 vault error at blocks/: signed vault cannot list")
            .context("gc");
        let chain = dedup_chain(&err);
        // The verbatim-duplicated inner line is collapsed: "gc" + the wrapper only.
        assert_eq!(
            chain,
            vec![
                "gc".to_string(),
                "vault: s3 vault error at blocks/: signed vault cannot list".to_string(),
            ]
        );
    }

    #[test]
    fn dedup_chain_keeps_distinct_causes() {
        let err = anyhow::anyhow!("root cause")
            .context("middle layer")
            .context("top");
        assert_eq!(
            dedup_chain(&err),
            vec![
                "top".to_string(),
                "middle layer".to_string(),
                "root cause".to_string(),
            ]
        );
    }

    // ----- the typed errors added by the hardening waves -----

    /// A guard that declined a destructive operation must say so AND say nothing
    /// was destroyed, wrapped as deep as the real gc path wraps it.
    #[test]
    fn refused_guard_is_phrased_as_a_declined_destructive_operation() {
        let err = anyhow::Error::new(EngineError::Refused(
            "no reachability roots: sweeping would delete every Block".into(),
        ))
        .context("gc");
        let d = diagnose(&err).expect("Refused must be phrased");
        assert!(d.message.contains("refused a destructive operation"));
        assert!(d.message.contains("no reachability roots"));
        assert!(d.next_step.contains("Nothing was deleted"));
    }

    /// The Space lock must name the holder and tell the user to wait, so a
    /// one-shot command that hit the daemon does not look like a hang or a bug.
    #[test]
    fn space_locked_names_the_holder_and_tells_the_user_to_wait() {
        let err = anyhow::Error::new(EngineError::SpaceLocked {
            root: "/Users/x/Notes".into(),
            holder: "pid 1234".into(),
        })
        .context("syncing /Users/x/Notes");
        let d = diagnose(&err).expect("SpaceLocked must be phrased");
        assert!(d.message.contains("/Users/x/Notes"));
        assert!(d.message.contains("pid 1234"));
        assert!(d.next_step.contains("Wait"));
    }

    /// A Manifest path that escapes the Space root is a SECURITY event: the
    /// message must say the data cannot be trusted, not just print the path.
    #[test]
    fn unsafe_manifest_path_is_reported_as_untrusted_space_data() {
        let err = anyhow::Error::new(EngineError::Core(CoreError::UnsafePath {
            path: "../../.ssh/authorized_keys".into(),
            reason: "parent-directory component",
        }))
        .context("fast-forwarding");
        let d = diagnose(&err).expect("UnsafePath must be phrased");
        assert!(d.message.contains("cannot be trusted"));
        assert!(d.message.contains("../../.ssh/authorized_keys"));
        assert!(d.message.contains("refused"));
        assert!(d.next_step.contains("Coordinator/Vault"));
    }

    /// A page that does not hash to the cid that referenced it is an integrity
    /// failure, and the user needs to know their files were not touched.
    #[test]
    fn manifest_page_cid_mismatch_is_reported_as_an_integrity_failure() {
        let err = anyhow::Error::new(EngineError::Manifest(ManifestError::PageCidMismatch {
            expected: ft_core::Cid::new([0xab; 32]),
            computed: ft_core::Cid::new([0xcd; 32]),
        }))
        .context("pulling");
        let d = diagnose(&err).expect("PageCidMismatch must be phrased");
        assert!(d.message.starts_with("Integrity check failed:"));
        assert!(d.message.contains(&"ab".repeat(32)));
        assert!(d.next_step.contains("Nothing was written to your files"));
    }

    /// A reassembled file failing its `pcid` check lives in `ft-diff`, which this
    /// crate does not depend on, so it is recognized from its message. The
    /// wrapper prefixes must not leak into the human line.
    #[test]
    fn reassembled_content_mismatch_is_reported_as_an_integrity_failure() {
        let err = anyhow::anyhow!(
            "diff: content mismatch for notes/a.md: the Manifest declares 10 bytes hashing to \
             aa, the reassembled Blocks are 12 bytes hashing to bb"
        )
        .context("fast-forwarding");
        let d = diagnose(&err).expect("a pcid mismatch must be phrased");
        assert!(d
            .message
            .starts_with("Integrity check failed: content mismatch for notes/a.md"));
        assert!(!d.message.contains("diff:"), "wrapper prefix leaked: {d:?}");
    }

    /// A Block object substituted in the Vault (its bytes do not hash to the cid
    /// that addressed it) is the same story for the user.
    #[test]
    fn block_cid_mismatch_is_reported_as_an_integrity_failure() {
        let err = anyhow::anyhow!("block: cid mismatch: expected aa, computed bb");
        let d = diagnose(&err).expect("a block cid mismatch must be phrased");
        assert!(d
            .message
            .starts_with("Integrity check failed: cid mismatch"));
    }

    /// A destination whose parent component is a symlink is a LOCAL problem with
    /// an actionable fix, and must not be dressed up as tampering.
    #[test]
    fn symlinked_parent_gets_a_local_fix_not_a_tampering_warning() {
        let err = anyhow::anyhow!(
            "diff: refusing to write /s/a/b.md: the intermediate component /s/a is a symlink"
        );
        let d = diagnose(&err).expect("SymlinkedParent must be phrased");
        assert!(d.message.starts_with("refusing to write /s/a/b.md"));
        assert!(d.next_step.contains("symlink"));
        assert!(!d.next_step.contains("tampered"));
    }

    /// Version skew must send the user to the self-updater instead of surfacing a
    /// raw discriminant, whichever layer notices it first.
    #[test]
    fn version_skew_says_run_filething_update() {
        let cases = [
            anyhow::Error::new(EngineError::Index(IndexError::SchemaTooNew {
                found: 4,
                supported: 3,
            }))
            .context("opening the local index"),
            anyhow::Error::new(EngineError::Core(CoreError::UnsupportedHeaderVersion(2)))
                .context("decoding a page"),
            anyhow::Error::new(EngineError::Core(CoreError::InvalidFileType(7)))
                .context("decoding a page"),
            anyhow::Error::new(EngineError::Manifest(ManifestError::UnknownKind(2)))
                .context("decoding a page"),
        ];
        for err in cases {
            let d = diagnose(&err).unwrap_or_else(|| panic!("must be phrased: {err:#}"));
            assert!(
                d.next_step.contains("`filething update`"),
                "{err:#} -> {d:?}"
            );
            // The raw discriminant/version is still stated, just not alone.
            assert!(!d.message.is_empty());
        }
    }

    /// An error nothing recognizes must still print: the raw chain, as before.
    #[test]
    fn an_unrecognized_error_has_no_diagnosis_and_falls_back_to_the_chain() {
        let err = anyhow::anyhow!("disk quota exceeded").context("writing the index");
        assert!(diagnose(&err).is_none());
        assert_eq!(
            dedup_chain(&err).join(": "),
            "writing the index: disk quota exceeded"
        );
    }
}
