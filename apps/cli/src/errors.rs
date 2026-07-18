//! Human-facing rendering of Coordinator errors (issue #11).
//!
//! The Coordinator now returns TYPED [`CoordinatorError`] variants, mapped from
//! the backend's `ConvexError.data.code` (see `ft-coordinator`). Their `Display`
//! still reads like plumbing ("space not found: [Request ID …] …"), so here we
//! turn the machine-typed variant into a one-line message plus a concrete next
//! step. The raw detail (message + the Convex Request ID it embeds) is shown
//! only in verbose mode — the `-v/--verbose` flag OR `RUST_LOG` requesting
//! `debug`/`trace` (`main` computes the signal; `RUST_LOG=error` asks for less
//! noise, not more).
//!
//! A Coordinator error usually reaches `main` wrapped: `ft-engine` folds it into
//! `EngineError::Coordinator(..)` and the command adds `anyhow` context on top.
//! [`find_coordinator_error`] walks the whole `anyhow` cause chain to recover the
//! typed error regardless of how many layers wrap it.

use anyhow::Error;
use ft_coordinator::CoordinatorError;

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
            "Space no encontrado o no tienes acceso.",
            "Verifica el id del Space (o revisa el estado de los tuyos con `filething status`).",
        )),
        CoordinatorError::NotAuthenticated { .. } => Some((
            "No has iniciado sesión, o tu sesión expiró.",
            "Corre `filething login` y reintenta.",
        )),
        CoordinatorError::VaultUnavailable { .. } => Some((
            "El almacén (Vault) del Coordinator no está disponible ahora mismo.",
            "Reintenta en unos segundos; si persiste, avisa al operador del Coordinator.",
        )),
        CoordinatorError::Conflict { .. } => Some((
            "La cabeza del Space avanzó mientras trabajabas.",
            "Corre `filething sync` para reconciliar y reintenta.",
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

/// Render a top-level command error for the user on stderr. When a typed
/// Coordinator error is found in the chain, prints the human message + next
/// step; otherwise prints `anyhow`'s own chain (de-duplicated). `verbose` (the
/// `-v` flag or RUST_LOG at debug/trace) appends the raw cause chain, which
/// carries the Convex Request ID for support.
pub fn report(err: &Error, verbose: bool) {
    if let Some(ce) = find_coordinator_error(err) {
        if let Some((msg, hint)) = explain(ce) {
            eprintln!("error: {msg}");
            eprintln!("  \u{2192} {hint}");
            if verbose {
                eprintln!("\ndetalle técnico:");
                for cause in dedup_chain(err) {
                    eprintln!("  - {cause}");
                }
            } else {
                eprintln!(
                    "  (usa -v o RUST_LOG=debug para ver el detalle técnico y el Request ID)"
                );
            }
            return;
        }
    }
    // No typed mapping: anyhow's chain, de-duplicated (see [`dedup_chain`]).
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
            .contains("no encontrado o no tienes acceso"));
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
}
