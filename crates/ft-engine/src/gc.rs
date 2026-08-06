//! `gc` — mark-and-sweep garbage collection of ORPHANED Vault objects
//! (`docs/format.md §6.3`, `docs/adr/0007`, `docs/adr/0012`).
//!
//! The **mark** phase computes every Vault key reachable from EVERY Revision of
//! EVERY Space of the account: every Manifest page, every externalized blocklist
//! (and the Blocks it lists), every inline Block, plus each Space's meta blob and
//! the empty-Manifest root. The **sweep** phase lists the physical objects and
//! deletes those that are BOTH unreachable (from any Revision) AND older than the
//! grace-period. Dry-run by default: nothing is deleted unless
//! [`GcOptions::apply`] is set.
//!
//! This is deliberately **orphan-sweep only** — it retains ALL history, so it
//! never removes an object any Revision references and thus never strands a
//! Device's sync base. It reclaims genuine garbage: objects a commit uploaded but
//! never referenced because the head never advanced (a crash/abort between the
//! Vault write and the CAS, `§7`). History-pruning via a retention floor
//! (reclaiming Blocks of deleted/superseded content below `min(baseSeqInUse)`) is
//! DEFERRED: a SOUND per-Space floor needs per-(Device,Space) base telemetry,
//! which the current per-Device `baseSeqInUse` scalar cannot provide — a per-Space
//! seq published into a per-Device scalar can raise one Space's floor above a
//! Device's real base there and strand its data. The `revisions:listFromSeq` /
//! `spaces:refreshRetentionFloor` machinery is kept (unused for now) for that
//! future work. See `docs/adr/0012`.
//!
//! Safety nets:
//! - **Roots guard**: refuses to run at all unless the authenticated Account lists
//!   at least one Space AND owns the Space the caller pointed at. Reachability comes
//!   entirely from `list_mine`, so an Account with no Spaces collapses the mark set
//!   to a single key and the sweep would delete the WHOLE bucket — the realistic
//!   cause being a wrong login or a re-deployed Coordinator while `S3_*` still
//!   points at the real Vault.
//! - **Grace-period**: never sweep an object younger than the window (24h
//!   default), so a commit in flight (Vault-first, head-after, `§7`) whose objects
//!   are uploaded but not yet referenced is protected. A missing/future mtime is
//!   treated as "too young" (never sweep on uncertainty). The window enforced is
//!   `grace + clock_skew_allowance` — see residual race 2 below.
//! - **Proportion guard**: refuses `--apply` when the delete set is a large
//!   fraction ([`GcOptions::max_sweep_fraction`]) of the objects scanned. A sweep
//!   that big is far more likely to mean an INCOMPLETE mark than a Vault that full
//!   of garbage, so it must be asked for explicitly.
//! - **Concurrency guard**: the reachability snapshot predates the object listing,
//!   so before deleting (with `apply`) the GC re-reads every Space head; if any
//!   advanced (a concurrent commit) it ABORTS without deleting. It re-reads again
//!   every [`HEAD_RECHECK_EVERY`] deletes and once after the last one, so a race
//!   that starts mid-sweep is at worst REPORTED instead of silent.
//! - **Anomaly guard**: refuses to run if a Space has a head but zero Revisions
//!   are listed, rather than sweeping everything.
//! - It fails if a reachable object cannot be read (never sweeps on a partial mark).
//! - Every refusal is an `Err`, never a [`GcReport`]: a guard that declined can
//!   therefore not be misread as a sweep that found nothing to do.
//!
//! Even so, a Device must still not trust a stale local presence cache. The commit
//! path never references a Block on the strength of its `local_block` row alone
//! (`scan.rs`/`commit.rs`): a cid may be referenced without a `HEAD` exactly when
//! the BASE Revision already references it — which this sweep, being
//! orphan-only, can never remove — and any other cid is either uploaded by that
//! same commit under `HEAD`-before-`PUT` or left out of the Manifest entirely. So a
//! Block this GC (or another Device's) removed is one no Revision referenced, and
//! the next commit that needs it re-reads the file and re-uploads it.
//!
//! ## Residual races (read before lowering the grace-period)
//!
//! Neither of these can be closed from the client side. They are written down
//! because an operator who knows about them can avoid them — run the GC when the
//! Account's Devices are idle, and keep the grace-period generous.
//!
//! 1. **HEAD-then-CAS.** A commit does NOT re-upload a Block whose presence a HEAD
//!    confirmed (`commit.rs`, `§7`), so between that HEAD and its CAS the Block is
//!    about to be referenced by a Revision that does not exist yet. The
//!    grace-period does not cover it: the object is OLD — it is being
//!    RE-referenced, not re-uploaded. Mitigated here by re-reading the heads before
//!    the first delete, every [`HEAD_RECHECK_EVERY`] deletes and once after the
//!    last, and by deleting OLDEST-FIRST so an abort has touched only the
//!    least-recently-written objects. What SURVIVES: a CAS landing after the final
//!    re-read is invisible to us, so a racing commit can still publish a Revision
//!    referencing a swept Block. The blast radius is bounded and recoverable — the
//!    racing Device fixes it by committing again (its next HEAD finds the Block
//!    gone and re-uploads it), and a Device that pulled the broken Revision in
//!    between gets a hard fetch error, not silent corruption. A real fix is
//!    server-side (a Coordinator-held "commit in flight" lease, or a server-side
//!    sweep) and is out of scope for the client (ADR 0012).
//! 2. **Clock skew and long commits.** An object's age mixes two clocks: `mtime` is
//!    stamped by the storage provider, `now` is this Device's. A local clock AHEAD
//!    of the provider's makes every object look OLDER and so silently SHORTENS the
//!    window — the dangerous direction, and one the listing cannot reveal. Hence
//!    the enforced window is `grace + clock_skew_allowance`. The opposite skew is
//!    safe (ages come out too small, and a future mtime is already "too young") and
//!    IS detectable, so it is warned about instead of corrected. Independently, an
//!    object is protected only while it is younger than the window, so the
//!    grace-period MUST exceed the longest commit that can be in flight: a
//!    multi-hour initial upload over a slow link is not protected by a window
//!    shorter than itself. `grace = 0` is an explicit opt-out (the demo gates use
//!    it to sweep an injected orphan immediately): no window, and no skew allowance
//!    silently reinstating one.
//!
//! ## Scope: ONE bucket == ONE account
//!
//! The Vault is a single bucket and dedup is account-wide, so the GC computes
//! reachability as the UNION over EVERY Space of the account (not the one Space
//! the CLI pointed at) — otherwise it would delete Blocks another Space of the
//! same account still needs. It follows that the GC also sweeps any object NOT
//! reachable from the account, i.e. it assumes the bucket belongs to exactly one
//! account (the shipped self-hosted / personal-use model: a deployment has one
//! account). A future MANAGED multi-tenant Vault sharing one bucket across
//! accounts would need account-prefixed keys or a server-side cross-account
//! sweep before this could run safely there.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use ft_coordinator::SpaceId;
use ft_core::{Cid, FileEntry};
use ft_manifest::{decode_page, Page};
use ft_vault::{Vault, VaultObject};

use crate::context::SpaceContext;
use crate::error::{EngineError, Result};

/// The Vault prefixes the GC enumerates and may sweep. `keys/<space_id>/<cid>`
/// data-key sidecars (`§4.5`, ADR 0015) are attachments of `blocks/<cid>`: a
/// sidecar is reachable iff its Block is reachable FROM ITS OWN SPACE (see
/// [`mark_entry_blocks`]), so an orphan sidecar — one whose Block is gone, or
/// which never had a live Block — is swept here just like any other orphan. The
/// `keys/` prefix covers every Space's per-Space subtree in one sweep. `reach/`
/// stays reserved and is never touched.
const SWEEP_PREFIXES: [&str; 5] = ["blocks/", "manifest/", "blocklist/", "meta/", "keys/"];

/// The default grace-period: 24h. An object younger than this is never swept.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// The default slack the grace-period is widened by to absorb client↔storage
/// clock skew: 1h. Generous enough for the skew a badly-synced host actually
/// shows (NTP keeps a healthy one inside seconds) while costing only an extra hour
/// of retained garbage. See residual race 2 in the module docs.
pub const DEFAULT_CLOCK_SKEW_ALLOWANCE: Duration = Duration::from_secs(60 * 60);

/// The default proportion guard: refuse `--apply` when the delete set exceeds HALF
/// the objects scanned. The GC retains all history, so live content is never
/// garbage and a healthy Vault's orphans (debris of commits that died between the
/// Vault write and the CAS, `§7`) are a small minority; a majority-orphan bucket is
/// far more likely to be an incomplete mark. A value `>= 1.0` disables the guard,
/// since the sweep set can never exceed what was scanned.
pub const DEFAULT_MAX_SWEEP_FRACTION: f64 = 0.5;

/// The proportion guard needs a meaningful denominator: below this many scanned
/// objects the ratio is noise (a fresh Space with three objects and two orphans is
/// 67% garbage and perfectly healthy) and the blast radius of a wrong sweep is a
/// handful of objects, so the guard stands down. The roots guard, the grace-period
/// and the concurrency guard still apply.
const PROPORTION_GUARD_MIN_SCANNED: usize = 32;

/// How often, in deletes, a long sweep re-reads the Space heads (residual race 1
/// in the module docs). It bounds the window in which a commit's HEAD→CAS can
/// overlap deletes still to come, at one Coordinator round-trip per 500 deletes.
const HEAD_RECHECK_EVERY: usize = 500;

/// Knobs for a [`SpaceContext::gc`] run. Construct with `..Default::default()` —
/// new safety knobs are added here as they are needed.
#[derive(Debug, Clone)]
pub struct GcOptions {
    /// Actually delete swept objects. `false` (the default) is a dry run: the
    /// report lists what WOULD be deleted and the Vault is untouched.
    pub apply: bool,
    /// Never sweep an object younger than this. Protects in-flight commits, so it
    /// must exceed the longest commit that can be in flight (module docs, residual
    /// race 2). `Duration::ZERO` waives the protection entirely.
    pub grace: Duration,
    /// Extra slack added to [`Self::grace`] because ages compare the storage
    /// provider's mtimes against the LOCAL clock: a local clock ahead of the
    /// provider's would otherwise shorten the real window. Ignored when
    /// [`Self::grace`] is zero (an explicit opt-out must not be silently undone).
    pub clock_skew_allowance: Duration,
    /// Refuse `--apply` when the delete set exceeds this fraction of the objects
    /// scanned — the guard against sweeping a Vault whose mark set came out
    /// incomplete. `>= 1.0` disables it, for the legitimately huge sweep.
    pub max_sweep_fraction: f64,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            apply: false,
            grace: DEFAULT_GRACE,
            clock_skew_allowance: DEFAULT_CLOCK_SKEW_ALLOWANCE,
            max_sweep_fraction: DEFAULT_MAX_SWEEP_FRACTION,
        }
    }
}

/// What a [`SpaceContext::gc`] run found and (with `apply`) did. GC is
/// **account-scoped**: the Vault (one bucket) holds Blocks for EVERY Space of the
/// account and dedup is account-wide, so reachability is the UNION over all of
/// them and these figures span the account, not one Space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    /// Number of the account's Spaces whose reachability was unioned.
    pub spaces: usize,
    /// Total Revisions (across all Spaces) whose trees were walked (all of them —
    /// orphan-sweep retains full history).
    pub retained_revisions: usize,
    /// Distinct reachable Vault objects (the mark set).
    pub reachable_objects: usize,
    /// Physical objects listed across the swept prefixes.
    pub scanned_objects: usize,
    /// Unreachable objects held back ONLY by the grace-period (younger than it).
    pub kept_by_grace: usize,
    /// The PLAN: keys eligible to sweep (unreachable AND older than the
    /// grace-period), sorted. Always the plan, in both modes — what was actually
    /// deleted is [`Self::deleted_keys`], so the two never have to be told apart by
    /// remembering which mode produced the report.
    pub sweepable: Vec<String>,
    /// Objects actually deleted (0 in a dry run) — `deleted_keys.len()`.
    pub deleted: usize,
    /// The keys actually deleted, sorted: EMPTY in a dry run, equal to
    /// [`Self::sweepable`] after a complete `--apply`. A run that stopped partway
    /// returns an `Err` naming what it had already deleted, so this field is never
    /// a partial record presented as a whole one.
    pub deleted_keys: Vec<String>,
    /// Whether deletes were applied.
    pub applied: bool,
}

impl SpaceContext {
    /// Runs an orphan-sweep GC over the **account-wide** Vault. The Vault is
    /// shared across ALL of the account's Spaces (one bucket, account-scoped
    /// dedup), so reachability is the UNION over every Space's Revisions — GCing
    /// from a single Space's view would delete other Spaces' live Blocks. The
    /// `dir` you point at only selects the account / Vault / Coordinator; the
    /// sweep covers the whole account. Requires a Coordinator (a staging-only
    /// mount errors). Dry-run unless [`GcOptions::apply`]. See the module docs for
    /// the safety model.
    pub async fn gc(&mut self, opts: GcOptions) -> Result<GcReport> {
        if self.coordinator.is_none() {
            return Err(EngineError::SpaceState(
                "gc requires a Coordinator; this context was mounted for staging only".to_string(),
            ));
        }
        // Every Space of the account shares this Vault. Gather reachability roots
        // (ALL Revisions of every Space — orphan-sweep retains full history) and
        // meta blobs, plus a snapshot of each Space head for the concurrency guard.
        // `list_mine` scopes to the caller's own Account (derived from the JWT).
        let spaces = self
            .coordinator
            .as_mut()
            .expect("coordinator present")
            .list_mine()
            .await?;
        // The mark set has NO other source, so an empty or foreign root set means
        // "delete the bucket". Check before touching the Vault at all.
        guard_roots(&spaces, &self.space_id)?;
        warn_on_weak_grace(opts.grace);

        // Each root is paired with its owning Space id so the mark can name that
        // Space's `keys/<space_id>/<cid>` sidecars (`§4.5`): the sidecar key is
        // per-Space even though the Block object it attaches to is Account-wide.
        let mut root_cids: Vec<(SpaceId, Cid)> = Vec::new();
        let mut meta_cids: Vec<Cid> = Vec::new();
        let mut retained_revisions = 0usize;
        let heads_before = head_snapshot(&spaces);
        for space in &spaces {
            meta_cids.push(space.meta_blob_cid);
            // Retain ALL Revisions (min_seq = 0): history-pruning is deferred (see
            // the module docs), so the GC removes only objects reachable from NO
            // Revision — true orphans (e.g. aborted-commit debris).
            let roots = self
                .coordinator
                .as_mut()
                .expect("coordinator present")
                .list_revisions_from(&space.space_id, 0)
                .await?;
            // Safety: a Space with a head but no Revisions listed is a backend
            // anomaly — refuse the WHOLE GC rather than treat live objects as junk.
            if roots.is_empty() && space.head_revision_id.is_some() {
                return Err(EngineError::SpaceState(format!(
                    "gc refusing to run: Space {} has a head but listFromSeq(0) returned no \
                     Revisions",
                    space.space_id.as_str()
                )));
            }
            retained_revisions += roots.len();
            root_cids.extend(
                roots
                    .into_iter()
                    .map(|r| (space.space_id.clone(), r.manifest_root_cid)),
            );
        }

        // ----- mark: every reachable Vault key across all Spaces -----
        let reachable = mark_reachable(self.vault.as_ref(), &root_cids, &meta_cids).await?;

        // ----- sweep: list physical objects, hold back reachable + young -----
        let now = SystemTime::now();
        let mut scanned = 0usize;
        let mut all_objects: Vec<VaultObject> = Vec::new();
        for prefix in SWEEP_PREFIXES {
            let listed = self.vault.list(prefix).await?;
            scanned += listed.len();
            all_objects.extend(listed);
        }
        warn_on_future_mtimes(&all_objects, now, opts.clock_skew_allowance);
        let window = enforced_grace(opts.grace, opts.clock_skew_allowance);
        // Oldest-first, so an abort partway through has deleted only the objects
        // least likely to be in a racing commit's working set (residual race 1).
        let (plan, kept_by_grace) = partition_sweep(all_objects, &reachable, now, window);
        let mut sweepable: Vec<String> = plan.iter().map(|c| c.key.clone()).collect();
        sweepable.sort();

        // ----- apply -----
        let mut deleted_keys: Vec<String> = Vec::new();
        if !plan.is_empty() {
            // A delete set that is most of the bucket means the mark is suspect. Both
            // modes evaluate the guard — `--apply` is refused, a dry run warns — so
            // the alarm reaches the operator from the mode that deletes nothing.
            match guard_sweep_proportion(plan.len(), scanned, opts.max_sweep_fraction) {
                Err(e) if opts.apply => return Err(e),
                Err(e) => tracing::warn!(
                    error = %e,
                    "gc dry run: this plan would be REFUSED by --apply"
                ),
                Ok(()) => {}
            }
        }
        if opts.apply && !plan.is_empty() {
            // Concurrency guard: our reachability snapshot predates the listing, so
            // a commit that advanced a head in between could have referenced an
            // object we now deem an orphan. Re-read the heads; if any changed (or a
            // Space appeared/vanished), ABORT without deleting.
            if self.heads_changed_since(&heads_before).await? {
                return Err(EngineError::Refused(
                    "gc --apply aborted: a Space head changed during the sweep (concurrent commit, \
                     or a Space was created/removed); nothing was deleted — re-run when idle"
                        .to_string(),
                ));
            }
            tracing::info!(total = plan.len(), "gc sweeping orphans");
            for (done, candidate) in plan.iter().enumerate() {
                // A long sweep can outlive its pre-delete guard, so re-check
                // periodically: it bounds how far a commit's HEAD→CAS window can
                // reach into deletes we have not made yet (residual race 1).
                if done > 0 && done % HEAD_RECHECK_EVERY == 0 {
                    if self.heads_changed_since(&heads_before).await? {
                        return Err(EngineError::Refused(format!(
                            "gc --apply aborted mid-sweep: a Space head changed (concurrent \
                             commit, or a Space was created/removed). {}. If that commit \
                             referenced one of them, commit again on the Device that made it — \
                             its HEAD-before-PUT (`§7`) re-uploads whatever went missing",
                            deleted_record(&deleted_keys, plan.len())
                        )));
                    }
                    tracing::info!(deleted = done, total = plan.len(), "gc sweeping orphans");
                }
                // Report what a partial run destroyed: an `Err` carries no
                // `GcReport`, so without this the record would be lost.
                self.vault.delete(&candidate.key).await.map_err(|e| {
                    tracing::error!(
                        deleted = deleted_keys.len(),
                        planned = plan.len(),
                        key = %candidate.key,
                        error = %e,
                        "gc --apply stopped: a delete failed"
                    );
                    EngineError::Refused(format!(
                        "gc --apply stopped: deleting {} failed ({e}); refusing to keep sweeping \
                         a Vault that is rejecting deletes. {}. Re-running gc is safe — deletes \
                         are idempotent and a fresh dry run shows what is left",
                        candidate.key,
                        deleted_record(&deleted_keys, plan.len())
                    ))
                })?;
                deleted_keys.push(candidate.key.clone());
            }
            // The pre-delete guard cannot see a commit whose CAS lands after it. This
            // last re-read cannot protect that commit — the deletes are done — it
            // exists so the operator LEARNS the sweep raced instead of reading a
            // clean report over a Revision that may reference a swept Block.
            if self.heads_changed_since(&heads_before).await? {
                return Err(EngineError::Refused(format!(
                    "gc --apply refuses to report a clean run: a Space head changed while it was \
                     deleting (concurrent commit). {}. Commit again on the Device that was \
                     committing — its HEAD-before-PUT (`§7`) re-uploads any Block this sweep \
                     removed from under it",
                    deleted_record(&deleted_keys, plan.len())
                )));
            }
            deleted_keys.sort();
            tracing::info!(deleted = deleted_keys.len(), "gc swept orphans");
        }

        Ok(GcReport {
            spaces: spaces.len(),
            retained_revisions,
            reachable_objects: reachable.len(),
            scanned_objects: scanned,
            kept_by_grace,
            sweepable,
            deleted: deleted_keys.len(),
            deleted_keys,
            applied: opts.apply,
        })
    }

    /// Re-reads every Space head and reports whether the account's head snapshot
    /// moved since `before` (a concurrent commit, or a Space created/removed) — the
    /// concurrency guard's single question, asked before, during and after the
    /// sweep.
    async fn heads_changed_since(&mut self, before: &[(String, Option<String>)]) -> Result<bool> {
        let after = self
            .coordinator
            .as_mut()
            .expect("coordinator present")
            .list_mine()
            .await?;
        Ok(head_snapshot(&after) != before)
    }
}

/// Refuses the whole GC unless the authenticated Account actually provides
/// reachability roots: at least one Space, INCLUDING the one the caller pointed at.
/// Reachability has no other source, so `list_mine() == []` collapses the mark set
/// to the empty-Manifest root and every object past the grace-period becomes
/// "garbage" — a whole-Vault wipe. The realistic trigger is an identity mismatch
/// (signed up again after re-deploying the Coordinator, or a personal login while
/// `S3_*` still points at the work bucket), not a corrupt backend, so the message
/// names that cause.
fn guard_roots(spaces: &[ft_coordinator::Space], space_id: &SpaceId) -> Result<()> {
    if spaces.is_empty() {
        return Err(EngineError::Refused(format!(
            "gc: the logged-in Account owns NO Spaces, so NOTHING in this Vault would be \
             reachable and the sweep would delete the entire bucket. This is almost always the \
             wrong login or the wrong Coordinator deployment (a fresh signup after re-deploying, \
             or a personal login while S3_* still points at the work bucket) — check `filething \
             whoami` and the Coordinator URL. Space {} was not touched",
            space_id.as_str()
        )));
    }
    if !spaces.iter().any(|s| s.space_id == *space_id) {
        return Err(EngineError::Refused(format!(
            "gc: the logged-in Account owns {} Space(s) but not {}, the Space this folder is \
             mapped to — the login and the Vault this folder syncs to disagree. Sweeping would \
             treat every object of this Space (and of every other Space missing from that login) \
             as garbage. Log in as the Account that owns this Space, or point S3_* at the Vault \
             of the Account you are logged in as",
            spaces.len(),
            space_id.as_str()
        )));
    }
    Ok(())
}

/// Refuses an `--apply` whose delete set is a large fraction of everything scanned.
/// Independent of [`guard_roots`] on purpose: it catches ANY cause of a collapsed
/// mark set (a Coordinator page that silently dropped Spaces or Revisions, a
/// prefix the mark forgot), not just a wrong login. Stands down below
/// [`PROPORTION_GUARD_MIN_SCANNED`] objects, where a ratio means nothing.
fn guard_sweep_proportion(sweepable: usize, scanned: usize, max_fraction: f64) -> Result<()> {
    if scanned < PROPORTION_GUARD_MIN_SCANNED {
        return Ok(());
    }
    // Every comparison against a NaN is false, so a NaN threshold (`"nan".parse()`
    // reaching a future --max-sweep-fraction flag) would silently WAIVE the guard.
    // Waiving must be explicit, so a NaN falls back to the default.
    let max_fraction = if max_fraction.is_nan() {
        DEFAULT_MAX_SWEEP_FRACTION
    } else {
        max_fraction
    };
    let fraction = sweepable as f64 / scanned as f64;
    if fraction > max_fraction {
        return Err(EngineError::Refused(format!(
            "gc --apply refused: the sweep would delete {sweepable} of {scanned} scanned \
             object(s) ({:.0}%), over the {:.0}% safety threshold. The GC retains all history, \
             so a majority-garbage Vault is far more likely to be an INCOMPLETE mark (a Space or \
             Revision the Coordinator did not list) than that much real debris. Re-run without \
             --apply and read the plan; if it is genuinely all garbage, raise \
             GcOptions::max_sweep_fraction (1.0 disables this guard). Nothing was deleted",
            fraction * 100.0,
            max_fraction * 100.0
        )));
    }
    Ok(())
}

/// The window [`partition_sweep`] actually enforces: `grace` WIDENED by the
/// clock-skew allowance, because an object's age compares the storage provider's
/// mtime against the local clock and a local clock running ahead would shorten the
/// window (module docs, residual race 2). A zero `grace` is an explicit opt-out of
/// the protection, so it is left at zero rather than silently reinstated as an hour.
fn enforced_grace(grace: Duration, skew_allowance: Duration) -> Duration {
    if grace.is_zero() {
        Duration::ZERO
    } else {
        grace.saturating_add(skew_allowance)
    }
}

/// Warns when the grace-period is too weak to do its job. It protects a commit
/// only while that commit's objects are younger than the window, so a window
/// shorter than the longest commit in flight (a huge initial upload over a slow
/// link) protects nothing (`§7`).
fn warn_on_weak_grace(grace: Duration) {
    if grace.is_zero() {
        tracing::warn!(
            "gc grace-period is 0: objects of a commit still in flight are NOT protected — only \
             safe on an idle Vault"
        );
    } else if grace < DEFAULT_GRACE {
        tracing::warn!(
            grace_secs = grace.as_secs(),
            default_secs = DEFAULT_GRACE.as_secs(),
            "gc grace-period is below the default: it must exceed the longest commit that can be \
             in flight, or that commit's Blocks can be swept before its head lands"
        );
    }
}

/// Warns when listed mtimes lie in the FUTURE of the local clock — the storage
/// clock is ahead of ours, so the two disagree. That direction is the safe one
/// (ages come out too small, so the window is effectively wider, and a future mtime
/// is already treated as too young), but an offset of the same size in the OTHER
/// direction is invisible here and shortens the window, which is why
/// [`GcOptions::clock_skew_allowance`] exists: skew this large means it is too small.
fn warn_on_future_mtimes(objects: &[VaultObject], now: SystemTime, allowance: Duration) {
    let ahead = objects
        .iter()
        .filter_map(|o| o.last_modified)
        .filter_map(|m| m.duration_since(now).ok())
        .max();
    if let Some(ahead) = ahead {
        if ahead > allowance {
            tracing::warn!(
                ahead_secs = ahead.as_secs(),
                allowance_secs = allowance.as_secs(),
                "gc: storage mtimes are in the future of this Device's clock by more than the \
                 skew allowance — fix the clocks (NTP) or raise the allowance; the reverse skew \
                 would silently shorten the grace-period"
            );
        }
    }
}

/// Renders what an aborted `--apply` had ALREADY deleted, for embedding in the
/// error. An `Err` carries no [`GcReport`], so this is the operator's only record
/// of a destructive partial run; truncated like the CLI's own listing, since a
/// re-run's dry-run plan shows precisely what is left.
fn deleted_record(deleted: &[String], planned: usize) -> String {
    if deleted.is_empty() {
        return "nothing had been deleted yet".to_string();
    }
    const SHOW: usize = 20;
    let mut out = format!(
        "{} of {planned} planned object(s) WERE ALREADY DELETED:",
        deleted.len()
    );
    for key in deleted.iter().take(SHOW) {
        out.push_str("\n    ");
        out.push_str(key);
    }
    if deleted.len() > SHOW {
        out.push_str(&format!("\n    … and {} more", deleted.len() - SHOW));
    }
    out
}

/// A sorted snapshot of each Space's `(id, head-revision-id)` — the concurrency
/// guard compares this before vs. after the sweep to detect a racing commit (or a
/// Space created/removed) and abort the delete.
fn head_snapshot(spaces: &[ft_coordinator::Space]) -> Vec<(String, Option<String>)> {
    let mut snap: Vec<(String, Option<String>)> = spaces
        .iter()
        .map(|s| {
            (
                s.space_id.as_str().to_string(),
                s.head_revision_id.as_ref().map(|r| r.as_str().to_string()),
            )
        })
        .collect();
    snap.sort();
    snap
}

/// Computes the complete set of reachable Vault keys over `&dyn Vault`: the meta
/// blob (`meta/`), the empty-Manifest root, and everything reachable from each
/// Manifest `root` (pages, externalized blocklists + their Blocks, inline
/// Blocks). Coordinator-free so it is testable against an [`ft_vault::FsVault`].
/// Fails if a reachable object cannot be read — the mark must be COMPLETE before
/// any sweep, so a partial mark aborts the whole GC rather than risk deleting
/// live data.
pub(crate) async fn mark_reachable(
    vault: &dyn Vault,
    roots: &[(SpaceId, Cid)],
    meta_cids: &[Cid],
) -> Result<HashSet<String>> {
    let mut reachable: HashSet<String> = HashSet::new();
    // Each Space's meta blob (`meta/<cid>`) is a reachability root independent of
    // the Manifest tree; its cid is not discoverable by walking. Never delete.
    for meta_cid in meta_cids {
        reachable.insert(crate::secrets::meta_key(meta_cid));
    }
    // The empty-Manifest root is the "no base yet" base a fresh Device reads.
    // Insert its key directly (do NOT walk/fetch: it may legitimately be absent
    // from the Vault, which must not fail the mark).
    let empty_root = ft_manifest::build(Vec::new()).root;
    reachable.insert(ft_hash::manifest_key(&empty_root));
    // Walk every retained Revision's tree. Shared pages/blocks dedupe by cid; a
    // sidecar, however, is per-Space, so the walk carries the owning Space id.
    for (space_id, root) in roots {
        mark_from_root(vault, space_id.as_str(), root, &mut reachable).await?;
    }
    Ok(reachable)
}

/// Adds every Vault key reachable from a single Manifest `root` to `reachable`.
/// Iterative walk with an explicit stack; pages dedupe by cid. `space_id` scopes
/// the per-Space `keys/<space_id>/<cid>` sidecars marked for the Blocks found
/// (`§4.5`); pages/blocks/blocklists are Account-scoped and need no Space id.
async fn mark_from_root(
    vault: &dyn Vault,
    space_id: &str,
    root: &Cid,
    reachable: &mut HashSet<String>,
) -> Result<()> {
    let mut stack = vec![*root];
    while let Some(cid) = stack.pop() {
        let manifest_key = ft_hash::manifest_key(&cid);
        // Already visited this page (content-addressed pages dedupe by cid)?
        if !reachable.insert(manifest_key.clone()) {
            continue;
        }
        let obj = vault.get(&manifest_key).await?;
        match decode_page(&obj)? {
            Page::Index(index) => {
                for child in index.children {
                    stack.push(child.cid);
                }
            }
            Page::Leaf(leaf) => {
                for entry in leaf.e {
                    mark_entry_blocks(vault, space_id, &entry, reachable).await?;
                }
            }
        }
    }
    Ok(())
}

/// Marks the Block objects a single [`FileEntry`] references — either the
/// externalized blocklist (and every Block it lists) via `bk_ref`, or the inline
/// `bk` list. Verifies an externalized blocklist hashes to its `bk_ref` and
/// refuses to proceed on a mismatch (never sweep on corruption).
///
/// For every reachable Block cid it ALSO marks the Block's
/// `keys/<space_id>/<cid>` data-key sidecar reachable (`§4.5`, ADR 0015) for the
/// Space this entry's Manifest belongs to — the sidecar is per-Space, so the
/// mark must name the same Space that wrote it or the sweep would reclaim a live
/// sidecar. Marking a sidecar key that has no physical object (an `alg=0` Block
/// never wrote one) is harmless: a reachable key with no listed object simply
/// never matches during the sweep. This is what keeps a live encrypted Block's
/// sidecar from being collected, and — with the `keys/` prefix now swept — lets
/// an orphan sidecar be reclaimed.
async fn mark_entry_blocks(
    vault: &dyn Vault,
    space_id: &str,
    entry: &FileEntry,
    reachable: &mut HashSet<String>,
) -> Result<()> {
    match entry.bk_ref {
        Some(bk_ref) => {
            let bl_key = ft_hash::blocklist_key(&bk_ref);
            reachable.insert(bl_key.clone());
            let obj = vault.get(&bl_key).await?;
            let computed = ft_hash::cid_of(&obj);
            if computed != bk_ref {
                return Err(EngineError::SpaceState(format!(
                    "gc: blocklist {} bytes hash to {}, not its bk_ref — refusing to sweep on \
                     corrupt data",
                    bl_key,
                    computed.to_hex()
                )));
            }
            let list: Vec<Cid> = ciborium::de::from_reader(&obj[..]).map_err(|e| {
                EngineError::SpaceState(format!("gc: decoding blocklist {bl_key}: {e}"))
            })?;
            for c in list {
                reachable.insert(ft_hash::block_key(&c));
                reachable.insert(ft_diff::keys_key(space_id, &c));
            }
        }
        None => {
            for c in &entry.bk {
                reachable.insert(ft_hash::block_key(c));
                reachable.insert(ft_diff::keys_key(space_id, c));
            }
        }
    }
    Ok(())
}

/// One object the sweep intends to delete: its key plus the mtime the grace check
/// judged it by, which the delete loop orders on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SweepCandidate {
    key: String,
    mtime: SystemTime,
}

/// Splits listed objects into (delete plan, kept_by_grace_count). An object is
/// sweepable iff it is unreachable AND provably older than `grace` (the window
/// [`enforced_grace`] computed, not the raw option). A missing or future
/// `last_modified` counts as "too young" — the GC never sweeps on uncertainty. The
/// plan comes out OLDEST-FIRST (key as tie-break, so it is deterministic): the
/// order the deletes are made in, oldest being the least likely to be re-referenced
/// by a commit racing the sweep (module docs, residual race 1).
fn partition_sweep(
    objects: Vec<VaultObject>,
    reachable: &HashSet<String>,
    now: SystemTime,
    grace: Duration,
) -> (Vec<SweepCandidate>, usize) {
    let mut plan: Vec<SweepCandidate> = Vec::new();
    let mut kept_by_grace = 0usize;
    for obj in objects {
        if reachable.contains(&obj.key) {
            continue;
        }
        // Only a provable age sweeps, so a candidate always has a known mtime.
        let old_enough = match obj.last_modified {
            Some(mtime) => now
                .duration_since(mtime)
                .map(|age| age >= grace)
                .unwrap_or(false),
            None => false,
        };
        match (old_enough, obj.last_modified) {
            (true, Some(mtime)) => plan.push(SweepCandidate {
                key: obj.key,
                mtime,
            }),
            _ => kept_by_grace += 1,
        }
    }
    plan.sort_by(|a, b| a.mtime.cmp(&b.mtime).then_with(|| a.key.cmp(&b.key)));
    (plan, kept_by_grace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ft_core::{CanonicalPath, CasefoldKey, FileType};
    use ft_vault::FsVault;
    use std::time::{Duration, UNIX_EPOCH};

    fn cid(n: u8) -> Cid {
        Cid::new([n; 32])
    }

    /// A [`ft_coordinator::Space`] as `list_mine` returns it; only the id matters
    /// to the roots guard.
    fn space(id: &str) -> ft_coordinator::Space {
        ft_coordinator::Space {
            space_id: SpaceId::new(id),
            account_id: ft_coordinator::AccountId::new("acct1"),
            name: b"space".to_vec(),
            head_revision_id: None,
            meta_blob_cid: cid(200),
            space_key: None,
        }
    }

    /// The keys of a delete plan, in plan order.
    fn keys(plan: &[SweepCandidate]) -> Vec<String> {
        plan.iter().map(|c| c.key.clone()).collect()
    }

    /// A minimal File [`FileEntry`] at `path` referencing inline blocks `bk`.
    fn file_entry(path: &str, bk: Vec<Cid>) -> (CasefoldKey, FileEntry) {
        let p = CanonicalPath(path.to_string());
        let key = ft_fsmap::casefold_key(&p);
        let entry = FileEntry {
            p,
            t: FileType::File,
            x: false,
            sz: 0,
            pcid: ft_core::Pcid::new([0u8; 32]),
            bk,
            bk_ref: None,
            lt: None,
            wu: None,
        };
        (key, entry)
    }

    /// Uploads every Manifest page of `entries` to the Vault; returns the root.
    async fn upload_manifest(vault: &FsVault, entries: Vec<(CasefoldKey, FileEntry)>) -> Cid {
        let m = ft_manifest::build(entries);
        for (page_cid, bytes) in &m.pages {
            vault
                .put(&ft_hash::manifest_key(page_cid), bytes.clone())
                .await
                .unwrap();
        }
        for (bl_cid, bytes) in &m.blocklists {
            vault
                .put(&ft_hash::blocklist_key(bl_cid), bytes.clone())
                .await
                .unwrap();
        }
        m.root
    }

    #[tokio::test]
    async fn mark_reaches_pages_and_inline_blocks_and_meta() {
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let meta = cid(200);
        let block_a = cid(1);
        let block_b = cid(2);

        let root = upload_manifest(
            &vault,
            vec![
                file_entry("a.txt", vec![block_a]),
                file_entry("b.txt", vec![block_b]),
            ],
        )
        .await;

        let reachable = mark_reachable(&vault, &[(SpaceId::new("s1"), root)], &[meta])
            .await
            .unwrap();

        assert!(reachable.contains(&ft_hash::manifest_key(&root)));
        assert!(reachable.contains(&ft_hash::block_key(&block_a)));
        assert!(reachable.contains(&ft_hash::block_key(&block_b)));
        assert!(reachable.contains(&crate::secrets::meta_key(&meta)));
        // The empty-Manifest root is always protected.
        let empty = ft_manifest::build(Vec::new()).root;
        assert!(reachable.contains(&ft_hash::manifest_key(&empty)));
    }

    #[tokio::test]
    async fn mark_follows_externalized_blocklist() {
        // The dangerous path: a FileEntry whose blocks live in a `blocklist/`
        // object via bk_ref. Missing it would let the GC delete live blocks.
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let meta = cid(200);
        let block_a = cid(10);
        let block_b = cid(11);

        // Build the blocklist object exactly as the reader expects: bare CBOR of
        // Vec<Cid>, addressed by cid_of(bytes).
        let mut bl_bytes = Vec::new();
        ciborium::ser::into_writer(&vec![block_a, block_b], &mut bl_bytes).unwrap();
        let bl_cid = ft_hash::cid_of(&bl_bytes);
        vault
            .put(&ft_hash::blocklist_key(&bl_cid), bl_bytes)
            .await
            .unwrap();

        // A FileEntry that references the blocklist (bk empty, bk_ref set).
        let p = CanonicalPath("big.bin".to_string());
        let entry = FileEntry {
            p: p.clone(),
            t: FileType::File,
            x: false,
            sz: 0,
            pcid: ft_core::Pcid::new([0u8; 32]),
            bk: Vec::new(),
            bk_ref: Some(bl_cid),
            lt: None,
            wu: None,
        };
        let root = upload_manifest(&vault, vec![(ft_fsmap::casefold_key(&p), entry)]).await;

        let reachable = mark_reachable(&vault, &[(SpaceId::new("s1"), root)], &[meta])
            .await
            .unwrap();

        assert!(reachable.contains(&ft_hash::blocklist_key(&bl_cid)));
        assert!(reachable.contains(&ft_hash::block_key(&block_a)));
        assert!(reachable.contains(&ft_hash::block_key(&block_b)));
    }

    #[tokio::test]
    async fn mark_aborts_on_corrupt_blocklist() {
        // A blocklist object whose bytes do NOT hash to its bk_ref must abort the
        // mark (never sweep on corruption).
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let wrong_ref = cid(99);
        // Store arbitrary bytes under the key the entry will point at.
        vault
            .put(
                &ft_hash::blocklist_key(&wrong_ref),
                b"not a valid blocklist".to_vec(),
            )
            .await
            .unwrap();
        let p = CanonicalPath("x".to_string());
        let entry = FileEntry {
            p: p.clone(),
            t: FileType::File,
            x: false,
            sz: 0,
            pcid: ft_core::Pcid::new([0u8; 32]),
            bk: Vec::new(),
            bk_ref: Some(wrong_ref),
            lt: None,
            wu: None,
        };
        let root = upload_manifest(&vault, vec![(ft_fsmap::casefold_key(&p), entry)]).await;

        let err = mark_reachable(&vault, &[(SpaceId::new("s1"), root)], &[cid(200)])
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::SpaceState(_)));
    }

    #[tokio::test]
    async fn mark_retains_the_sidecar_of_a_live_block_and_leaves_orphans_unmarked() {
        // A live (reachable) Block's `keys/<space_id>/<cid>` sidecar must be
        // marked reachable so the GC never collects it (§4.5, ADR 0015 — sidecar
        // lives with its Block). A sidecar whose Block is NOT referenced stays
        // unmarked, so the `keys/` sweep can reclaim it.
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let meta = cid(200);
        let live_block = cid(1);
        let orphan_block = cid(2);

        let root = upload_manifest(&vault, vec![file_entry("a.txt", vec![live_block])]).await;
        let reachable = mark_reachable(&vault, &[(SpaceId::new("s1"), root)], &[meta])
            .await
            .unwrap();

        // The live Block AND its sidecar (under THIS Space's subtree) are reachable.
        assert!(reachable.contains(&ft_hash::block_key(&live_block)));
        assert!(reachable.contains(&ft_diff::keys_key("s1", &live_block)));
        // A Block referenced by nothing — and thus its sidecar — is NOT reachable,
        // so both would be swept (subject to the grace-period).
        assert!(!reachable.contains(&ft_hash::block_key(&orphan_block)));
        assert!(!reachable.contains(&ft_diff::keys_key("s1", &orphan_block)));
    }

    #[tokio::test]
    async fn mark_scopes_each_spaces_sidecar_and_never_crosses_spaces() {
        // Two Spaces of one Account share the SAME Block cid (the Block object is
        // Account-deduped) but each has its OWN per-Space sidecar. The mark, run
        // over both Spaces' roots, must reach `keys/<A>/<cid>` AND `keys/<B>/<cid>`
        // — and must NOT mark Space B's sidecar reachable only because Space A
        // references the shared Block. If it did, a real two-Space vault could
        // sweep a live sidecar (BUG this fix guards against).
        let dir = tempfile::tempdir().unwrap();
        let vault = FsVault::new(dir.path());
        let meta = cid(200);
        let shared_block = cid(1);

        // Both Spaces reference the same shared Block from their own Manifest.
        let root_a = upload_manifest(&vault, vec![file_entry("a.txt", vec![shared_block])]).await;
        let root_b = upload_manifest(&vault, vec![file_entry("b.txt", vec![shared_block])]).await;
        // (root_a == root_b would collapse the point; different paths keep them
        // distinct so the walk genuinely visits two Spaces' trees.)
        assert_ne!(root_a, root_b);

        let reachable = mark_reachable(
            &vault,
            &[
                (SpaceId::new("space-a"), root_a),
                (SpaceId::new("space-b"), root_b),
            ],
            &[meta],
        )
        .await
        .unwrap();

        // The shared Block AND both Spaces' sidecars are reachable.
        assert!(reachable.contains(&ft_hash::block_key(&shared_block)));
        assert!(reachable.contains(&ft_diff::keys_key("space-a", &shared_block)));
        assert!(reachable.contains(&ft_diff::keys_key("space-b", &shared_block)));

        // A THIRD Space that references nothing has no reachable sidecar even for
        // the shared cid — the mark is strictly per-Space, never cross-Space.
        assert!(!reachable.contains(&ft_diff::keys_key("space-c", &shared_block)));
    }

    #[test]
    fn partition_sweep_reclaims_an_orphan_sidecar_under_the_keys_prefix() {
        // With `keys/` now a swept prefix, an orphan `keys/<space_id>/<cid>` object (its Block
        // gone or never live) that is old enough is reclaimed exactly like any
        // other orphan, while a live block's sidecar (in the reachable set) is kept.
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let grace = Duration::from_secs(3600);
        let mut reachable = HashSet::new();
        reachable.insert("keys/aa/live".to_string());

        let objects = vec![
            VaultObject {
                key: "keys/aa/live".to_string(),
                last_modified: Some(now - Duration::from_secs(10_000)),
            },
            VaultObject {
                key: "keys/bb/orphan-old".to_string(),
                last_modified: Some(now - Duration::from_secs(10_000)),
            },
        ];
        let (plan, _kept) = partition_sweep(objects, &reachable, now, grace);
        assert_eq!(keys(&plan), vec!["keys/bb/orphan-old".to_string()]);
    }

    #[test]
    fn partition_sweep_holds_back_reachable_and_young() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let grace = Duration::from_secs(3600);
        let mut reachable = HashSet::new();
        reachable.insert("blocks/aa/live".to_string());

        let objects = vec![
            // Reachable, old → kept.
            VaultObject {
                key: "blocks/aa/live".to_string(),
                last_modified: Some(now - Duration::from_secs(10_000)),
            },
            // Unreachable + old → SWEEP.
            VaultObject {
                key: "blocks/bb/orphan-old".to_string(),
                last_modified: Some(now - Duration::from_secs(10_000)),
            },
            // Unreachable but YOUNG → kept by grace.
            VaultObject {
                key: "blocks/cc/orphan-young".to_string(),
                last_modified: Some(now - Duration::from_secs(60)),
            },
            // Unreachable, no mtime → kept (never sweep on uncertainty).
            VaultObject {
                key: "blocks/dd/orphan-nomtime".to_string(),
                last_modified: None,
            },
        ];

        let (plan, kept_by_grace) = partition_sweep(objects, &reachable, now, grace);
        assert_eq!(keys(&plan), vec!["blocks/bb/orphan-old".to_string()]);
        assert_eq!(kept_by_grace, 2); // orphan-young + orphan-nomtime
    }

    // ----- roots guard (a mark set with no roots would wipe the Vault) -----

    #[test]
    fn gc_refuses_when_the_authenticated_account_lists_no_spaces_at_all() {
        // The whole-Vault wipe: reachability comes ONLY from list_mine(), so with
        // zero Spaces every object past the grace-period looks like garbage.
        let err = guard_roots(&[], &SpaceId::new("space1")).unwrap_err();
        assert!(matches!(err, EngineError::Refused(_)));
        let msg = err.to_string();
        assert!(msg.contains("NO Spaces"), "{msg}");
        // The message must point at the real cause, not at the Vault.
        assert!(msg.contains("whoami"), "{msg}");
    }

    #[test]
    fn gc_refuses_when_the_account_does_not_own_the_space_the_caller_pointed_at() {
        // A login that owns OTHER Spaces is just as dangerous: this Space's objects
        // are unreachable from the roots that login can see.
        let err =
            guard_roots(&[space("other1"), space("other2")], &SpaceId::new("space1")).unwrap_err();
        assert!(matches!(err, EngineError::Refused(_)));
        let msg = err.to_string();
        assert!(msg.contains("space1"), "{msg}");
        assert!(msg.contains("2 Space(s)"), "{msg}");
    }

    #[test]
    fn gc_runs_when_the_roots_include_the_space_the_caller_pointed_at() {
        guard_roots(&[space("other"), space("space1")], &SpaceId::new("space1")).unwrap();
    }

    // ----- proportion guard -----

    #[test]
    fn gc_refuses_to_apply_a_sweep_that_would_delete_most_of_the_vault() {
        let err = guard_sweep_proportion(90, 100, DEFAULT_MAX_SWEEP_FRACTION).unwrap_err();
        assert!(matches!(err, EngineError::Refused(_)));
        let msg = err.to_string();
        assert!(msg.contains("90 of 100"), "{msg}");
        assert!(msg.contains("Nothing was deleted"), "{msg}");
    }

    #[test]
    fn the_proportion_guard_passes_an_ordinary_orphan_sweep() {
        guard_sweep_proportion(5, 100, DEFAULT_MAX_SWEEP_FRACTION).unwrap();
    }

    #[test]
    fn the_proportion_guard_can_be_raised_for_a_legitimately_huge_sweep() {
        // The override exists because a real all-garbage Vault exists (a huge
        // staged upload the user then deleted before any head referenced it).
        guard_sweep_proportion(100, 100, 1.0).unwrap();
    }

    #[test]
    fn the_proportion_guard_stands_down_on_a_vault_too_small_to_reason_about() {
        // 2 of 3 objects is 67% garbage and perfectly healthy on a fresh Space.
        guard_sweep_proportion(2, 3, DEFAULT_MAX_SWEEP_FRACTION).unwrap();
    }

    #[test]
    fn a_nan_threshold_falls_back_to_the_default_instead_of_waiving_the_guard() {
        // Every comparison against NaN is false, so a NaN would disable the guard
        // silently — the one way to waive it must be an explicit `>= 1.0`.
        assert!(guard_sweep_proportion(90, 100, f64::NAN).is_err());
    }

    // ----- grace-period under clock skew -----

    #[test]
    fn the_enforced_grace_window_is_widened_by_the_clock_skew_allowance() {
        assert_eq!(
            enforced_grace(Duration::from_secs(100), Duration::from_secs(30)),
            Duration::from_secs(130)
        );
    }

    #[test]
    fn a_zero_grace_period_stays_zero_so_an_explicit_opt_out_is_never_undone() {
        assert_eq!(
            enforced_grace(Duration::ZERO, DEFAULT_CLOCK_SKEW_ALLOWANCE),
            Duration::ZERO
        );
    }

    #[test]
    fn an_object_only_just_past_the_grace_period_is_kept_by_the_skew_allowance() {
        // Ages mix clocks: mtime is the provider's, `now` is ours. A local clock
        // ahead of the provider's inflates every age, so an object that looks
        // 3700s old may really be younger than the 3600s window. The widened
        // window is what holds it back.
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let grace = Duration::from_secs(3600);
        let skew = Duration::from_secs(600);
        let objects = vec![VaultObject {
            key: "blocks/aa/just-past-grace".to_string(),
            last_modified: Some(now - Duration::from_secs(3700)),
        }];

        let (bare, _) = partition_sweep(objects.clone(), &HashSet::new(), now, grace);
        assert_eq!(keys(&bare), vec!["blocks/aa/just-past-grace".to_string()]);

        let (widened, kept) =
            partition_sweep(objects, &HashSet::new(), now, enforced_grace(grace, skew));
        assert!(widened.is_empty());
        assert_eq!(kept, 1);
    }

    #[test]
    fn the_delete_plan_is_ordered_oldest_first() {
        // Oldest-first bounds the damage of an abort mid-sweep: the objects most
        // likely to be re-referenced by a racing commit go last (residual race 1).
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let grace = Duration::from_secs(60);
        let objects = vec![
            VaultObject {
                key: "blocks/bb/newer".to_string(),
                last_modified: Some(now - Duration::from_secs(100)),
            },
            VaultObject {
                key: "blocks/aa/oldest".to_string(),
                last_modified: Some(now - Duration::from_secs(10_000)),
            },
            VaultObject {
                key: "blocks/cc/middle".to_string(),
                last_modified: Some(now - Duration::from_secs(5_000)),
            },
        ];
        let (plan, _) = partition_sweep(objects, &HashSet::new(), now, grace);
        assert_eq!(
            keys(&plan),
            vec![
                "blocks/aa/oldest".to_string(),
                "blocks/cc/middle".to_string(),
                "blocks/bb/newer".to_string(),
            ]
        );
    }

    // ----- forensics of a partial run -----

    #[test]
    fn an_aborted_apply_names_every_object_it_had_already_deleted() {
        let deleted = vec!["blocks/aa/one".to_string(), "blocks/bb/two".to_string()];
        let record = deleted_record(&deleted, 7);
        assert!(record.contains("2 of 7"), "{record}");
        assert!(record.contains("blocks/aa/one"), "{record}");
        assert!(record.contains("blocks/bb/two"), "{record}");
    }

    #[test]
    fn an_aborted_apply_that_had_deleted_nothing_says_so_explicitly() {
        assert_eq!(deleted_record(&[], 7), "nothing had been deleted yet");
    }

    #[test]
    fn the_deleted_record_truncates_a_huge_deleted_set_but_still_counts_all_of_it() {
        let deleted: Vec<String> = (0..50).map(|i| format!("blocks/aa/{i:02}")).collect();
        let record = deleted_record(&deleted, 100);
        assert!(record.contains("50 of 100"), "{record}");
        assert!(record.contains("blocks/aa/00"), "{record}");
        assert!(record.contains("and 30 more"), "{record}");
        assert!(!record.contains("blocks/aa/49"), "{record}");
    }

    #[test]
    fn gc_options_keep_working_with_struct_update_syntax_and_default_to_the_safe_knobs() {
        // The CLI constructs GcOptions positionally-by-name; every new safety knob
        // must arrive with a safe default so `..Default::default()` stays correct.
        let opts = GcOptions {
            apply: true,
            grace: Duration::from_secs(1),
            ..Default::default()
        };
        assert!(!GcOptions::default().apply);
        assert_eq!(opts.clock_skew_allowance, DEFAULT_CLOCK_SKEW_ALLOWANCE);
        assert_eq!(opts.max_sweep_fraction, DEFAULT_MAX_SWEEP_FRACTION);
    }
}
