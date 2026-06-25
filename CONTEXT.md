# filething

filething is a developer-focused file-sync SaaS: a CLI that keeps a developer's working folders identical across their machines (Mac, Windows, Linux VPS) with continuous background sync. This document defines the ubiquitous language of the project — pick these words in code, docs, and conversation.

## Sync

**Space**:
A named, independently-synced folder tree — the unit of sync. A space has exactly one root folder tree; to sync separate folders, create separate spaces. Each device chooses which spaces to sync and maps each one one-to-one to a single local folder (the path may differ per device).
_Avoid_: folder, share, vault, repo, project, sync set

**Device**:
A machine paired to an account that runs the filething CLI and participates in sync.
_Avoid_: machine, client, node, peer, computer

**Daemon**:
The always-on background process on a device that watches files and performs continuous sync.
_Avoid_: agent, service, worker, background process

**Block**:
A content-addressed chunk of a file's bytes — the unit of transfer, deduplication, and encryption. A block is addressed by the hash of its ciphertext; deduplication is scoped to the account. Only changed blocks move.
_Avoid_: chunk, piece, segment, shard

**Manifest**:
The index describing a space's complete file tree at a point in time, mapping each path to its ordered list of blocks. The coordinator stores it in cleartext — it holds paths and block references, never file contents.
_Avoid_: index, tree, catalog, listing

**Revision**:
A saved manifest representing a space's state at a moment, with a single parent (the revision it was based on). Revisions form a per-space linear chain whose head the coordinator advances — the basis of version history and of conflict detection.
_Avoid_: version, snapshot, commit, checkpoint

**Space head**:
The single, tiny coordinator-held pointer to a space's current revision. A commit succeeds via an atomic compare-and-swap on this pointer; manifest pages are written first (content-addressed, immutable), so a document-size limit never affects commit atomicity.
_Avoid_: tip, HEAD, latest, current pointer

**Conflict copy**:
The extra file kept when the same path changed on two devices relative to their common base revision, so no change is lost (e.g. `notes (conflict from mac).md`). A device whose base revision is no longer the space head must first reconcile — that is divergence, not yet a conflict; only a path changed on both sides becomes a conflict copy. Detection is causal (from the revision chain), never from wall-clock time.
_Avoid_: conflicted copy, fork, duplicate, merge

**Ignore file**:
A per-space `.filethingignore` listing paths the user chose to exclude from sync. Empty by default — filething never drops data you did not choose to exclude. Distinct from the engine's automatic handling of a derived path.
_Avoid_: exclude list, gitignore, denylist

**Derived path**:
A path whose contents are regenerated from versioned source rather than synced byte-for-byte — e.g. `node_modules/`, `target/`, `.next/`, a `venv`. By default the engine does not move its bytes; it syncs the source and lockfile and leaves the path ready to regenerate, offering (never auto-running) the install/build command on the destination device.
_Avoid_: build artifact, generated folder, ignored path, cache

## Storage & coordination

**Vault**:
The S3-compatible storage location that holds a space's encrypted blocks — the data plane. It is one of: a managed vault (filething's rented R2) or a self-hosted vault (a device in serve mode).
_Avoid_: bucket, backend, blob store, storage, store

**Serve mode**:
Running a device (e.g. a VPS or Mac mini) as a self-hosted vault for its owner's spaces. The serve validates short-lived, coordinator-signed grants locally and never hands its storage keys to the coordinator.
_Avoid_: self-host, host mode, server mode

**Coordinator**:
The always-on control-plane service (built on Convex) that handles identity, device pairing, manifests, and the change feed. It never sees file bytes and never holds a self-hosted vault's storage keys; it does see manifest metadata in cleartext (paths, file tree, block references).
_Avoid_: brain, control plane, server, backend, hub

**Change feed**:
The real-time stream the coordinator pushes to devices announcing which blocks and manifests changed.
_Avoid_: notifications, events, push, subscription, websocket

**Grant**:
A short-lived, coordinator-signed authorization (scoped to account + space + operation) that a device presents to a vault. The managed vault turns it into an R2 presigned URL; a self-hosted serve validates it offline against the coordinator's public key.
_Avoid_: token, permission, credential, lease

## Identity & access

_v1 scope: spaces are personal — each belongs to exactly one account. There is no team, member, role, or space membership yet; the "Team" price tier is, in v1, multi-seat for one owner. Real collaboration (sharing a space across accounts) is reserved for v2._

**Account**:
A single person's identity. Owns spaces and devices and carries the subscription.
_Avoid_: user, profile, login, customer

**Pairing**:
Authorizing a new device onto an account, via browser login or a device code (for headless machines).
_Avoid_: enrollment, registration, linking, onboarding

**Device key**:
The per-device key pair whose private half never leaves the device; used to wrap a space key for that device during pairing.
_Avoid_: device secret, machine key, node key

**Space key**:
The key that protects a space. Each block is encrypted with a per-block random key, which is wrapped by the space key. The space key is wrapped per account with access (in v1, exactly one: the owner) and escrowed by the account, so it survives losing every device — recoverable via account login. Blocks are encrypted on the device before they leave it.
_Avoid_: secret, password, master key, cipher key

**Recovery phrase**:
An optional user-held secret, never seen by the coordinator, that roots the advanced content-private mode in which not even filething can decrypt. Not used in the default escrow model, where keys are recoverable via account login.
_Avoid_: seed, passphrase, recovery key, mnemonic

## Billing

**Seat**:
The billable unit — a paid device on an account. filething charges for coordination (connecting devices), not for storing bytes.
_Avoid_: license, slot, subscription

**Metered storage**:
The usage-based add-on charged per GB when an account uses a managed vault.
_Avoid_: usage billing, overage, consumption
