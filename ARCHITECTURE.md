# Großer Adler V1 — Minimal Architecture

## 1. Purpose
Großer Adler is an independent second look on running work. It reads primary evidence, records evidence-bound findings, and places the current advisory view beside an explicitly known Grabowski worktree. It does not execute or steer the work.

## 2. Authority Boundary
Adler owns observation, verification, advisory findings, the immutable finding store, and computed inbox files under its own state root. Grabowski owns work identity, decisions, claims, leases, tasks, product mutations, Git index/commit/push, pull-request mutation, merge, deployment, service/process control, credentials, effect policy, and the worktree-local `.adler` pointer metadata. Severity is not authority.

## 3. Finding Contract
New findings use `adler-finding-v1`: `finding_id`, `finding_sha256`, `kind`, `severity`, `confidence`, `subject`, `checkpoint`, `binding_strength`, `summary`, `evidence_refs`, optional `recommendation` and `affected_effects`, plus `observed_at`. Kinds are `observation`, `risk`, `contradiction`, `missing_evidence`, or `advice`. The digest covers the complete stored V1 core but is an integrity check, not an authenticity signature. Changes are appended as new recheck records; historical records are never rewritten. A recheck always references the original root finding, never another recheck. Explicit historical legacy records remain readable but do not define V1 delivery semantics; malformed or ambiguous V1-like records are not downgraded to legacy.

## 4. Worktree-Sidecar Contract
Grabowski remains authoritative for `lane_id`, repository, worktree, branch, and purpose. For an Adler-enabled lane, Grabowski creates the local `.adler/` metadata and an exact `.adler/inbox.json` symlink to Adler state at `<state>/worktree-inboxes/<lane_id>.json`. Adler validates that pointer but writes only the external target under its own state root. The resolved inbox remains a computed current view for the worktree HEAD, reconstructible from the central finding store, and never canonical history. Git exclusion and pointer creation belong to Grabowski; Adler has no worktree, Git-metadata, or Git-index write authority. No finding-to-task/lane resolver exists.

## 5. Explicit Non-Goals
V1 has no Adler work-state database, current_work overlay, supervision lifecycle, delivery queue, acknowledgements, task conversion, admission engine, generic file writer, shell, coding-agent start, Bureau mutation, product write, Git-index mutation, commit, push, PR mutation, merge, deploy, service control, process signal, credential mutation, or generic probe sandbox.

## 6. Failure Semantics
The immutable finding is persisted before inbox delivery is attempted. Delivery requires the exact Grabowski-owned worktree pointer and never creates or repairs that pointer. Delivery failure never rolls back history and never means “no findings”. Invalid JSON, a malformed/ambiguous V1 record, a digest mismatch, or any other unreadable canonical finding makes the finding-store observation incomplete and blocks publication of a new `source_complete=true` inbox; Adler does not silently repair or discard such records. An absent, invalid, failed, or checkpoint-stale inbox is unknown/stale, not evidence of absence. Normal local work remains possible when Adler is unavailable. Any later protected-effect policy belongs to Grabowski and consumes facts only; Adler never returns ALLOW, DENY, or BLOCK.
