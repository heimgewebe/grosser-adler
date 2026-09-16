# Großer Adler V1 — Minimal Architecture

## 1. Purpose
Großer Adler is an independent second look on running work. It reads primary evidence, records evidence-bound findings, and places the current advisory view beside an explicitly known Grabowski worktree. It does not execute or steer the work.

## 2. Authority Boundary
Adler owns observation, verification, advisory findings, the immutable finding store, and only the `.adler` sidecar it creates. Grabowski owns work identity, decisions, claims, leases, tasks, product mutations, Git index/commit/push, pull-request mutation, merge, deployment, service/process control, credentials, and effect policy. Severity is not authority.

## 3. Finding Contract
New findings use `adler-finding-v1`: `finding_id`, `finding_sha256`, `kind`, `severity`, `confidence`, `subject`, `checkpoint`, `binding_strength`, `summary`, `evidence_refs`, optional `recommendation` and `affected_effects`, plus `observed_at`. Kinds are `observation`, `risk`, `contradiction`, `missing_evidence`, or `advice`. Changes are appended as new recheck records; historical records are never rewritten. Legacy records remain readable but do not define V1 delivery semantics.

## 4. Worktree-Sidecar Contract
Grabowski remains authoritative for `lane_id`, repository, worktree, branch, and purpose. Adler reads that exact active lane and may publish only inside `<worktree>/.adler/`: the current `inbox.json` plus an Adler-owned local `.gitignore` helper. The inbox is a computed current view for the worktree HEAD, reconstructible from the central finding store, and never canonical history. Full Git exclusion of the `.adler/` directory belongs to Grabowski as worktree setup metadata; Adler does not write Git metadata or the Git index. No finding-to-task/lane resolver exists.

## 5. Explicit Non-Goals
V1 has no Adler work-state database, current_work overlay, supervision lifecycle, delivery queue, acknowledgements, task conversion, admission engine, generic file writer, shell, coding-agent start, Bureau mutation, product write, Git-index mutation, commit, push, PR mutation, merge, deploy, service control, process signal, credential mutation, or generic probe sandbox.

## 6. Failure Semantics
The immutable finding is persisted before sidecar delivery is attempted. Delivery failure never rolls back history and never means “no findings”. An absent, failed, or checkpoint-stale inbox is unknown/stale, not evidence of absence. Normal local work remains possible when Adler is unavailable. Any later protected-effect policy belongs to Grabowski and consumes facts only; Adler never returns ALLOW, DENY, or BLOCK.
