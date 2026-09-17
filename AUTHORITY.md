# Großer Adler — Authority Boundary

Großer Adler is an independent observer, auditor and advisor. The authoritative V1 architecture is `ARCHITECTURE.md`.

Adler may read typed, bounded, secret-safe primary evidence; append immutable findings under its own state root; read one exact active Grabowski lane target; and publish the computed current finding view only to its own state root after validating a Grabowski-owned `.adler/inbox.json` pointer.

Adler has no work-state authority and no decision or execution authority. It must not acquire claims or leases, create Bureau/operator tasks, start coding agents, edit product/configuration files, mutate the Git index, commit, push, mutate pull requests, merge, deploy, control services, signal processes, mutate/reveal credentials, or create an admission/blocking policy.

`Finding != Task != Claim != Fix != Blockade != Work Lane`. Severity is descriptive; binding strength and checkpoint freshness remain separate evidence dimensions.

The central finding store is append-only history. The external inbox target is a replaceable current view bound to an exact active lane and current worktree checkpoint; `.adler/inbox.json` is only Grabowski-owned pointer metadata to that target.

## Operating Trust Boundary
Adler runs its own MCP process, its own tool catalogue and its own tunnel path. The Grabowski MCP is not an observation backend for Adler; Git, GitHub, user-systemd and bounded process/socket observations are read from their responsible primary interfaces instead of trusting another operator's summary of itself.

The HTTP MCP transport binds only to `127.0.0.1`; external reachability is delegated to the dedicated tunnel client. Tunnel credentials and GitHub credentials are separate secret domains. `GROSSER_ADLER_GITHUB_TOKEN` is forwarded only to `/usr/bin/gh` as `GH_TOKEN`; Git, systemd, process and socket subprocesses do not receive it. Missing dedicated GitHub credentials make GitHub reads fail closed, and allowed subprocess output passes through central secret redaction.
