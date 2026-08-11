# Approved-workflow verification contract

- Contract: `INCIDENTSEAL-WORKFLOW-EXECUTION-001`
- Version: `1.0`
- Milestone: `IS6-U02`
- Machine contract: `fixtures/workflow-verification/execution-contract.valid.json`

## Claim boundary

`incidentseal verify --manifest PATH --json` may execute only after the existing external approval inspection returns `MATCH` for the exact manifest digest, workflow ID, repository remote, and repository-relative manifest path. The command rechecks approval before every step. It has no approval write path and cannot soften `MISSING`, `MISMATCH`, `EXPIRED`, invalid custody, or changed manifest bytes into an executable state.

Version 1 executes only manifest runner values `python` and `node`. Other schema-valid runner values fail as `INVALID` before Docker access. This is a deliberate release profile, not permission to reinterpret host commands or add a general execution platform.

## Exact source and staging

The manifest must be inside one Git worktree. Its repository remote and commit must match the exact checkout, and the worktree must be clean. `repository.tree_digest` is SHA-256 over the exact bytes returned by `git ls-tree -r -z --full-tree COMMIT`; the algorithm identifier is `sha256-git-ls-tree-z-v1`.

Only manifest-declared inputs from that committed tree are copied into bounded temporary custody. Symlinks, submodules, reparse points, overlapping inputs, untracked source, repository custody, OneDrive custody, more than 4,096 files, or more than 100 MiB fail closed. The staged workspace is mounted read-only. Persistent step outputs are not supported in v1; step evidence consists of bounded captured streams, identities, events, and the terminal portable receipt.

## Runtime boundary

The host CLI starts exact image IDs from `requirements/topology-runtime.lock.json` with direct argv and no shell. Each step uses numeric user `65532:65532`, a read-only root, `network=none`, all capabilities dropped, `no-new-privileges`, a 64-process limit, a 512 MiB memory limit, one bounded `/tmp` tmpfs, an exact small environment allowlist, and labels binding the run, step, manifest, contract, and image identity. No host environment, Docker socket, secret, privileged mode, host network, broad host mount, or runtime egress is admitted. Cancellation may stop only the exact owned container.

## Evidence, recovery, and claims

The internal writer owns restrictive external run custody. It appends canonical `incidentseal-run-event/v1` records and content-addressed step records atomically before progress is acknowledged. The agent-facing event stream is read-only. Existing PostgreSQL-backed platform event reads remain compatible; workflow-run reads add the exact external archive without granting an append command.

A nonterminal run is resumed only under the same repository, workflow, manifest digest, commit, and tree digest. Because step input is read-only, network is absent, and persistent output is forbidden, an interrupted exactly owned step can be reobserved and safely replayed. Unknown ownership is `INCONCLUSIVE`; conflicting exact ownership is product `FAIL`. Terminal runs and prior attempts are immutable.

Every claim-required step must complete with an expected exit code. An unexpected exit is product `FAIL`; missing evidence is `INCONCLUSIVE`; invalid policy, source, custody, or runtime identity is `INVALID`. Cancelled, failed, stale, and superseded lifecycle states never gain fabricated verdicts. Packaging remains blocked until the implementation and its exact credential-free public replay pass.

## Non-claims

This contract does not approve a manifest, execute a workflow, build an image, resolve redistribution, publish a package or release, or support arbitrary host, remote, PostgreSQL, Compose, or receipt commands. Those are separate gates.
