# Approved-workflow verification implementation

The `IS6-U02` implementation adds the first real `incidentseal verify --manifest PATH --json` path beneath the publicly replayed execution contract. It does not add approval authority, a general host-command runner, persistent outputs, arbitrary images, or a Docker-owning container.

## Authority and source order

The host loads and canonicalizes the closed v1 manifest, then requires an external approval result of `MATCH` before Git inspection or Docker access. The checkout must have the exact `origin`, `HEAD`, clean status, and SHA-256 of `git ls-tree -r -z --full-tree HEAD` declared by the manifest. Version 1 rejects runners other than Python and Node, commands that do not begin with their declared runner, persistent outputs, overlapping inputs, missing inputs, symlinks, submodules, reparse custody, and any OneDrive repository or state root.

Staging reads committed blob bytes with `git cat-file`; it never copies mutable worktree bytes or mounts the repository. Only declared regular files are recreated beneath a new temporary workspace outside repository and OneDrive custody. The workspace is read-only in the container and is removed after every terminal or rejected runtime attempt.

## Runtime

The host resolves exact Python and Node image IDs from `requirements/topology-runtime.lock.json`. Every created step container is inspected before start for its exact image, run/step/manifest/contract labels, numeric user, one read-only staged mount, `network=none`, read-only root, dropped capabilities, no-new-privileges, 64-process limit, 512 MiB memory limit, and bounded `/tmp` tmpfs.

The pinned distroless images intentionally contain no shell or `env` utility. A no-shell language bootstrap removes immutable image configuration and the private bootstrap argument before user code. Python v1 supports direct script, `-m`, and `-c` profiles in-process; Node uses `spawnSync` with `shell:false`. The effective user command receives only `HOME`, `PYTHONDONTWRITEBYTECODE`, `PYTHONHASHSEED`, and `TZ`. No host environment, secret, socket, external network, or broad mount is forwarded.

## Evidence and recovery

Production run custody is fixed under the platform IncidentSeal state root, never selected by the agent-facing CLI. The internal writer appends canonical run events with `ab` plus `fsync`, stores step records and terminal receipts by SHA-256 with exclusive creation, and keeps verification verdict separate from lifecycle. `run events` first checks restrictive external workflow custody and otherwise preserves the existing PostgreSQL event stream.

The active key binds repository remote, workflow ID, manifest digest, commit, and tree digest. A nonterminal exact-key attempt resumes; a terminal attempt is never rewritten. An exactly one matching leftover runtime yields `INCONCLUSIVE`, competing matches yield product `FAIL`, and authority loss becomes `stale`. Keyboard interruption may stop and remove only the exact label-owned container and records `cancelled` with no verdict.

## Current proof boundary

The disposable real probes use temporary in-process test authority and temporary Local AppData custody. The two-runner probe exercises the exact Python and Node images, effective environment, real mounts, isolation inspection, captured streams, append-only events, receipt, and teardown. The recovery probe separately preserves product `FAIL`, missing-evidence `INCONCLUSIVE`, stale authority, cancellation, same-key resume, crash-after-started-step safe replay, terminal immutability, different-digest non-resume, and an unowned lookalike that the product refuses to stop. The probes never write the production approval store. The production CLI still returns `INVALID` at exit 12 while approval is missing. A real repository workflow claim remains gated on a fixed candidate manifest and exact interactive operator approval.
