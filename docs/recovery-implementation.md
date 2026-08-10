# Host-only recovery implementation

- Unit: `IS4-U04`
- Contract: `INCIDENTSEAL-RECOVERY-001`
- Machine surface: `topology.recovery-probe`
- Implementation lock: `requirements/recovery-implementation.lock.json`

## Authority boundary

The implementation does not add a general workflow-recovery command. The only exposed surface is the argument-free fixed `platform-validation` probe. It reads no repository workflow manifest, never accesses or writes operator approval, accepts no run/container/path/command input, and executes only synthetic non-sensitive cases in the already locked disposable project.

The host CLI remains the sole Docker owner. Recovery containers receive no Docker socket, secret, mount, privilege, host network, or external network. Runtime ownership requires the exact container ID, name, locked image ID, non-root user, contract digest, run ID, workflow holder, workflow fence token, read-only root, `network=none`, dropped capabilities, and `no-new-privileges` before a stop is possible.

## Two separate leases

The frozen observation describes the workflow lease. An active workflow lease always defers. When that lease is expired, PostgreSQL atomically acquires a distinct recovery fence under a per-run advisory transaction lock. The recovery fence prevents a second recoverer from acting while preserving the truthful `expired` workflow-lease observation required by the contract.

Fence acquisition compares the exact workflow fence token, rejects an active workflow owner, rejects another unexpired recovery holder, increments a monotonic recovery token, and expires within five minutes. Only the exact recovery holder/token may authorize a process stop or release the fence. The runner role and `PUBLIC` have no access to the fence table or functions.

## Durable action ordering

One content-addressed decision is written atomically to non-repository, non-OneDrive host custody before an effect. The executor orders mutations as follows:

1. acquire the recovery fence;
2. repeat the complete observation and reject drift;
3. persist the exact observation, decision, evidence record, and optional terminal record;
4. execute a fixed idempotent replay if and only if the decision allows it;
5. append or exactly replay the recovery evidence record;
6. verify the live recovery fence and exact runtime again before any stop;
7. stop and remove only that exact runtime, then build and classify a new observation;
8. append or exactly replay the null-verdict terminal record when planned; and
9. archive the completed pending decision and release the recovery fence.

If the host stops after an evidence append, the pending record retains the original canonical bytes. A later exact holder replays those bytes as a no-op and appends only the missing terminal record. Lifecycle `cancelled`, `failed`, and `stale` remain distinct; nonterminal ambiguity stays `INCONCLUSIVE`; conflicting effects are recovery `FAIL`; no non-completed event receives a run verdict.

## Real probe boundary

The real CLI probe covers active-owner and unowned-runtime no-action cases, owned-orphan stop/reobservation/replay, running cancellation, retained nonzero failure, authority staleness, conflicting versus ambiguous effects, crash-after-evidence resume under a new fence, concurrent-recoverer exclusion, runner privilege denial, PostgreSQL restart persistence, exact protected-volume identity, and complete disposable teardown.

This proves the fixed host recovery mechanism, not arbitrary repository workflow recovery. Integration with an approved workflow manifest remains unavailable until a later bounded command can bind real authority and step/effect observations without broadening this surface.
