# ADR-0009: Compose the verified fixed surfaces at the host

- Status: accepted
- Date: 2026-08-10
- Unit: `IS4-U06`

## Decision

IncidentSeal will evaluate integrated evidence and recovery by composing the already locked receipt, reliability, journal, recovery, and backup/restore surfaces from the host CLI. Each stage keeps isolated disposable custody and must tear down before the next stage. The complete sequence runs twice and compares only stable semantic identities while retaining every individual content-addressed receipt.

The matrix will not create a long-lived orchestration container, mount the Docker socket, share a privileged database volume across unrelated failure scenarios, or use a repository manifest as authority. Cross-stage integration is established through exact implementation locks, image identities, contract digests, state-separated observations, content digests, protected-volume snapshots, and teardown receipts.

## Consequences

- Existing fixed probes remain independently inspectable and reusable.
- A stage cannot leave custody that contaminates a later stage or masks cleanup failure.
- Raw PostgreSQL custom archives remain individually content-addressed; normalized TOC and restored semantic state, not incidental archive bytes, are the cross-cycle comparison.
- The aggregate PASS cannot erase a nested product FAIL, `INCONCLUSIVE`, `INVALID`, cancellation, failure, stale run, or superseded run.
- The first contract step is runtime-free; implementation and public reproduction remain separate evidence gates.
