# Evaluation report

## Current conclusion

IncidentSeal has a verified local hardened topology checkpoint, not a releasable product. `checkpoint-is-0003` binds commit `a0c05070dd1d147aecae6b4ed686440414a3aa27` through annotated tag object `28eea260147265e7dd0328dcd072e134586a2ff0`.

## Verified surfaces

- Host-owned Docker and Compose with no container engine endpoint in workloads.
- Four exact local image identities on an internal-only Compose network with numeric non-root users, read-only roots, all capabilities dropped, no-new-privileges, no published ports, no secrets, and narrow staged mounts.
- PostgreSQL 18.4 with idempotent migration, distinct bootstrap and application roles, bounded DML, denied DDL and migration-ledger reads, restart persistence, and retained failure volumes.
- Shipped Python and Node application commands with exact positive outputs, exact database rows, cross-runner canonical input identity, language-bound result identity, and malformed-input rejection.
- Disposable reliability behavior that keeps completed verification `PASS`, `FAIL`, and `INVALID` separate from lifecycle `failed` and `cancelled`, recovers after database outage, persists through restart, detects orphans, and removes disposable resources without touching three protected evidence volumes.
- Credential-free public-clone replay with 50 tests, four machine-contract mutations, 16 topology mutations, 15 implementation mutations, Git object integrity, high-confidence secret scan, real reliability execution, and annotated-marker verification.

## Retained negative evidence

- Revision-1 PostgreSQL startup `FAIL` from non-root volume ownership.
- Revision-2 database least-privilege `FAIL` from a shared bootstrap superuser.
- Two Python-surface product `FAIL` attempts caused by Compose transport/orphan stderr policy.
- Malformed commands and harness invocations retained as `INVALID` rather than product failure.
- Real database-outage lifecycle `failed` and host-stop lifecycle `cancelled` observations with no fabricated verification verdict.

## Remaining before v0.1.0

Append-only portable receipts, idempotency and duplicate handling, durable cancellation records, crash recovery, verified PostgreSQL backup/restore, independent offline receipt verification, dashboard, broader scenario evaluation, packaged host CLI, SBOM/provenance/scan/reproducibility receipts for release artifacts, exact-digest registry publication, downloaded-release validation, and release documentation remain unverified.

Image redistribution remains `INCONCLUSIVE`; no derived image was published. No workflow manifest is approved and no workflow was executed.

## IS4-U04 local recovery candidate

The frozen recovery contract has a real local implementation candidate. It uses a separate PostgreSQL recovery fence, exact Docker ownership and hardening checks, atomic pending-decision custody outside the repository, deterministic journal identities, stop-then-reobserve, and fixed idempotent replay. The runner cannot read the recovery fence table, and the agent-facing CLI exposes no arbitrary recovery or append surface.

Passing invocation `e65374af-535f-47df-b8f2-40b5b9459885` completed all 15 fixed synthetic checks. It preserved active-owner and unowned-runtime deferral, exact orphan stop and replay, cancelled/failed/stale lifecycle exits, ambiguous `INCONCLUSIVE`, conflicting-effect recovery `FAIL`, crash-after-evidence resume, concurrent-recoverer exclusion, restart persistence, null non-completed run verdicts, the exact three protected volume identities, and complete disposable teardown. Seventy-four tests and 17 recovery implementation mutations pass. This is canonical-checkout candidate evidence; credential-free public implementation replay remains required before `EXIT-INTERRUPTION-RECOVERY` can pass.
