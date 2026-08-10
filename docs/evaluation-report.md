# Evaluation report

## Current conclusion

IncidentSeal has a verified local hardened topology checkpoint, not a releasable product. `checkpoint-is-0003` binds commit `a0c05070dd1d147aecae6b4ed686440414a3aa27` through annotated tag object `28eea260147265e7dd0328dcd072e134586a2ff0`.

## Verified surfaces

- Host-owned Docker and Compose with no container engine endpoint in workloads.
- Four exact local image identities on an internal-only Compose network with numeric non-root users, read-only roots, all capabilities dropped, no-new-privileges, no published ports, no secrets, and narrow staged mounts.
- PostgreSQL 18.4 with idempotent migration, distinct bootstrap and application roles, bounded DML, denied DDL and migration-ledger reads, restart persistence, and retained failure volumes.
- Shipped Python and Node application commands with exact positive outputs, exact database rows, cross-runner canonical input identity, language-bound result identity, and malformed-input rejection.
- Disposable reliability behavior that keeps completed verification `PASS`, `FAIL`, and `INVALID` separate from lifecycle `failed` and `cancelled`, recovers after database outage, persists through restart, detects orphans, and removes disposable resources without touching three protected evidence volumes.
- Fixed synthetic host-only recovery with separate PostgreSQL fencing, exact Docker ownership and hardening, stop-then-reobserve, deterministic replay and append, cancellation/failure/stale exits, ambiguous and conflicting effects, crash-after-evidence resume, concurrent-holder exclusion, restart persistence, runner denial, and protected teardown from exact credential-free public custody.
- Credential-free public-clone replay with 50 tests, four machine-contract mutations, 16 topology mutations, 15 implementation mutations, Git object integrity, high-confidence secret scan, real reliability execution, and annotated-marker verification.

## Retained negative evidence

- Revision-1 PostgreSQL startup `FAIL` from non-root volume ownership.
- Revision-2 database least-privilege `FAIL` from a shared bootstrap superuser.
- Two Python-surface product `FAIL` attempts caused by Compose transport/orphan stderr policy.
- Malformed commands and harness invocations retained as `INVALID` rather than product failure.
- Real database-outage lifecycle `failed` and host-stop lifecycle `cancelled` observations with no fabricated verification verdict.

## Remaining before v0.1.0

Integrated recovery, dashboard, broader scenario evaluation, packaged host CLI, SBOM/provenance/scan/reproducibility receipts for release artifacts, exact-digest registry publication, downloaded-release validation, and release documentation remain unverified.

Image redistribution remains `INCONCLUSIVE`; no derived image was published. No workflow manifest is approved and no workflow was executed.

## IS4-U04 local recovery candidate

The frozen recovery contract has a real local implementation candidate. It uses a separate PostgreSQL recovery fence, exact Docker ownership and hardening checks, atomic pending-decision custody outside the repository, deterministic journal identities, stop-then-reobserve, and fixed idempotent replay. The runner cannot read the recovery fence table, and the agent-facing CLI exposes no arbitrary recovery or append surface.

Canonical invocation `e65374af-535f-47df-b8f2-40b5b9459885` and exact public invocation `84ceb376-b2bb-43e7-a93f-46129c3472f0` each completed all 15 fixed synthetic checks. They preserved active-owner and unowned-runtime deferral, exact orphan stop and replay, cancelled/failed/stale lifecycle exits, ambiguous `INCONCLUSIVE`, conflicting-effect recovery `FAIL`, crash-after-evidence resume, concurrent-recoverer exclusion, restart persistence, null non-completed run verdicts, the exact three protected volume identities, and complete disposable teardown. Seventy-four tests and 17 recovery implementation mutations pass. `EXIT-INTERRUPTION-RECOVERY` passes; backup and clean restore are next.

## IS4-U05 backup and clean-restore contract

The dependency-free contract binds exact custom archive bytes and a normalized TOC to a fixed disposable source and a different clean target. Roles are measured cluster-global state and are rebuilt and hardened by the exact migration after restoring with no owner or ACL commands; role SQL from the archive is never authority. PASS requires exact schema, journal, verification-result, and role equivalence; five negative runner privileges; protected-volume identity; and teardown.

Exact credential-free public commit `30513b70a9c7a2e283e4643232fa5c8b13f650c2` reproduced all 80 tests, 18 backup mutations, every prior cross-surface suite, and one schema across two fixtures using six rehashed source-gated wheels offline. Git integrity, a zero-match four-pattern secret scan, `MISSING` approval at exit `12`, zero IncidentSeal containers and networks, and the exact three protected volume identities all passed. No dump, restore, PostgreSQL, or Docker runtime action occurred. The contract replay gate passes; real archive creation, clean restore, equivalence, privilege, restart, and teardown behavior remain the next implementation gate.

## IS4-U05 verified backup and clean-restore implementation

The implementation is a fixed platform-validation command, not an arbitrary backup utility. The host alone owns Docker. It uses exact locked images, two fixed internal-network projects, two clean disposable volumes, and a narrow temporary archive bind; containers receive no Docker socket, secret, broad host mount, or external network. Source writes are fenced with a live table lock before the exact no-owner/no-privilege custom dump. The host fsyncs and hashes the archive, lists it without network, normalizes its TOC, rejects database/role/tablespace/ACL authority, restores with error-stop and one transaction, and then reruns the exact migration to rebuild and harden cluster-global roles.

Final-lock invocation `e38826ae-8d6f-4d24-a033-bd6a298d0f8e` and exact public invocation `72cda586-8994-489b-8295-043aac2b294d` each passed all ten checks. Their fresh `52800`-byte archives have distinct exact byte digests bound by their individual receipts, while their 20-entry normalized TOC digest and exact schema, journal, result, and role digests match. All five negative privileges held after restart; all three protected volume identities matched; and every disposable container, network, volume, and archive was removed. Public commit `f8c2526389ea73c157f535c2d6651ba86b8169ac` also passed 86 tests, all 21 implementation mutations and every prior suite, offline schema validation, Git integrity, secret scanning, and the missing-approval boundary. Seven implementation attempts and three public or closure harness attempts remain `INVALID`; the third was a no-execution push-wrapper parser error. The earlier passing calibration remains `superseded`. `EXIT-BACKUP-RESTORE` passes; integrated recovery is next.
