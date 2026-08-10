# PostgreSQL logical backup and clean-restore contract

- Contract ID: `INCIDENTSEAL-BACKUP-RESTORE-001`
- Unit: `IS4-U05`
- Status: frozen candidate
- Runtime status: not started

## Claim

A backup exists only when the host CLI creates a PostgreSQL custom-format archive from a fixed disposable evidence source, hashes the exact bytes and a normalized table of contents, restores that exact archive into a different clean disposable PostgreSQL volume, reapplies the exact locked migration to create and harden cluster-global roles, and proves source/restore equivalence plus negative privileges. Archive creation alone is not PASS.

PostgreSQL documents that `pg_dump` produces a consistent single-database export and that custom archives are inspectable and restorable with `pg_restore`. It also documents that roles are cluster-global and are not saved by `pg_dump`; `pg_dumpall` is required for global objects. IncidentSeal therefore does not execute role SQL from the archive. The real implementation must measure the exact two-role source baseline, restore the database archive with `--no-owner --no-privileges --exit-on-error --single-transaction`, and reapply the exact migration image before checking the restored role baseline and denied privileges. See the official [PostgreSQL 18 pg_dump](https://www.postgresql.org/docs/18/app-pgdump.html), [pg_restore](https://www.postgresql.org/docs/18/app-pgrestore.html), and [pg_dumpall](https://www.postgresql.org/docs/18/app-pg-dumpall.html) documentation.

## Authority and custody

The contract is platform-validation only. Both source and target are fixed synthetic disposable projects. The three protected evidence volumes are identity-checked before and after and never mounted. The backup directory is narrow host-owned temporary custody outside the repository and OneDrive. Containers receive no Docker socket, secret, broad host mount, external network, or arbitrary repository input.

The archive is treated as executable database content. A future real probe must accept only the exact archive it just created from the locked synthetic source, inspect its normalized TOC, and reject changed bytes, unexpected objects, stderr, a different image, a reused source project, or any restore not bound to the receipt.

## Required equivalence

PASS requires the exact schema digest, normalized ordered journal digest, normalized verification-results digest, and normalized two-role digest to match after restore. It also requires denied runner schema creation, DDL, migration-ledger reads, journal reads, and recovery-fence reads; PostgreSQL restart persistence; exact protected-volume identity; and complete source, target, network, backup, and state teardown. The receipt is RFC 8785 content-addressed and closed to unknown fields.

## Non-claims

This contract does not run `pg_dump`, `pg_restore`, PostgreSQL, Docker, an approved workflow, a protected-volume backup, or a production disaster-recovery process. It does not prove integrated recovery, dashboard, packaging, redistribution, registry, or release behavior.
