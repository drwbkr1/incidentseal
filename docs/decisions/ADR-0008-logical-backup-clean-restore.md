# ADR-0008: Bind logical backup to clean restore and measured roles

- Status: accepted
- Date: 2026-08-10
- Unit: `IS4-U05`

## Decision

IncidentSeal will use an exact PostgreSQL custom-format archive for the fixed backup/restore surface. A receipt binds the raw archive digest, normalized TOC digest, exact source image and state digests, fixed `pg_dump` and `pg_restore` argument vectors, and a distinct clean target project and volume. PASS requires a completed clean restore and independently normalized equivalence checks; dump creation is insufficient.

PostgreSQL roles are cluster-global and absent from a single-database `pg_dump`. IncidentSeal will not restore role SQL from an archive. It will measure the exact source role baseline, restore with no owner or ACL commands, reapply the exact locked migration image to create and harden roles, then verify role attributes and negative privileges.

## Consequences

- The archive is untrusted executable database content until exact source, byte, TOC, and restore bindings pass.
- A clean target prevents preexisting state from masking missing archive content.
- The real probe must stop on the first restore error and complete in one transaction.
- Protected evidence volumes remain out of scope; all backup and restore runtime custody is disposable.
- Physical backup, point-in-time recovery, production data, and cross-version migration remain non-goals for this checkpoint.
