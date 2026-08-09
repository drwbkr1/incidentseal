# PostgreSQL database surface

`IS3-U05` verifies the real database surface through:

```text
incidentseal topology database-probe --mode platform-validation --json
```

The command is host-owned, non-interactive, manifest-free, and limited to platform validation. It requires the exact topology, implementation, and runtime locks; it does not rebuild a missing locked image or execute repository input.

The probe starts PostgreSQL from the exact local image ID, executes the real migration twice, inspects the exact migration container, verifies PostgreSQL 18.4 and database identity, checks the `verification_results` schema and `001-schema-v2` migration record, inspects the runner role attributes, performs one deterministic DML upsert, requires runner DDL and migration-ledger reads to fail, restarts PostgreSQL, verifies the row persisted, and removes every container and the internal network. The exact named volume remains retained.

The bootstrap/migration role is `incidentseal_admin`. The application role is `incidentseal_runner`, with login, database connect, schema usage, and only `SELECT`, `INSERT`, and `UPDATE` on `verification_results`. It is not a superuser and cannot create roles or databases, replicate, bypass RLS, create public-schema objects, or read the migration ledger.

A completed check failure is product `FAIL` with exit `10`; invalid locks, custody, or runtime preconditions are `INVALID` with exit `12`. The original shared-superuser run is retained as `FAIL` even though revision 3 passes. This surface does not prove either real language runner, dump/restore, crash recovery, workflow approval, or release readiness.
