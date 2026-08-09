# ADR-0004: Separate PostgreSQL bootstrap and application roles

- Status: accepted
- Date: 2026-08-09
- Decision owner: `IS3-U05`

## Context

The first real database probe proved migration, schema, DML, persistence, restart, and teardown, but returned product `FAIL`: both application runners used the PostgreSQL bootstrap role. That role was a login superuser with database and role creation, replication, bypass-RLS, and schema-creation authority. An internal network limits who can connect; it does not make excessive database authorization acceptable.

## Decision

PostgreSQL initializes with `incidentseal_admin`, used only by the database entrypoint and one-shot migration container. The migration creates or hardens `incidentseal_runner` as `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`, revokes public database and schema creation, grants only database connect, schema usage, and `SELECT`, `INSERT`, and `UPDATE` on `verification_results`, and keeps the migration ledger inaccessible to the runner.

No password is introduced because the database has no published port and accepts traffic only on the private internal Compose network. This is not a general passwordless deployment recommendation; it is a bounded local topology decision. Any future network broadening or secret-bearing authentication change crosses an explicit security gate and requires a new decision.

## Consequences

- Application runners cannot create tables, roles, databases, replication connections, or bypass row-level security.
- Migrations retain the narrow bootstrap authority needed to create and grant objects.
- Every role or grant change alters the topology contract digest and requires new exact image IDs, a new volume, static mutations, real migration tests, and a new runtime lock.
- The revision-2 shared-superuser FAIL remains retained and is not superseded into PASS.
