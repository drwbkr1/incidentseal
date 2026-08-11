# ADR-0012: Bound v0.1.0 workflow execution to Python and Node

- Status: accepted for `IS6-U02` contract validation
- Date: 2026-08-11

## Decision

The first `verify` implementation supports only the manifest's `python` and `node` runner values. It executes direct argv in exact locked non-root images from copy-only committed input staging with no network or persistent output. Other runner values remain schema-valid for future compatibility but are execution-unsupported and return `INVALID` before Docker access.

## Why

The v0.1.0 release contract explicitly requires the two language runners before packaging. Executing `host` would make network, secret, filesystem, and side-effect denials unenforceable on the supported Windows host. Treating PostgreSQL, Compose, or receipt command arrays as arbitrary commands would also broaden IncidentSeal into the general execution platform it explicitly excludes.

## Consequences

- Operator approval remains necessary but is not sufficient to bypass the execution profile.
- The existing fixed topology, database, receipt, recovery, and dashboard probes remain separate real surfaces and will be rerun later against packaged and downloaded release candidates.
- Adding another workflow runner requires a new execution-contract revision, source and runtime gates, fail-closed mutations, and public reproduction; it cannot be smuggled through an optional field.
