# ADR-0003: Host orchestration and staged custody

- Status: accepted
- Date: 2026-08-09
- Authority: `INCIDENTSEAL-PRODUCT-001`
- Contract: `INCIDENTSEAL-TOPOLOGY-001`

## Context

IS-0003 needs a real PostgreSQL and cross-language topology without giving a container Docker authority or mounting the repository broadly. The project also needs to validate the platform before a real workflow digest exists, without creating an approval bypass.

## Decision

The host CLI is both the control service and the sole Docker/Compose client. Compose contains only the database, one-shot migration, Python runner, and Node runner. No orchestration container exists.

Platform validation and workflow execution are distinct modes. Platform validation is limited to baked-in synthetic probes, accepts no repository input, and can claim only topology behavior. Workflow execution requires `MATCH` for the exact externally approved manifest digest and rechecks it across staging and runner boundaries.

Repository content is copied into bounded per-run custody outside the repository and forbidden roots. The source checkout is never mounted. Inputs are read-only, runner outputs are separate narrow writes, and evidence is hash-promoted before cleanup.

Derived images use copy-only Dockerfiles, exact locked bases, the exact locked Dockerfile frontend, no build network, and no dependency resolution. Runtime uses locally frozen image IDs with pulls disabled.

## Consequences

- A container compromise cannot directly invoke Docker or rewrite approval.
- Platform engineering can proceed without manufacturing a real workflow approval.
- A platform-validation PASS cannot become a repository release claim.
- Staging costs extra local copy space but makes mount scope inspectable and bounded.
- Minimal PostgreSQL v3 clients in the two runners avoid a new dependency source gate but must be tested against the real database and treated as narrow protocol implementations, not general drivers.
- The dashboard remains a later surface; it does not justify a control container in IS-0003.

## Rejected alternatives

- Docker socket or engine API in a control container: violates host-only authority.
- Docker-in-Docker: requires a privileged daemon and duplicates the control plane.
- Direct repository bind mount: broadens write/read exposure and permits time-of-check/time-of-use drift.
- Publishing host ports for convenience: expands the surface before a dashboard contract exists.
- Package-manager installs during builds: introduce uncontrolled network and dependency resolution.
- Treating platform validation as workflow verification: bypasses the approved manifest digest.
