# ADR-0001: Host-owned Docker and digest-bound workflow authority

- Status: accepted
- Date: 2026-08-09
- Authority: `INCIDENTSEAL-PRODUCT-001`

## Context

IncidentSeal must verify Codex-authored changes without allowing a verification container to control Docker or allowing Codex to silently weaken the policy used to verify its own change.

## Decision

The host IncidentSeal CLI is the only Docker and Compose owner. Containers do not receive a Docker socket, engine API access, secrets, privileged mode, host networking, broad host mounts, or external network by default.

Workflow manifests are schema-validated, deterministically canonicalized, and hashed. Execution authority is bound to an operator-approved SHA-256 digest stored outside the repository. The agent-facing execution path can inspect and compare approval but cannot create or replace it.

## Consequences

- Docker orchestration must remain in the host CLI rather than a control container.
- The Compose topology can be evaluated as an untrusted workload rather than an authority source.
- A changed manifest fails closed until separately approved.
- A local external trust store must be portable enough for supported hosts but is not a defense against unrestricted same-user host compromise.
- Runtime networking and any source acquisition must be separate actions with separate evidence.

## Rejected alternatives

- Docker-outside-of-Docker through a mounted socket: violates the authority boundary.
- Docker-in-Docker: adds a privileged daemon and unnecessary complexity.
- Repository-only approval record: Codex could silently edit policy and approval together.
- A skill as the primary integration: reusable prompting is not a stable enforcement boundary.
