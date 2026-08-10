# ADR-0010: Read-only dashboard projection outside the verification CLI

- Status: accepted candidate
- Unit: `IS5-U01`

## Context

IncidentSeal must provide a polished loopback-only evidence dashboard without letting rendered state become verification authority. The existing `incidentseal` verification CLI and its exact implementation locks are already public checkpoint evidence. Changing that dispatcher merely to add a dashboard would invalidate historical runtime self-bindings and introduce an unnecessary authority path.

## Decision

The dashboard will use a separate `incidentseal-dashboard` launcher and a dependency-free host process. It will build one strict in-memory projection from exact repository records, bind that projection to the verified checkpoint and every source-record digest, and serve only fixed local assets plus the projection over IPv4 loopback.

The server has no Docker, approval-write, workflow-execution, secret, repository-write, external-network, telemetry, analytics, upload, arbitrary-path, or command authority. Only fixed `GET` and `HEAD` routes may be admitted. The rendered dashboard is a view over evidence; receipts and checkpoint records remain authoritative.

## Consequences

- The frozen verification CLI remains unchanged.
- Dashboard implementation can be validated and packaged independently.
- A valid snapshot is necessary but not sufficient: the real loopback server, rendered browser surface, responsive layouts, accessibility structure, and failure states remain separate gates.
- Any record drift, missing checkpoint identity, unknown state, non-loopback bind, remote asset, write method, or positive authority claim fails closed.
