# ADR-0011: Close approved-workflow execution before portable release

- Status: accepted for IS-0006
- Date: 2026-08-11
- Decision owners: IncidentSeal product, technical, and reliability direction under the approved long-running goal

## Context

Checkpoint IS-0005 verifies manifest canonicalization and external approval custody, hardened Docker and Compose, PostgreSQL, Python and Node runner probes, receipts, journal, recovery, backup/restore, dashboard, and repeated evaluation. It does not provide the product command that executes a repository's declared workflow under a current operator-approved digest.

Packaging that state as v0.1.0 would make installation portable without making the core user promise true. The missing path is already recorded as a limitation, so closing it is not a new product promise or scope expansion.

## Decision

IS-0006 inserts an approved-workflow unit before packaging. The stable command is `incidentseal verify --manifest PATH --json`. It must fail closed unless external approval is `MATCH` and repository remote, commit, tree, manifest bytes, and digest remain exact. The host CLI stages declared inputs and invokes only the approved Python and Node argument vectors in exact locked runner images. It owns Docker and evidence writing; containers receive no Docker endpoint, secret, privileged mode, host network, broad mount, or external network.

The internal writer records append-only, digest-bound events and receipts while the agent-facing surface remains read-only for event streaming. Cancellation and resume preserve lifecycle separately from verdict and require the same approved digest plus safe idempotent evidence. The complete path must reproduce from credential-free public custody before package work begins.

## Consequences

- The first release becomes demonstrably useful between Codex-authored changes and release claims rather than merely packaging platform probes.
- Packaging moves from IS6-U02 to IS6-U03; later units shift by one without changing their evidence or authority boundaries.
- The implementation is bounded to the existing v1 Python/Node manifest contract. It does not add arbitrary runner types, remote execution, network access, secrets, Kubernetes, or a hosted control plane.
- A valid manifest still creates no authority. Only current external approval `MATCH` permits execution.
- The immutable publication human gate remains exactly one later unit and is not moved or weakened.

## Rejected alternatives

- **Release the platform probes as v0.1.0:** rejected because it contradicts the approved user promise.
- **Treat a valid manifest digest as approval:** rejected because it lets repository-controlled state create authority.
- **Run commands directly on the host:** rejected because it defeats the staged container boundary and makes repository input ambient host authority.
- **Add a generic remote runner or plugin system:** rejected as unnecessary platform scope and arbitrary remote execution.
