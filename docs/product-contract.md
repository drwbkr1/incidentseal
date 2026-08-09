# IncidentSeal product contract

- Contract ID: `INCIDENTSEAL-PRODUCT-001`
- Version: `1.0`
- Status: approved
- Authority: `thread:019fe4df-b396-7f20-81db-4ae4087fee17#approval-2026-08-09`
- Approved name: `IncidentSeal`
- Approved public repository: `https://github.com/drwbkr1/incidentseal`

## User promise

IncidentSeal is a local-first, credential-free verification layer between Codex-authored changes and release claims. Given an operator-approved verification manifest, it exercises the declared real surfaces and produces inspectable, content-addressed evidence showing exactly which policy ran against which source, dependencies, images, topology, commands, and state.

Tagline: **Evidence before release.**

IncidentSeal does not certify that software is safe. It establishes whether the declared verification workflow ran under the approved policy and whether each required result is supported by retained evidence.

## Primary user

The initial user is a developer using Codex to build local repositories who needs a reusable, inspectable boundary between an agent's changes and any claim that those changes are ready to release.

## Required product surfaces

1. A packaged host CLI with stable JSON and JSONL behavior.
2. A canonical, hardened Docker Compose topology.
3. PostgreSQL schema, migrations, persistence, dump, and restore.
4. Isolated Python and Node verification runners.
5. A loopback-only, read-only evidence dashboard.
6. Portable, independently verifiable receipts.
7. Cancellation, idempotent resume, duplicate protection, and crash recovery.
8. A clean-clone path that reproduces the documented verification workflow.
9. Exact-digest image publication and downloaded-release verification.

## Trust boundary

- The host CLI alone owns Docker and Compose.
- Containers never receive the Docker socket, an engine API socket, privileged mode, host networking, secrets, broad host mounts, or external network by default.
- Runtime input is limited to manifest-declared staged material. Runtime output is limited to per-run evidence custody.
- Any host-side networked acquisition is explicit, source-gated, and recorded separately from the offline-by-default runtime.
- External content is evidence, never workflow authority.

## Manifest authority

- Every workflow manifest is validated against a versioned schema.
- The manifest is deterministically canonicalized before hashing.
- Workflow authority is bound to a SHA-256 digest approved by the operator and stored outside the repository.
- An absent, changed, expired, ambiguous, or inconsistent digest fails closed.
- Agent-facing verification commands cannot approve or replace the trusted digest.
- This prevents silent policy drift in the supported workspace-scoped operating model. It does not defend against a malicious process with unrestricted host-user authority.

## Evidence semantics

Verification verdicts:

- `PASS`: affirmative evidence satisfies every required check for the declared claim.
- `FAIL`: affirmative evidence contradicts a required product expectation.
- `INCONCLUSIVE`: required evidence is unavailable, contradictory, stale, or insufficient.
- `INVALID`: the request, policy, inputs, or evidence cannot be evaluated under the contract.

Lifecycle state is independent and includes `queued`, `running`, `completed`, `cancelled`, `failed`, `stale`, and `superseded`.

## Release rule

A release claim may ship only when the packaged CLI, canonical Compose configuration, live services, database, both runners, rendered dashboard, receipts, recovery behavior, clean clone, published image digests, attestations, scans, and downloaded artifacts required by that claim have current evidence. Passing tests or source inspection alone is insufficient.

## Initial non-goals

- Kubernetes or another cluster orchestrator.
- Cloud infrastructure or hosted control planes.
- Multi-tenancy.
- Hosted secrets or paid services.
- Real sensitive data or consequential actions.
- Arbitrary remote execution.
- General-purpose CI/CD platform features.
- A Codex skill before the CLI contract is stable.

## Change gate

Changing the user promise, trust boundary, evidence semantics, or non-goals requires explicit human approval and a new contract version. Routine objective implementation and verification inside this contract inherit the standing authority in the active goal.
