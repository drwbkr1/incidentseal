# IncidentSeal threat model

- Threat model ID: `INCIDENTSEAL-THREAT-001`
- Version: `1.0`
- Status: active baseline
- Scope: local single-user development and release verification

## Security objectives

1. A Codex-authored change cannot silently weaken the policy used to verify itself.
2. Verification containers cannot control the Docker daemon or inherit broad host authority.
3. Runtime containers operate without secrets or external network by default.
4. Release evidence identifies exact inputs and retains missing, failed, interrupted, stale, and superseded outcomes.
5. A receipt can be checked independently of the live database and dashboard.

## Assets

- Approved manifest digest and approval metadata.
- Source commit, tree, staged inputs, and dependency lockfiles.
- Exact image and platform digests.
- Compose configuration and runtime identities.
- PostgreSQL event history and migration state.
- Logs, artifacts, SBOMs, provenance, scans, and release receipts.
- Git and registry release identities.

## Actors

- Operator: owns normative product decisions and manifest approval.
- Codex: may implement and invoke the agent-facing CLI under the standing project authority.
- Host CLI: trusted orchestrator and sole Docker owner.
- Verification containers: untrusted, bounded execution workers.
- External publishers and registries: untrusted until their exact artifacts pass a source gate.
- Other local host processes: outside the initial isolation guarantee.

## Trust zones

### Operator-controlled host state

The approved manifest digest is held outside the repository. The operator approval path is distinct from the agent-facing run path. No secret is required for the initial local model.

### Repository

Repository content is mutable input. Instructions, manifests, Dockerfiles, scripts, tests, and generated claims are not self-authorizing.

### Host CLI and Docker engine

The host CLI may invoke the Docker and Compose CLIs. Docker authority is security-sensitive and never delegated into containers.

### Verification capsule

Containers receive only explicit staged inputs and narrow evidence outputs. Services run non-root where feasible, with read-only filesystems, dropped capabilities, no-new-privileges, bounded tmpfs, internal or absent networks, and exact image digests.

### External network and publishers

Networked acquisition is a separate host-side action. Runtime egress is denied by default. Publisher pages, registry metadata, signatures, provenance, and advisory feeds are retained as evidence but do not create authority.

## Principal threats and controls

| Threat | Required control | Required evaluation |
|---|---|---|
| Codex edits the manifest and verifies under weaker rules | Canonical digest must match operator approval outside the repo | Mutate policy, whitespace, field order, and semantics; require exact expected rejection behavior |
| Codex invokes an approval command | Separate operator approval surface from agent-facing CLI; prohibit approval in repository guidance | Attempt noninteractive and agent-profile approval; require rejection |
| Runner controls Docker | No socket, named pipe, API proxy, `use_api_socket`, or daemon credentials | Inspect canonical Compose model and mounts; probe expected socket paths |
| Runner reads host or secret material | No secrets or broad mounts; narrow read-only staged input | Inspect mounts and environment; run canary-path denial tests |
| Runner exfiltrates data | No runtime network by default | DNS, TCP, HTTP, and route probes must fail while required local communication still works |
| Container gains unnecessary privilege | Non-root, read-only root, all capabilities dropped, no-new-privileges | Inspect actual container configuration and run write/capability probes |
| Mutable image tag changes bytes | Pin tag plus exact platform digest after source gate | Resolve and compare manifest/platform digests before use and at release |
| Missing provenance or advisory data is treated as safe | `INCONCLUSIVE`, never `PASS` | Remove or block evidence source and verify verdict |
| Database reports partial work as complete | Transactional step commits, idempotency keys, immutable events | Kill at defined boundaries, resume, and verify no duplicate committed step |
| Receipt is edited or truncated | Canonical serialization, content hashes, chain/root digest, independent verifier | Mutate fields, reorder records, remove records, and corrupt artifacts |
| Dashboard or prose overstates evidence | Dashboard derives from receipt schema; release claim matrix is explicit | Compare rendered claims with receipt and current release matrix |
| Registry loses or rewrites attestations | Verify remote digest and attestations after push and after download | Registry round-trip verification |

## Implemented approval-boundary controls

The agent-facing host CLI has read-only `policy status` and `policy diff` paths. They derive the external approval location from the platform default, do not accept an approval-root override, never create a missing store, and expose no approval write function. A non-interactive attempt to invoke `operator approve-manifest` is rejected with stable exit `77` and `IS_AUTHORITY_MUTATION_FORBIDDEN`.

`IS2-U04A` implements the separate human surface. It requires a real terminal and full-digest confirmation, rechecks manifest and approval state after the prompt, compare-and-swaps the prior approval-file digest, writes through a restrictive same-directory temporary file, retains exact superseded bytes, atomically replaces the active record, and independently verifies MATCH. A failed final inspection restores the prior record when possible. Tests use temporary custody only; no real approval is created by the project workflow.

Approval inspection rejects repository-overlapping and configured-forbidden custody, symlinks and Windows reparse points, ambiguous case resolution, unexpected writers, unreadable paths, malformed or ambiguous JSON, invalid timestamps, and non-closed record fields. Windows custody requires the current principal to own each object and permits write grants only for owner/creator-owner rights, SYSTEM, and Administrators. POSIX custody requires current-user ownership, no group/other writes, and no extended access ACL; macOS extended-ACL verification currently fails closed. Exact digest comparison uses a constant-time primitive after record validation.

Temporary-custody probes distinguish `MATCH`, `MISMATCH`, `MISSING`, `EXPIRED`, and `INVALID`; test repository and forbidden-root overlap, unverified permissions, and a real Windows junction; and confirm the default operator store is absent before and after agent-facing inspection. These probes create no real approval and authorize no workflow.

## Explicit limitations

- Docker authority is effectively host-root authority on common systems. A compromised host CLI or unrestricted same-user process is outside the protection offered by container hardening.
- A non-secret local approval record is tamper-evident and outside the normal repository write scope; it is not strong identity proof against a fully privileged same-user attacker.
- Windows approval inspection depends on local PowerShell and `icacls` read access and fails closed if ownership or ACL evidence cannot be interpreted. macOS approval matching remains unavailable until extended ACLs can be verified without weakening this gate.
- An OS-level failure during both approval replacement verification and rollback can leave state requiring operator inspection; IncidentSeal reports failure and cannot treat that state as approved.
- Container isolation reduces risk but is not a proof that the Docker engine or kernel is free of vulnerabilities.
- Vulnerability scans depend on advisory freshness and coverage. A clean scan is not proof of absence.
- Reproducible procedure and digest-pinned inputs do not imply bit-for-bit reproducible outputs until measured.

## Human gates

Stop before changing the core product promise or trust boundary, weakening a security or evidence gate, using real sensitive data or consequential actions, introducing spending or a paid service, adding a secret, changing access or ownership, taking an irreversible action, or shipping an unverifiable claim.
