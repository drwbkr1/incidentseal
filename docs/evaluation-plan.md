# Evaluation plan

IncidentSeal evaluations grade deterministic state and retained evidence before presentation quality.

## Required dimensions

- Manifest identity and unauthorized-change rejection.
- Canonical Compose topology and exact runtime identity.
- Docker authority isolation, mounts, privilege, filesystem, and network posture.
- PostgreSQL migration, persistence, dump, restore, and recovery correctness.
- Python and Node runner contract behavior.
- Verdict and lifecycle-state separation.
- Receipt completeness, canonicalization, hash verification, corruption detection, and independent inspection.
- Cancellation, duplicate delivery, crash boundaries, idempotent resume, stale policy, and supersession.
- CLI JSON/JSONL schema stability and exit codes.
- Dashboard identity, evidence fidelity, accessibility, and loopback-only exposure.
- Clean-clone setup and verification.
- SBOM, provenance, scan, reproducibility, registry, and downloaded-release identity.

## Claim rules

- Deterministic expected state is the primary grader.
- Human review may assess presentation but cannot override a failed objective gate.
- Missing, contradictory, unavailable, or stale evidence is `INCONCLUSIVE`.
- Invalid manifest, schema, authority, or receipt material is `INVALID`.
- A crashed or cancelled run has a lifecycle state and no implied verification verdict.

## Initial scenario families

1. Nominal successful verification.
2. Product expectation failure.
3. Insufficient evidence.
4. Invalid manifest and unsupported schema.
5. Manifest digest drift and approval substitution.
6. Docker socket, secret, mount, privilege, and network access attempts.
7. Runner failure, cancellation, duplicate delivery, and crash recovery.
8. Database persistence, dump, clean restore, and migration failure.
9. Receipt mutation, truncation, reordering, and artifact corruption.
10. Dashboard versus receipt claim comparison.
11. Clean-clone and registry round trip.

Quantitative thresholds will be frozen only after the corresponding real surfaces exist and a baseline measurement is available.
