# IncidentSeal roadmap

## Product target

Release a polished `v0.1.0` local verification path that binds an approved workflow digest to real cross-language, database, dashboard, recovery, supply-chain, clean-clone, and release evidence.

## Checkpoints

### IS-0001 - Contract and source boundary

Status: complete

- Establish canonical non-OneDrive custody and public repository identity.
- Freeze the product contract and threat model.
- Record the live environment inventory.
- Validate the project control profile and milestone contract.
- Run the exact-image source gate without using an ungated candidate.
- Commit and push the verified checkpoint if all publication gates pass.

### IS-0002 - Manifest authority and CLI contract

Status: complete

- Versioned manifest JSON Schema and deterministic canonicalization.
- Operator-controlled digest approval store outside the repository.
- Agent-safe policy status, diff, lint, and verification paths.
- Stable CLI exit codes plus JSON and JSONL schemas.
- Mutation tests proving that policy drift fails closed.

### IS-0003 - Hardened real topology

Status: complete

Progress: `IS3-U01` through `IS3-U09` passed. Annotated marker `checkpoint-is-0003` freezes exact verified closure commit `a0c05070dd1d147aecae6b4ed686440414a3aa27` after credential-free real-surface, integrity, and secret-scan replay.

- Canonical Compose topology with exact-digest images.
- PostgreSQL, one-shot migrations, Python runner, Node runner, and host-CLI control plane.
- No Docker socket, secrets, broad mounts, or runtime egress.
- Real configuration, health, identity, filesystem, privilege, mount, and network probes.

### IS-0004 - Evidence and recovery

Status: active

Progress: `IS4-U01` froze the portable receipt contract. `IS4-U02` passed the atomic writer and independent verifier. `IS4-U03` is active: its canonical candidate adds immutable transactional PostgreSQL history and real read-only ordered JSONL, passes 62 tests plus 8 journal, 15 topology, and 12 receipt mutations, and preserves all three protected volume identities through disposable restart and teardown. Credential-free public replay remains before U03 closes.

- Append-only event model and portable content-addressed receipts.
- Idempotency, cancellation, duplicate protection, crash recovery, stale and superseded runs.
- PostgreSQL dump and verified clean restore.
- Independent offline receipt verifier.

### IS-0005 - Dashboard and evaluation

Status: planned

- Polished dark forensic-style local dashboard.
- Deterministic scenario corpus for success, product failure, invalid input, missing evidence, policy attack, isolation attack, corrupted receipt, crash, and recovery.
- Repeated-trial reliability, latency, resource use, and claim-calibration report.

### IS-0006 - Portable release

Status: planned

- Packaged host CLI and documented clean-clone path.
- SBOM, SLSA provenance, vulnerability, hardening, reproducibility, and registry receipts.
- Exact-digest GHCR images and downloaded-release verification.
- Public `v0.1.0`, changelog, architecture decisions, release notes, and devlog.

### IS-0007 - Reusable Codex skill

Status: gated

- Begin only after the CLI contract remains stable across verified checkpoints and at least two repository integrations.
- The skill teaches Codex to use IncidentSeal; it does not implement policy or own Docker.

## Priority rule

Start each cycle from the latest verified checkpoint and select the smallest eligible unit that measurably advances the next unmet exit condition. Do not expand into the explicit non-goals to create activity.
