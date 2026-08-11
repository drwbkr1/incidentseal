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

Status: complete

Progress: `IS4-U01` froze portable receipts. `IS4-U02` passed the writer and independent verifier. `IS4-U03` passed immutable PostgreSQL history. `IS4-U04` passed fixed host-only recovery. `IS4-U05` passed fixed host-only backup and clean restore from exact credential-free public custody. `IS4-U06` passed exact public integrated replay. `IS4-U07` then reproduced closure commit `25328dacef4d9283090bed809db75b33f613829b`, repeated both complete real cycles, and independently verified annotated marker `checkpoint-is-0004` object `60b467a7970a6fb6b5e80dcdc4dd283ab80b0acf`. All IS-0004 exits pass.

- Append-only event model and portable content-addressed receipts.
- Idempotency, cancellation, duplicate protection, crash recovery, stale and superseded runs.
- PostgreSQL dump and verified clean restore.
- Independent offline receipt verifier.

### IS-0005 - Dashboard and evaluation

Status: complete

Progress: `IS5-U01` through `IS5-U05` passed. Exact closure commit `04230dcc...`, tree `ec2ed653...`, reproduced the full contract, implementation, browser evidence, real launcher, 27-trial evaluation, 133 tests, all 124 mutations, offline schema validation, Git/secret integrity, missing approval, unchanged Docker custody, and teardown from credential-free public custody. Annotated marker `checkpoint-is-0005` object `aba5e64f...` was independently fetched and peeled to that exact commit. Every IS-0005 exit passes.

- Polished dark forensic-style local dashboard.
- Deterministic scenario corpus for success, product failure, invalid input, missing evidence, policy attack, isolation attack, corrupted receipt, crash, and recovery.
- Repeated-trial reliability, latency, resource use, and claim-calibration report.

### IS-0006 - Portable release

Status: active

Progress: `IS6-U01` passes from exact public custody. The U02 runtime-free execution contract passes from exact public commit `bcc8583e...`, tree `6d1cba99...`; public implementation commit `04fd0525...` reproduced the bounded verifier and recovery matrix. Corrected public source `3c47f16d...` produced manifest digest `sha256:969c0626...`; external operator approval matched it and real run `785847c3...` completed both runner steps with terminal PASS receipt `sha256:75ff3e2a...`. Required post-run validation exposed and retained a third product FAIL: 3 of 163 tests assumed the global authority store was absent. Exact credential-free public remediation commit `3d10dcd...`, tree `b599fbf6...`, now reproduces all 163 tests, 23 focused tests, 29 mutations, both gates, milestone control, Git/secret integrity, exact retained external hashes, and clean Docker custody under lock `sha256:6fefd277...`. The final receipt commit, new manifest digest, matching external approval, and second real run remain. Prior failures, invalid attempts, superseded PASS, and superseded unapproved handoff stay distinct. No package, image, tag, or release has been built or published.

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
