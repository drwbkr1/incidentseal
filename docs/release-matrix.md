# Release surface matrix

| Surface | Current state | Required release evidence |
|---|---|---|
| Packaged host CLI | Not implemented | Fresh install, real invocation, JSON/JSONL schema and exit-code receipts |
| Manifest authority | Not implemented | Approved digest, mutation rejection, agent-safe approval denial |
| Compose topology | Not implemented | Canonical rendered config, exact image digests, live identity and health |
| PostgreSQL | Not implemented | Migration, persistence, dump, clean restore, recovery receipts |
| Python runner | Not implemented | Real isolated execution and output receipt |
| Node runner | Not implemented | Real isolated execution and output receipt |
| Dashboard | Not implemented | Rendered visual QA, evidence fidelity, loopback-only exposure |
| Receipts | Not implemented | Independent verification plus corruption and truncation rejection |
| Recovery | Not implemented | Cancellation, crash, duplicate, idempotent resume, stale and superseded cases |
| Clean clone | Not implemented | Fresh clone setup and end-to-end verification |
| Supply chain | Gate active | Source decisions, lockfiles, SBOM, provenance, scan and reproducibility evidence |
| GitHub/GHCR release | Not created | Remote identity, commit/tag, exact digest, attestations and downloaded verification |

No row may be represented as released or verified from source inspection alone.
