# Release surface matrix

| Surface | Current state | Required release evidence |
|---|---|---|
| Packaged host CLI | Checkout CLI verified; package not built | Fresh install plus retained real JSON/JSONL schema and exit-code receipts |
| Manifest authority | Digest and operator boundary verified; no manifest approved | Approved digest, mutation rejection, agent-safe approval denial |
| Compose topology | Local and public-clone runtime verified; images not redistributed | Canonical rendered config, exact image digests, live identity and health |
| PostgreSQL | Migration, persistence, least privilege, and journal verified; backup/restore pending | Migration, persistence, dump, clean restore, recovery receipts |
| Python runner | Synthetic real runner verified | Real isolated execution and output receipt |
| Node runner | Synthetic real runner verified | Real isolated execution and output receipt |
| Dashboard | Not implemented | Rendered visual QA, evidence fidelity, loopback-only exposure |
| Receipts | Portable custody and offline verification implemented and publicly replayed | Independent verification plus corruption and truncation rejection |
| Recovery | Contract publicly replayed; local fixed synthetic runtime matrix passes; public implementation replay pending | Exact public replay of fenced lease and ownership, cancellation, crash, duplicate, idempotent resume, stale, failure, orphan, ambiguous, conflicting-effect, restart, custody, and teardown cases |
| Clean clone | Multiple bounded public paths verified; full product workflow pending | Fresh clone setup and end-to-end verification |
| Supply chain | Gate active | Source decisions, lockfiles, SBOM, provenance, scan and reproducibility evidence |
| GitHub/GHCR release | Not created | Remote identity, commit/tag, exact digest, attestations and downloaded verification |

No row may be represented as released or verified from source inspection alone.
