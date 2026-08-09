# IncidentSeal status

- Current checkpoint: `IS-0003`
- Latest verified checkpoint: `IS-0002`
- State: active
- Version: `0.0.0`
- Canonical root: `C:\Projects\Active\incidentseal`
- Expected public remote: `https://github.com/drwbkr1/incidentseal.git`
- Expected branch: `main`
- Latest verified checkpoint commit: `e8b9823f63e3505f87490cbd87894705221a33cd` on local and remote `main`
- Verified checkpoint marker: `checkpoint-is-0002` tag object `630bc88f0860de56c51d0637260953429a6df172` -> `e8b9823f63e3505f87490cbd87894705221a33cd`
- Approved workflow manifest digest: not established
- Application surfaces: static topology and topology-only runtime security verified; real migration, database persistence, and application runners remain pending
- Release state: unreleased

## Current truth

The product name, promise, trust boundary, public repository owner, presentation direction, Apache-2.0 license, and long-running operating authority were approved on 2026-08-09. `IS-0002` now establishes the public manifest authority and real host CLI contract: exact local and public clean clones passed both checkout launchers, 38 tests, full Draft 2020-12 schema validation, approval denial, frozen mutations, and 50 fail-closed executions without Docker or real approval state.

The canonical repository is not in OneDrive. All OneDrive paths are forbidden for IncidentSeal work.

## Active unit

`IS3-U01` passed without starting a container. The exact linux/amd64 Dockerfile frontend, Chainguard PostgreSQL 18.4, Distroless Node.js 24, and Chainguard Python 3.14.7 images are now bound in `requirements/images.lock.json` with platform children, local identities, signatures or provenance, SBOMs, vulnerability evidence, license limits, and mandatory runtime constraints.

`IS3-U02` passed without starting Docker runtime surfaces. The topology contract now binds the exact image lock, host-only Docker authority, copy-only offline builds, one internal network, numeric non-root service identities, bounded staged custody, distinct evidence states, and a normalized render model. All 12 security-relevant mutations failed closed with their expected stable error codes.

`IS3-U03` passed without building an image or starting a container. The real Windows CLI rendered `compose.yaml` through Docker Compose 5.1.3, matched the frozen normalized security projection, repeated the stable redacted-model digest, validated the exact implementation lock, and rejected all 13 real implementation mutations. Python and Node source self-tests agreed on the same canonical input digest; 41 unit tests passed.

`IS3-U04` passed after preserving its two revision-1 runtime failures. Topology revision 2 added a fourth exact-base, copy-only database image whose ownership-seeded path lets a new named volume initialize under required user `70:70` without a root runtime or privileged helper. Four exact local image IDs are bound in `requirements/topology-runtime.lock.json`. All 14 contract and 14 implementation mutations failed closed. Two real host-CLI probes reached PostgreSQL health and passed container identity, capability, filesystem, staged-mount, internal-network, egress-denial, sensitive-environment, and Docker-endpoint checks; the second run verified image reuse and exact-volume resume. Both runs removed every container and network. The passing and failed labeled volumes remain separately retained.

`IS3-U05` passed while retaining its real revision-2 product `FAIL`. Revision 3 separates bootstrap role `incidentseal_admin` from application role `incidentseal_runner`, revokes public database and schema creation, and grants only required DML. Sixteen contract mutations and 15 implementation mutations passed before four new exact images were runtime-locked. Two database probes passed PostgreSQL 18.4 identity, idempotent migration, schema and migration record, non-superuser attributes, bounded DML, denied DDL, denied migration-ledger reads, restart persistence, repeatability, and teardown. All three digest-bound volumes remain separately retained; no container or network remains.

## Known limitations

- The checkout CLI implements policy lint, digest, status, diff, and the TTY-only operator approval command; verification and run events remain unimplemented.
- The database surface now passes, but real Python and Node application commands remain unverified in `IS3-U06` and `IS3-U07`.
- No workflow digest is approved and workflow execution remains unavailable.
- Four selected base images have been pulled and scanned; their four revision-2 derived images ran only under the exact topology contract. The base artifacts were not started directly.
- Image redistribution remains `INCONCLUSIVE` until exact component notices and `NOASSERTION` license entries are reconciled at the release gate.
- The Distroless Node image has retained MEDIUM and LOW findings and no located signed SLSA statement; its exact signatures, Bazel history, runtime version, and runner behavior remain explicitly bounded claims.
- Direct Codex CLI execution currently fails with `Access is denied`.
- The historical `checkpoint-is-0001` marker remains at `55ad47d250041c2148c0f458d276e62d8f02a25d`; `checkpoint-is-0002` is the latest verified marker, while remote `main` has advanced through current IS-0003 evidence work.

## Next eligible action

Execute `IS3-U06` with the exact revision-3 runtime lock: run the real Python application command against bounded staged input and `incidentseal_runner`, retain positive and negative evidence, and do not claim Node or workflow verification.
