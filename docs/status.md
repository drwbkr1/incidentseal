# IncidentSeal status

- Current checkpoint: `IS-0003`
- Latest verified checkpoint: `IS-0003`
- State: checkpoint complete; next milestone not yet opened
- Version: `0.0.0`
- Canonical root: `C:\Projects\Active\incidentseal`
- Expected public remote: `https://github.com/drwbkr1/incidentseal.git`
- Expected branch: `main`
- Latest verified checkpoint commit: `a0c05070dd1d147aecae6b4ed686440414a3aa27`
- Verified checkpoint marker: `checkpoint-is-0003` tag object `28eea260147265e7dd0328dcd072e134586a2ff0` -> `a0c05070dd1d147aecae6b4ed686440414a3aa27`
- Approved workflow manifest digest: not established
- Application surfaces: topology security, PostgreSQL, Python, Node, cross-runner consistency, and bounded topology reliability are verified
- Release state: unreleased

## Current truth

The product name, promise, trust boundary, public repository owner, presentation direction, Apache-2.0 license, and long-running operating authority were approved on 2026-08-09. `IS-0003` now establishes the verified public hardened-topology checkpoint on top of the `IS-0002` manifest authority and machine CLI contract.

The canonical repository is not in OneDrive. All OneDrive paths are forbidden for IncidentSeal work.

## Active unit

`IS3-U01` passed without starting a container. The exact linux/amd64 Dockerfile frontend, Chainguard PostgreSQL 18.4, Distroless Node.js 24, and Chainguard Python 3.14.7 images are now bound in `requirements/images.lock.json` with platform children, local identities, signatures or provenance, SBOMs, vulnerability evidence, license limits, and mandatory runtime constraints.

`IS3-U02` passed without starting Docker runtime surfaces. The topology contract now binds the exact image lock, host-only Docker authority, copy-only offline builds, one internal network, numeric non-root service identities, bounded staged custody, distinct evidence states, and a normalized render model. All 12 security-relevant mutations failed closed with their expected stable error codes.

`IS3-U03` passed without building an image or starting a container. The real Windows CLI rendered `compose.yaml` through Docker Compose 5.1.3, matched the frozen normalized security projection, repeated the stable redacted-model digest, validated the exact implementation lock, and rejected all 13 real implementation mutations. Python and Node source self-tests agreed on the same canonical input digest; 41 unit tests passed.

`IS3-U04` passed after preserving its two revision-1 runtime failures. Topology revision 2 added a fourth exact-base, copy-only database image whose ownership-seeded path lets a new named volume initialize under required user `70:70` without a root runtime or privileged helper. Four exact local image IDs are bound in `requirements/topology-runtime.lock.json`. All 14 contract and 14 implementation mutations failed closed. Two real host-CLI probes reached PostgreSQL health and passed container identity, capability, filesystem, staged-mount, internal-network, egress-denial, sensitive-environment, and Docker-endpoint checks; the second run verified image reuse and exact-volume resume. Both runs removed every container and network. The passing and failed labeled volumes remain separately retained.

`IS3-U05` passed while retaining its real revision-2 product `FAIL`. Revision 3 separates bootstrap role `incidentseal_admin` from application role `incidentseal_runner`, revokes public database and schema creation, and grants only required DML. Sixteen contract mutations and 15 implementation mutations passed before four new exact images were runtime-locked. Two database probes passed PostgreSQL 18.4 identity, idempotent migration, schema and migration record, non-superuser attributes, bounded DML, denied DDL, denied migration-ledger reads, restart persistence, repeatability, and teardown. All three digest-bound volumes remain separately retained; no container or network remains.

`IS3-U06` passed while retaining two real product `FAIL` attempts. The real host CLI now executes the shipped Python application command against fixed read-only staged input and `incidentseal_runner`, independently verifies the exact result file and PostgreSQL row, rejects malformed input with no output or row, and inspects the exact image, numeric user, read-only root, dropped capabilities, no-new-privileges, narrow mounts, internal network, sensitive environment names, and Docker-endpoint absence. Two identical invocations passed with stable receipts and teardown. The earlier Compose-stderr and orphan-warning failures remain digest-bound; all containers and network were removed and the revision-3 volume remains retained.

`IS3-U07` passed on its first two real evidence runs. The host CLI executes the shipped Node application command against the same read-only staged contract and narrow database role, verifies the exact Node result and row, and requires the retained Python row to share the canonical input digest while keeping language-bound result digests distinct. Malformed input produced no output or Node row. Both invocations passed exact image, numeric user, read-only root, dropped capability, no-new-privileges, narrow mount, internal network, sensitive-environment, Docker-endpoint, repeatability, and teardown gates. No container or network remains; the same revision-3 volume is retained.

`IS3-U08` passed. Two canonical-checkout disposable runs and one exact credential-free public-clone run passed fresh bootstrap, both real runners, exact rows, tampered-receipt `FAIL`, malformed-input `INVALID`, database-outage lifecycle `failed`, post-failure recovery, host cancellation at exit `137`, restart persistence, orphan detection, protection of all three retained volumes, and complete disposable teardown. The clone also passed 50 tests and 15 implementation mutations. Two invalid harness attempts remain retained. Local command policy denied recursive deletion of the clean non-canonical temp clone, which remains outside OneDrive and outside canonical custody.

`IS3-U09` passed. Exact closure commit `a0c05070...` and tree `67c05a10...` passed the full credential-free clone matrix, Git object integrity, secret scanning, and real reliability invocation `73711f49...`. Annotated marker object `28eea260...` was pushed and independently fetched from public custody, peeling to the exact closure commit. IS-0003 is complete.

## Known limitations

- The checkout CLI implements policy lint, digest, status, diff, the TTY-only operator approval command, and bounded platform-validation probes; approved-workflow verification and its run-event stream remain unimplemented.
- The database, both real language surfaces, bounded topology reliability, exact public closure commit, and annotated checkpoint marker pass. Evidence/recovery, dashboard, packaging, and release gates remain pending in later milestones.
- No workflow digest is approved and workflow execution remains unavailable.
- Four selected base images have been pulled and scanned; the active revision-3 derived images ran only under the exact topology and runtime locks. The base artifacts were not started directly.
- Image redistribution remains `INCONCLUSIVE` until exact component notices and `NOASSERTION` license entries are reconciled at the release gate.
- The Distroless Node image has retained MEDIUM and LOW findings and no located signed SLSA statement; its exact signatures, Bazel history, runtime version, and runner behavior remain explicitly bounded claims.
- Direct Codex CLI execution currently fails with `Access is denied`.
- Historical markers `checkpoint-is-0001` and `checkpoint-is-0002` remain intact; `checkpoint-is-0003` is the latest verified marker. Remote `main` may advance with post-marker receipts and the next milestone while the marker continues to freeze its exact closure commit.

## Next eligible action

Open and validate a new `IS-0004` evidence-and-recovery milestone from `checkpoint-is-0003`. Preserve the stable machine CLI and trust boundary while adding append-only receipts, idempotency, durable cancellation/failure records, crash recovery, verified PostgreSQL backup/restore, and an independent offline receipt verifier one bounded unit at a time.
