# IncidentSeal v0.1.0 release contract

- Contract ID: `INCIDENTSEAL-RELEASE-001`
- Milestone: `IS-0006`
- Active unit: `IS6-U01`
- Candidate version: `0.1.0`
- Verified base: annotated `checkpoint-is-0005`
- Machine plan: `fixtures/release/release-plan.valid.json`
- Exact lock: `requirements/release-contract.lock.json`

## Release promise

IncidentSeal v0.1.0 may be presented as a local-first, credential-free verification layer only after an operator-approved manifest has driven the real bounded workflow path and every release surface has current candidate-bound evidence. Packaging, a registry push, a passing test suite, a mutable tag, or a rendered dashboard cannot independently support the release claim.

The release remains a verification product, not a safety certification. A `PASS` says the declared checks ran under the exact approved policy and have retained evidence. It does not say that undeclared risks are absent.

## Decisive pre-package gate

The current checkout can validate, digest, inspect, and interactively approve a manifest, but the IS-0005 CLI has no approved-workflow verifier or internal event writer. That gap must close before packaging. `IS6-U02` therefore precedes package work and must add the stable machine command:

```text
incidentseal verify --manifest PATH --json
```

The command must require current external approval `MATCH`, exact repository remote/commit/tree identity, and the unchanged manifest digest before, during, and after execution. It may run only manifest-declared Python and Node argument vectors from copy-only, read-only staged input. The host CLI owns Docker. Workloads receive no Docker socket or engine API, secret, privileged mode, host network, broad host mount, or external network. Output is limited to per-run content-addressed evidence. The agent-facing CLI never gains an approval or arbitrary event-append command.

The verifier must preserve queued, running, completed, cancelled, failed, stale, and superseded lifecycle records separately from PASS, FAIL, INCONCLUSIVE, and INVALID verification verdicts. It must retain interruption evidence and resume only under the same approved digest and safe idempotent boundary. Exact local and credential-free public real-surface replay are required before the unit closes.

## Package boundary

The initial host distribution is a pure-Python, standard-library runtime package requiring Python 3.12 or newer. It exposes `incidentseal` and `incidentseal-dashboard` console scripts and adds no product runtime dependency.

The exact release artifacts are:

- `incidentseal-0.1.0-py3-none-any.whl`
- `incidentseal-0.1.0.tar.gz`

Build frontend `build==1.5.0`, backend `hatchling==1.32.0`, and every transitive build wheel are source-gated by filename and SHA-256. Three isolated builds—two local and one clean public—must be byte-identical under `SOURCE_DATE_EPOCH=1786424840`. A fresh environment must install the wheel without resolving any runtime dependency, exercise both console scripts, and reproduce the stable JSON/JSONL and exit-code contract.

PyPI is not a v0.1.0 channel. Excluding it avoids a second publishing identity or user-managed secret and keeps the first reusable path focused on GitHub and GHCR.

## Image and redistribution boundary

One GHCR repository, `ghcr.io/drwbkr1/incidentseal`, holds four version-labelled roles:

| Role | Version label | Required runtime user |
| --- | --- | --- |
| database | `database-v0.1.0` | `70:70` |
| migration | `migration-v0.1.0` | `65532:65532` |
| Python runner | `python-runner-v0.1.0` | `65532:65532` |
| Node runner | `node-runner-v0.1.0` | `65532:65532` |

Labels are discovery aids only. Documentation, Compose, receipts, attestations, and verification must use exact registry digests. No image may publish while redistribution is `INCONCLUSIVE`, a component remains `NOASSERTION`, or a required license or notice is missing. `THIRD_PARTY_NOTICES.md` and machine-readable component decisions must bind the exact published content.

Every image requires two digest-identical builds, an SPDX 2.3 JSON SBOM, SLSA v1 in-toto provenance, zero CRITICAL and HIGH Grype findings, retained MEDIUM/LOW findings with review, exact OCI source/version/revision/license labels, and the already frozen runtime hardening. BuildKit provides image provenance and SBOM attestations; exact Syft and Grype binaries are separately source-gated for independent artifacts and scans.

## Release asset set

The GitHub Release draft must contain all nine assets before publication:

1. `incidentseal-0.1.0-py3-none-any.whl`
2. `incidentseal-0.1.0.tar.gz`
3. `incidentseal-0.1.0.spdx.json`
4. `incidentseal-0.1.0.provenance.json`
5. `incidentseal-v0.1.0-release-manifest.json`
6. `incidentseal-v0.1.0-scan-summary.json`
7. `incidentseal-v0.1.0-verification-receipt.json`
8. `THIRD_PARTY_NOTICES.md`
9. `SHA256SUMS`

The release manifest binds the candidate commit and tree, annotated tag object, every asset digest, four GHCR digests, package and image SBOMs, provenance, scans, source gates, real-surface receipts, and exact release notes. Missing or ambiguous evidence is not a partial PASS.

## Real-surface matrix

The release candidate must verify all of these from the packaged and clean-public contexts where applicable:

| Surface | Required proof |
| --- | --- |
| Packaged CLI | Fresh isolated install; stable JSON, JSONL, exits, policy status, receipt verification, and both console scripts |
| Approved workflow | Current external digest `MATCH`; exact repository; staged Python and Node commands; internal events; cancellation; recovery; no authority drift |
| Compose topology | Canonical render plus live exact image, identity, health, mount, network, capability, and teardown checks |
| PostgreSQL | Migration, least privilege, persistence, journal, logical dump, clean restore, and negative privileges |
| Python and Node | Exact declared execution, outputs, rows, isolation, negative input, cross-runner identity, and teardown |
| Dashboard | Packaged loopback launcher, security headers, fixed states, rendered desktop/mobile, accessibility, and claim calibration |
| Receipts and recovery | Materialization, independent verification, corruption rejection, event streaming, cancellation, resume, backup/restore, and two-cycle recovery |
| Clean install and clone | No cached repository import; no credential helper; exact package/image identities; complete matrix |
| Downloaded release and registry | Immutable release, every downloaded asset, attestations, exact digest pulls, clean consumer replay, and live reconciliation |

Unit tests and source inspection remain supporting evidence, never substitutes for these surfaces.

## Publication sequence and human gate

All workflow Actions are pinned to full commits and may use only repository-scoped `GITHUB_TOKEN` permissions: `contents:write`, `packages:write`, `id-token:write`, and `attestations:write`. No user-managed secret is allowed.

The exact sequence is:

1. Pass the workflow, package, redistribution, supply-chain, and complete clean candidate units.
2. Create a GitHub Release draft and attach the complete verified asset set without publishing it.
3. Present the exact candidate commit, tag, assets, digests, images, receipts, and rollback limitation at `IS6-U06-IMMUTABLE-PUBLICATION`.
4. Only after the owner confirms that irreversible action, enable immutable releases if still disabled, create the annotated `v0.1.0` tag, publish exact GHCR digests and attestations, and publish the complete release.
5. Independently download, pull, verify, replay, and reconcile every public surface before marking IS-0006 complete.

If the published state cannot be verified, IncidentSeal must not ship a release claim.

## Current-practice basis

The contract follows current primary guidance:

- Docker documents BuildKit SBOM and SLSA provenance attestations and warns that registry-capable output is required to retain them: <https://docs.docker.com/build/metadata/attestations/>.
- Docker's Compose service and trust-model references identify read-only filesystems, capability controls, host networking, bind mounts, and file references as security-relevant execution authority: <https://docs.docker.com/reference/compose-file/services/> and <https://docs.docker.com/compose/trust-model/>.
- GitHub documents artifact attestations as verifiable provenance rather than a safety guarantee, and supports verification of both files and OCI images: <https://docs.github.com/en/actions/concepts/security/artifact-attestations>.
- GitHub documents exact-digest GHCR pulls and repository association through OCI source labels: <https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry>.
- PyPA specifies `pyproject.toml`, `[project.scripts]`, standard build frontends, and isolated CLI installation: <https://packaging.python.org/en/latest/guides/writing-pyproject-toml/> and <https://packaging.python.org/en/latest/guides/creating-command-line-tools/>.
- GitHub recommends draft-first immutable releases and provides release and asset verification commands: <https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases> and <https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/verify-release-integrity>.

## Explicit non-goals

This release does not add Kubernetes, cloud infrastructure, multi-tenancy, arbitrary remote execution, PyPI publication, paid services, or a reusable Codex skill. The skill remains gated until the installed machine contract is stable across verified checkpoints and multiple repository integrations.

## Current non-claims

This contract is runtime-free. It does not approve a manifest, run a workflow, acquire a build dependency, build a package or image, resolve image redistribution, create a workflow, tag, release, or package, change GitHub access or settings, or prove v0.1.0. Those remain separate dependency-ordered units.
