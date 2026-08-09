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
- Application surfaces: not implemented
- Release state: unreleased

## Current truth

The product name, promise, trust boundary, public repository owner, presentation direction, Apache-2.0 license, and long-running operating authority were approved on 2026-08-09. `IS-0002` now establishes the public manifest authority and real host CLI contract: exact local and public clean clones passed both checkout launchers, 38 tests, full Draft 2020-12 schema validation, approval denial, frozen mutations, and 50 fail-closed executions without Docker or real approval state.

The canonical repository is not in OneDrive. All OneDrive paths are forbidden for IncidentSeal work.

## Active unit

`IS3-U01` passed without starting a container. The exact linux/amd64 Dockerfile frontend, Chainguard PostgreSQL 18.4, Distroless Node.js 24, and Chainguard Python 3.14.7 images are now bound in `requirements/images.lock.json` with platform children, local identities, signatures or provenance, SBOMs, vulnerability evidence, license limits, and mandatory runtime constraints.

`IS3-U02` is the sole eligible unit. It must freeze the Compose and service contract around that lock before Dockerfiles, Compose configuration, migrations, runners, or host orchestration are implemented. No selected image may run merely because acquisition passed.

## Known limitations

- The checkout CLI implements policy lint, digest, status, diff, and the TTY-only operator approval command; verification and run events remain unimplemented.
- No Compose topology or database exists.
- No workflow digest is approved and workflow execution remains unavailable.
- Four selected exact images have been pulled and scanned and are eligible only for later contract-controlled execution. None has been started.
- Image redistribution remains `INCONCLUSIVE` until exact component notices and `NOASSERTION` license entries are reconciled at the release gate.
- The Distroless Node image has retained MEDIUM and LOW findings and no located signed SLSA statement; its exact signatures, Bazel history, runtime version, and runner behavior remain explicitly bounded claims.
- Direct Codex CLI execution currently fails with `Access is denied`.
- The verified `checkpoint-is-0001` marker remains at `55ad47d250041c2148c0f458d276e62d8f02a25d`; remote `main` has advanced through current IS-0003 evidence work.

## Next eligible action

Execute `IS3-U02` in `contracts/IS-0003.json`: freeze the Compose, service identity, user, network, mount, filesystem, health, migration, runner, and host-orchestration contract around `requirements/images.lock.json` before implementation or runtime use.
