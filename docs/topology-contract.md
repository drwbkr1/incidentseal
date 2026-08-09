# Hardened topology contract

- Contract: `INCIDENTSEAL-TOPOLOGY-001`
- Version: `1.0`
- Machine instance: `contracts/topology-v1.json`
- Schema: `schemas/topology-contract-v1.schema.json`
- Image authority: `requirements/images.lock.json`
- Status: frozen by `IS3-U02`

## User-facing promise

The topology is a local verification substrate, not a second control plane. The host IncidentSeal CLI is the only Docker and Compose client. PostgreSQL, migrations, and the two language runners are untrusted workloads with no Docker socket, secret, privileged mode, host network, published port, broad host mount, or external network.

The roadmap's control service is the host CLI. There is deliberately no orchestration container: placing Docker authority or approval authority in a service would cross the product trust boundary and add a platform surface without improving verification.

## Two operation modes

`platform-validation` starts only fixed IncidentSeal infrastructure and baked-in synthetic probes. It accepts no repository input, runs no repository command, and may claim only topology behavior. This mode lets the project verify isolation and reliability before any real manifest is approved.

`workflow-execution` requires external approval status `MATCH` for the exact workflow digest. The host CLI rechecks authority before staging, after staging, and before each runner. Only declared inputs are copied into bounded external custody; the repository itself is never mounted. A platform-validation result can never be promoted into a release claim for repository work.

## Build boundary

Derived migration and runner images use the exact Dockerfile frontend and base images in the image lock. Build contexts are three narrow container directories. Dockerfiles are copy-and-configure only: `RUN`, remote `ADD`, build secrets, SSH mounts, online dependency resolution, and build networking are denied. The Python and Node runners use only their standard libraries, including a deliberately small PostgreSQL v3 client for fixed, parameter-bounded result operations.

The host records each derived local image ID in a runtime lock and sets `pull_policy: never`. A mutable local tag is never sufficient authority. If Compose cannot use and verify the expected local image ID, the implementation fails rather than falling back to a floating tag.

## Runtime topology

The Compose model contains four container services:

- `database`: persistent PostgreSQL 18.4, forced to UID/GID `70:70`, with one named data volume and bounded tmpfs paths;
- `migration`: one-shot `psql` from a copy-only derived PostgreSQL image;
- `python-runner`: one-shot Python 3.14.7, UID/GID `65532:65532`;
- `node-runner`: one-shot Distroless Node.js 24, UID/GID `65532:65532`.

Every service has a read-only root filesystem, drops all capabilities, sets no-new-privileges, disables restart, uses bounded PIDs and tmpfs, joins only the internal `data` bridge, and publishes no port. PostgreSQL trust authentication is acceptable only because the database is isolated on that internal network, has no host port, and receives no secret.

## Staged custody

The host copies only manifest-declared paths into a per-run state directory outside the repository and every forbidden root. Symlinks, reparse points, hardlinks, devices, sockets, FIFOs, path escapes, ambiguous case, and ownership or permission failures are rejected. A run is bounded to 4,096 files and 256 MiB before Docker sees any input.

Inputs mount read-only. Each runner receives a separate narrow output directory; it cannot write the input or source tree. Outputs become evidence only after the host hashes, promotes, and verifies them. Staging cleanup follows evidence promotion and never doubles as evidence deletion.

## Proof rules

A schema pass or `docker compose config` pass proves only contract shape. Static implementation validation must also reject mutations, bind exact local image identities, and compare the normalized render with the frozen contract. Runtime PASS requires later real probes of users, capabilities, filesystems, mounts, networks, egress denial, health, migration, database persistence, both runners, cancellation, and cleanup.

The topology preserves `PASS`, `FAIL`, `INCONCLUSIVE`, and `INVALID` independently from `queued`, `running`, `completed`, `cancelled`, `failed`, `stale`, and `superseded`.
