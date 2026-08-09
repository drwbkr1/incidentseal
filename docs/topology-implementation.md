# Static topology implementation

`IS3-U03` implements the frozen topology but deliberately stops before image build or runtime. The real host command is:

```text
incidentseal topology validate --mode platform-validation --json
```

The command is non-interactive, accepts no manifest, never reads or writes approval, creates only short-lived generated staging directories, invokes `docker compose config --format json`, and returns one `incidentseal-cli-envelope/v1` document. It validates exact implementation hashes, copy-only Dockerfiles, exact frontend and base references, commands, environments, dependencies, health checks, tmpfs controls, staged bind sources, labels, networking, mounts, and the normalized security projection.

Static validation injects clearly synthetic IDs for the four derived images. It redacts generated staging paths before hashing the Compose model, so repeated renders have a stable digest without turning placeholders into runtime authority. `pull_policy: never` remains frozen. `IS3-U04` built the four images with network disabled, bound their exact local IDs in `requirements/topology-runtime.lock.json`, rerendered with those IDs, and only then started the topology-only probes.

The implementation contains:

- four Compose services: PostgreSQL, one-shot migration, Python runner, and Node runner;
- one internal bridge and one non-external database volume;
- four narrow, exact-base, copy-only Dockerfiles with no `RUN`, package resolution, build network, secret, SSH mount, or remote `ADD`; the database context contains only its Dockerfile and fixed UID/GID 70 ownership marker;
- an idempotent PostgreSQL schema with a migration ledger, separate bootstrap and runner roles, revoked public creation, and explicit bounded runner DML grants;
- standard-library-only Python and Node runners with bounded PostgreSQL v3 clients; and
- an exact implementation lock covering every executable or rendered product input.

The source self-tests prove only parsing and cross-language canonical-input agreement. U04 proves exact image users, read-only roots, privilege and capability controls, staged mount direction, internal networking, egress denial, Docker-endpoint absence, database health, repeated volume resume, and container/network cleanup. U05 proves the real migration, PostgreSQL identity, least-privilege application role, schema, migration record, bounded DML, denied DDL and ledger reads, restart persistence, repeatability, and cleanup. The real Python and Node application commands remain separate claims for U06 and U07.
