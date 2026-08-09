# Static topology implementation

`IS3-U03` implements the frozen topology but deliberately stops before image build or runtime. The real host command is:

```text
incidentseal topology validate --mode platform-validation --json
```

The command is non-interactive, accepts no manifest, never reads or writes approval, creates only short-lived generated staging directories, invokes `docker compose config --format json`, and returns one `incidentseal-cli-envelope/v1` document. It validates exact implementation hashes, copy-only Dockerfiles, exact frontend and base references, commands, environments, dependencies, health checks, tmpfs controls, staged bind sources, labels, networking, mounts, and the normalized security projection.

Static validation injects clearly synthetic IDs for the three derived images. It redacts generated staging paths before hashing the Compose model, so repeated renders have a stable digest without turning placeholders into runtime authority. `pull_policy: never` remains frozen; `IS3-U04` must build the derived images, bind their real local IDs in a separate runtime lock, rerender, and only then start the topology.

The implementation contains:

- four Compose services: PostgreSQL, one-shot migration, Python runner, and Node runner;
- one internal bridge and one non-external database volume;
- three narrow, exact-base, copy-only Dockerfiles with no `RUN`, package resolution, build network, secret, SSH mount, or remote `ADD`;
- an idempotent PostgreSQL schema;
- standard-library-only Python and Node runners with bounded PostgreSQL v3 clients; and
- an exact implementation lock covering every executable or rendered product input.

The source self-tests prove only parsing and cross-language canonical-input agreement. Real PostgreSQL authentication, inserts, result files, image users, filesystems, mounts, egress denial, and cleanup remain runtime claims for later units.
