# IncidentSeal

**Evidence before release.**

IncidentSeal is a local-first, credential-free verification layer between Codex-authored changes and release claims. It is designed to run an operator-approved workflow against real local surfaces and export evidence that identifies the policy, source, dependencies, images, topology, commands, outcomes, and recovery history involved.

IncidentSeal does not claim to be a complete sandbox, vulnerability scanner, release certification, cloud CI platform, or arbitrary remote-execution system.

## Current state

`checkpoint-is-0004` is the latest verified public checkpoint. It adds portable receipts, independent offline verification, an immutable PostgreSQL event journal, fenced interruption recovery, verified backup/clean restore, and repeated integrated recovery to the hardened Compose, PostgreSQL, Python, and Node surfaces. `IS-0005` is active: its dashboard contract has passed from public custody and the local read-only implementation candidate awaits exact public replay and rendered-browser evaluation. IncidentSeal remains unreleased at `0.0.0`.

Current truth is recorded in:

- [`docs/status.md`](docs/status.md)
- [`docs/roadmap.md`](docs/roadmap.md)
- [`docs/product-contract.md`](docs/product-contract.md)
- [`docs/threat-model.md`](docs/threat-model.md)
- [`control/project-control.json`](control/project-control.json)

The static topology check is:

```powershell
.\incidentseal.cmd topology validate --mode platform-validation --json
```

It renders Compose and returns one machine envelope. A PASS from that command is explicitly topology-only. Separate host-owned probes validate the database, Python runner, Node runner, and disposable recovery topology; none of those platform-validation probes approves or executes a workflow manifest.

The dashboard is deliberately separate from that frozen verification CLI. Start the current local candidate on an operating-system-assigned IPv4 loopback port with:

```powershell
.\incidentseal-dashboard.cmd --port 0
```

Open only the `http://127.0.0.1:PORT/` endpoint reported by its startup JSON. The process is read-only, serves five fixed local routes, accepts only exact-host `GET` and `HEAD`, and has no Docker, approval, workflow, secret, repository-write, analytics, telemetry, or external-network authority. See [`docs/dashboard-implementation.md`](docs/dashboard-implementation.md). Rendered browser quality and accessibility remain separate gates until their receipts exist.

## Intended workflow

1. An operator reviews and approves the digest of a versioned verification manifest.
2. The host-side IncidentSeal CLI verifies that approval and owns every Docker and Compose operation.
3. Hardened, network-restricted containers execute only the manifest-declared verification units.
4. PostgreSQL indexes the event history while portable, content-addressed receipts retain independent evidence.
5. The CLI and local dashboard report verification verdicts separately from execution lifecycle state.
6. Release claims are allowed only when every required real-surface gate has current evidence.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
