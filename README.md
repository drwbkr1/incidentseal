# IncidentSeal

**Evidence before release.**

IncidentSeal is a local-first, credential-free verification layer between Codex-authored changes and release claims. It is designed to run an operator-approved workflow against real local surfaces and export evidence that identifies the policy, source, dependencies, images, topology, commands, outcomes, and recovery history involved.

IncidentSeal does not claim to be a complete sandbox, vulnerability scanner, release certification, cloud CI platform, or arbitrary remote-execution system.

## Current state

`checkpoint-is-0003` is the latest verified public checkpoint. It freezes an exact-image hardened Compose topology, least-privilege PostgreSQL, the shipped Python and Node commands, state-separated reliability behavior, and a credential-free public-clone replay. IncidentSeal remains unreleased at `0.0.0`; evidence recovery, the dashboard, release packaging, and release supply-chain gates are still planned.

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

## Intended workflow

1. An operator reviews and approves the digest of a versioned verification manifest.
2. The host-side IncidentSeal CLI verifies that approval and owns every Docker and Compose operation.
3. Hardened, network-restricted containers execute only the manifest-declared verification units.
4. PostgreSQL indexes the event history while portable, content-addressed receipts retain independent evidence.
5. The CLI and local dashboard report verification verdicts separately from execution lifecycle state.
6. Release claims are allowed only when every required real-surface gate has current evidence.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
