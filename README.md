# IncidentSeal

**Evidence before release.**

IncidentSeal is a local-first, credential-free verification layer between Codex-authored changes and release claims. It is designed to run an operator-approved workflow against real local surfaces and export evidence that identifies the policy, source, dependencies, images, topology, commands, outcomes, and recovery history involved.

IncidentSeal does not claim to be a complete sandbox, vulnerability scanner, release certification, cloud CI platform, or arbitrary remote-execution system.

## Current state

`IS-0002` is the latest verified public checkpoint. `IS-0003` is active: exact source-gated images and the frozen topology contract have passed, and the host CLI now has a static `topology validate` surface for the implemented Compose, migration, Python, and Node sources. The implementation has not built an image or started a container yet; database and runner behavior remain unverified runtime claims.

Current truth is recorded in:

- [`docs/status.md`](docs/status.md)
- [`docs/roadmap.md`](docs/roadmap.md)
- [`docs/product-contract.md`](docs/product-contract.md)
- [`docs/threat-model.md`](docs/threat-model.md)
- [`control/project-control.json`](control/project-control.json)

The current static real-surface check is:

```powershell
.\incidentseal.cmd topology validate --mode platform-validation --json
```

It renders Compose and returns one machine envelope. A PASS is explicitly topology-only and uses synthetic derived-image identities; it is not runtime, workflow, or release proof.

## Intended workflow

1. An operator reviews and approves the digest of a versioned verification manifest.
2. The host-side IncidentSeal CLI verifies that approval and owns every Docker and Compose operation.
3. Hardened, network-restricted containers execute only the manifest-declared verification units.
4. PostgreSQL indexes the event history while portable, content-addressed receipts retain independent evidence.
5. The CLI and local dashboard report verification verdicts separately from execution lifecycle state.
6. Release claims are allowed only when every required real-surface gate has current evidence.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
