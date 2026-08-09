# IncidentSeal

**Evidence before release.**

IncidentSeal is a local-first, credential-free verification layer between Codex-authored changes and release claims. It is designed to run an operator-approved workflow against real local surfaces and export evidence that identifies the policy, source, dependencies, images, topology, commands, outcomes, and recovery history involved.

IncidentSeal does not claim to be a complete sandbox, vulnerability scanner, release certification, cloud CI platform, or arbitrary remote-execution system.

## Current state

Checkpoint `IS-0001` is establishing the product contract, threat model, project control plane, environment inventory, and exact-image source gate. No application CLI, Compose topology, database, runner, dashboard, or released image exists yet.

Current truth is recorded in:

- [`docs/status.md`](docs/status.md)
- [`docs/roadmap.md`](docs/roadmap.md)
- [`docs/product-contract.md`](docs/product-contract.md)
- [`docs/threat-model.md`](docs/threat-model.md)
- [`control/project-control.json`](control/project-control.json)

## Intended workflow

1. An operator reviews and approves the digest of a versioned verification manifest.
2. The host-side IncidentSeal CLI verifies that approval and owns every Docker and Compose operation.
3. Hardened, network-restricted containers execute only the manifest-declared verification units.
4. PostgreSQL indexes the event history while portable, content-addressed receipts retain independent evidence.
5. The CLI and local dashboard report verification verdicts separately from execution lifecycle state.
6. Release claims are allowed only when every required real-surface gate has current evidence.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
