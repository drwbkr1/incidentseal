# Integrated receipt and recovery implementation

- Implementation ID: `INCIDENTSEAL-INTEGRATED-RECOVERY-IMPLEMENTATION-001`
- Unit: `IS4-U06`
- Harness: `python -B scripts/run_integrated_recovery_implementation.py`
- Authority: fixed synthetic platform validation only

## Fixed host orchestration

The agent-facing harness accepts no arguments: no manifest, workflow, project, volume, receipt, archive, source, destination, stage selection, repetition count, mode selection, or arbitrary operation. The host process invokes the six already locked machine-command identities in the frozen five-stage order: receipt materialize and verify, reliability, journal, recovery, and backup/clean restore. It deliberately adds no seventh command to the stable IncidentSeal CLI because changing that locked dispatcher would invalidate the already approved contract dependencies. No container receives or owns Docker authority.

The full sequence runs exactly twice. Receipt custody is created under a host temporary directory outside the repository and OneDrive, then removed. Each Docker stage remains an independent child CLI process and uses only its existing fixed synthetic custody. Before and after every stage, and after every cycle, the host requires zero IncidentSeal containers and networks, exactly the three protected evidence volumes, and byte-stable canonical volume identities. An unexpected resource fails closed before the next stage.

## Evidence mapping

The harness emits one `incidentseal-cli-envelope/v1` document with command identity `validation.integrated-recovery`; its data is `incidentseal-integrated-recovery-probe/v1`. It retains every child invocation identity and exact child-output digest, while the stable semantic projection binds all twenty frozen cases. Lifecycle, run verdict, observation verdict, and exit remain separate. In particular, completed product `FAIL` is not lifecycle `failed`; malformed input has no run lifecycle because both runners create no result and the database gains no row; cancelled, failed, stale, and superseded states have no run verdict; a successfully completed safe-replay operation does not fabricate a run verdict; ambiguous recovery remains `INCONCLUSIVE`; and conflicting recovery remains `FAIL`.

Cross-cycle equality covers exact image IDs, topology contract digest, receipt semantics, journal streams, recovery decisions, normalized backup TOC, restored schema/journal/result/role state, negative privileges, protected-volume identity, and teardown. Every raw custom archive is still hashed and bound by its own backup receipt. Raw archive bytes, their derived receipt digests, timestamps, UUIDs, invocation and container IDs are deliberately excluded from equality and never from individual evidence.

## Trust boundary and non-claims

The implementation introduces no dependency, workflow executor, approval access, general recovery command, general backup command, external runtime network, container secret, broad host mount, privileged container, or Docker socket mount. It runs only the fixed non-sensitive scenarios already authorized by `IS-0004`. A valid composite result does not approve or execute a repository workflow and does not prove dashboard, packaging, registry, downloaded-release, or software-release behavior.

If a child surface returns a valid product `FAIL`, the composite retains and returns `FAIL`; it does not rewrite it as `INVALID`. Malformed child streams, lock drift, custody ambiguity, unsafe residue, or unexpected exits fail closed as invalid or I/O evidence through the existing CLI contract.
