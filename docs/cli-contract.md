# CLI machine contract

- Contract: `INCIDENTSEAL-CLI-001`
- Version: `1.0`
- Status: frozen for implementation by `IS2-U01`
- Result schema: `schemas/cli-envelope-v1.schema.json`
- Event schema: `schemas/run-event-v1.schema.json`

## Stable agent-facing commands

The v1 Codex integration surface is the local `incidentseal` executable plus repository guidance. These commands are non-interactive and never mutate operator approval:

| Command ID | CLI shape | Purpose |
| --- | --- | --- |
| `policy.lint` | `incidentseal policy lint --manifest PATH --json` | Strict parsing and schema validation. |
| `policy.digest` | `incidentseal policy digest --manifest PATH --json` | Return canonical digest and canonical byte count. |
| `policy.status` | `incidentseal policy status --manifest PATH --json` | Compare the manifest with external approval. |
| `policy.diff` | `incidentseal policy diff --manifest PATH --json` | Explain bound-field and canonical policy differences without writing approval. |
| `topology.validate` | `incidentseal topology validate --mode platform-validation --json` | Render and compare the real static Compose security projection without building or starting containers. |
| `topology.runtime-probe` | `incidentseal topology runtime-probe --mode platform-validation --json` | Build or verify exact local images, run topology-only security probes, and clean containers/network while retaining evidence-bound database storage. |
| `topology.database-probe` | `incidentseal topology database-probe --mode platform-validation --json` | Execute the real migration and evaluate PostgreSQL identity, role privilege, schema, bounded DML, forbidden DDL, restart persistence, and teardown. |
| `topology.python-probe` | `incidentseal topology python-probe --mode platform-validation --json` | Execute the shipped Python application command and evaluate exact staged input, result receipt, PostgreSQL row, malformed-input rejection, runtime isolation, repeatability, and teardown. |
| `topology.node-probe` | `incidentseal topology node-probe --mode platform-validation --json` | Execute the shipped Node application command and evaluate exact staged input, result receipt, PostgreSQL row, Python-row consistency, malformed-input rejection, runtime isolation, repeatability, and teardown. |
| `topology.reliability-probe` | `incidentseal topology reliability-probe --mode platform-validation --json` | Exercise a protected disposable topology through fresh start, real runners, distinct failure/cancellation states, recovery, restart, orphan detection, and teardown. |
| `topology.journal-probe` | `incidentseal topology journal-probe --mode platform-validation --json` | Exercise fixed synthetic append, exact replay/conflict rejection, real ordered JSONL streaming, restart persistence, immutability, protected-volume identity, and disposable teardown. |
| `topology.recovery-probe` | `incidentseal topology recovery-probe --mode platform-validation --json` | Exercise fixed synthetic PostgreSQL recovery fencing, exact runtime ownership, stop and reobservation, idempotent replay, durable pending-decision resume, state-separated terminals, restart persistence, protected-volume identity, and teardown. |
| `topology.backup-restore-probe` | `incidentseal topology backup-restore-probe --mode platform-validation --json` | Create and hash a fixed synthetic custom archive, inspect its normalized TOC, restore it into different clean disposable custody, reapply locked role hardening, and verify exact state, negative privileges, restart persistence, protected-volume identity, and teardown. |
| `receipt.materialize` | `incidentseal receipt materialize --receipt PATH --source-root PATH --output-root PATH --json` | Validate exact source receipt/artifact bytes and atomically create or idempotently reuse a content-addressed portable bundle outside repository and OneDrive custody. |
| `receipt.verify` | `incidentseal receipt verify --receipt PATH --bundle-root PATH [--expected-digest SHA256] --json` | Read-only offline verification; exact identity may pass, unbound identity is inconclusive, corruption fails, and unsafe custody is invalid. |
| `verify` | `incidentseal verify --manifest PATH --json` | Execute only after approval status is `MATCH`. |
| `run.events` | `incidentseal run events --run-id ID --jsonl` | Stream retained append-only events. |

`topology.runtime-probe` remains narrower than workflow verification. A PASS binds exact local image IDs, runtime inspections, fixed isolation probes, retained-volume identity, and teardown state in `requirements/topology-runtime.lock.json`; it does not approve a manifest, execute repository input, prove the real migration or application runner commands, or authorize image publication.

`topology.database-probe` returns a product `FAIL` with exit `10` when a valid database run exposes a failed gate; invalid locks, custody, or runtime state remain `INVALID` with exit `12`. Its bounded persistence rows are platform evidence, not a repository workflow.

`topology.python-probe` has the same product-failure semantics. A PASS proves only the exact Python application surface bound in the active runtime lock. It does not prove Node behavior, approve or run a workflow, or verify cancellation, recovery, dashboard, clean-clone, redistribution, or release claims.

`topology.node-probe` has the same product-failure semantics and additionally binds the Node result to the retained Python row through the shared canonical input digest. A PASS proves only the exact Node and bounded cross-runner surface; it does not approve or run a workflow or verify cancellation, recovery, dashboard, clean-clone, redistribution, or release claims.

`topology.reliability-probe` operates only on the exact disposable project named by the retained-volume lock. It may delete only that non-sensitive disposable volume after verified teardown. Its machine output keeps verification `FAIL` and `INVALID` separate from lifecycle `failed` and `cancelled`. A canonical-checkout PASS does not prove the clean-clone gate.

`topology.journal-probe` uses the same fixed disposable custody and no repository workflow input. Its records are the frozen platform-validation vectors, not evidence of workflow approval or execution. It must compare protected volume identities before and after and remove the disposable volume. The agent-facing CLI exposes no append command.

`topology.recovery-probe` is the only recovery mutation surface in this checkpoint. It accepts no manifest, run ID, container ID, path, or arbitrary command. The host CLI creates fixed synthetic runs in the locked disposable project, acquires a separate PostgreSQL recovery fence after an expired workflow lease, requires exact image/label/user/isolation ownership before stopping, reobserves after every stop, writes only contract-derived journal evidence, and removes all disposable custody. `MATCH` authority inside this probe is a fixed platform-validation sentinel, never operator approval. No agent-facing `run recover` or journal append command exists.

`topology.backup-restore-probe` is the only backup or restore mutation surface in this checkpoint. It accepts no manifest, database, project, volume, archive, destination, path, or arbitrary command. The host CLI owns Docker and uses two fixed synthetic projects, exact locked images, internal-only networks, no secrets or Docker socket, and one narrow temporary archive mount outside the repository and OneDrive. A dump alone is never PASS: the exact bytes and normalized TOC must restore into a different clean volume and pass state equivalence, role hardening, five negative privileges, restart persistence, protected-volume identity, archive cleanup, and full disposable teardown.

The separate operator surface is `incidentseal operator approve-manifest --manifest PATH`. It is deliberately interactive and is not part of the agent-safe machine path.

`receipt.materialize` and `receipt.verify` do not approve or execute a workflow and never access Docker, PostgreSQL, the network, or approval state. Materialization writes only beneath the explicit non-repository, non-OneDrive output root. Verification writes nothing. Their `data` object conforms to the frozen receipt implementation or verification contract; the outer envelope and stable exit meanings remain v1.

## Output discipline

For `--json`:

- stdout contains exactly one UTF-8 JSON document conforming to `incidentseal-cli-envelope/v1`, followed by one newline;
- stdout never contains progress text, banners, color, prompts, or logs;
- stderr contains human diagnostics only and may be empty;
- the JSON `process_exit_code` equals the actual process exit code; and
- a command that completed correctly may still carry product verdict `FAIL`, `INCONCLUSIVE`, or `INVALID`.

For `--jsonl`:

- stdout contains one `incidentseal-run-event/v1` JSON object per line;
- `sequence` is monotonic and unique within a run;
- already retained events are not rewritten;
- stderr remains outside the event stream; and
- cancellation, execution failure, staleness, and supersession remain lifecycle values rather than verification verdicts.

`run events` streams the exact canonical event bytes retained by PostgreSQL. Its final event determines the stable lifecycle or verdict exit code. An empty matching run is `INCONCLUSIVE` at `11`; unavailable active journal custody is an evidence-read error at `74`. No JSON envelope is inserted into the event stream.

All machine timestamps are second-precision UTC in `YYYY-MM-DDTHH:MM:SSZ`. All content digests use lowercase `sha256:` form. UUIDs are lowercase RFC 4122 version 4 strings in v1 fixtures and envelopes.

## Exit codes

| Code | Stable meaning |
| ---: | --- |
| `0` | Inspection succeeded, or verification completed with `PASS`. |
| `10` | Verification completed with `FAIL`. |
| `11` | Verification completed with `INCONCLUSIVE`. |
| `12` | Verification or policy evaluation produced `INVALID`. |
| `20` | The requested run is `cancelled`. |
| `21` | The requested run lifecycle is `failed`; the verification verdict may be absent. |
| `22` | The referenced evidence or run is `stale`. |
| `23` | The referenced run or evidence is `superseded`. |
| `64` | CLI usage error before a valid request exists. |
| `70` | Unexpected internal CLI error. |
| `74` | Required local input or evidence could not be read or written. |
| `77` | The caller attempted a forbidden authority mutation or the approval custody boundary is unsafe. |

Policy mismatch, missing approval, expired approval, and invalid approval custody are product verdict `INVALID` with exit `12`. Exit `77` is reserved for a direct boundary violation such as attempting an operator-only write through a non-interactive or agent-facing path.

## Independent state dimensions

`command_status`, verification `verdict`, and run `lifecycle` answer different questions:

- `command_status` says whether the CLI fulfilled the request (`succeeded`, `rejected`, or `errored`).
- `verdict` says whether evidence supports the declared claim (`PASS`, `FAIL`, `INCONCLUSIVE`, or `INVALID`).
- `lifecycle` says what happened to the run (`queued`, `running`, `completed`, `cancelled`, `failed`, `stale`, or `superseded`).

Examples:

- A completed verification that finds a failing check is `command_status=succeeded`, `lifecycle=completed`, `verdict=FAIL`, exit `10`.
- A process crash is `command_status=errored`, `lifecycle=failed`, `verdict=null`, exit `21`.
- A changed unapproved manifest is `command_status=rejected`, `lifecycle=null`, `verdict=INVALID`, exit `12`.

No implementation may infer a missing verdict from lifecycle or overwrite prior attempts when a later attempt passes.

## Error and evidence rules

Errors are structured as stable `IS_*` codes with a bounded message, optional detail object, and explicit retriability. Human prose may improve without changing the code meaning.

Evidence references contain a kind, path or locator, and exact SHA-256 digest. The envelope references evidence; it does not silently inline or discard the retained record. Paths printed to machine output must be absolute or explicitly relative to a declared evidence root.

## Compatibility

- Additive fields require a new schema version because v1 envelopes are closed.
- New command IDs may use the same envelope if their `data` object is documented and fixtures are added.
- Existing exit-code meanings, enum values, and error-code meanings cannot be reassigned.
- The reusable Codex skill remains gated until this contract survives implementation, evaluation, and at least two repository integrations.

Current Codex guidance supports this design: repository `AGENTS.md` is the durable project instruction surface, while non-interactive `codex exec --json` uses JSONL for machine consumption. IncidentSeal supplies its own narrower stable contract and does not depend on Codex session files as release evidence. See [AGENTS.md guidance](https://learn.chatgpt.com/docs/agent-configuration/agents-md.md) and [Codex non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode.md).
