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

`topology.runtime-probe` remains narrower than workflow verification. A PASS binds exact local image IDs, runtime inspections, fixed isolation probes, retained-volume identity, and teardown state in `requirements/topology-runtime.lock.json`; it does not approve a manifest, execute repository input, prove the real migration or application runner commands, or authorize image publication.
| `verify` | `incidentseal verify --manifest PATH --json` | Execute only after approval status is `MATCH`. |
| `run.events` | `incidentseal run events --run-id ID --jsonl` | Stream retained append-only events. |

The separate operator surface is `incidentseal operator approve-manifest --manifest PATH`. It is deliberately interactive and is not part of the agent-safe machine path.

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
