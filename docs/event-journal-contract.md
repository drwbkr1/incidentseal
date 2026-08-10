# Append-only event journal contract

- Contract: `INCIDENTSEAL-EVENT-JOURNAL-001`
- Version: `1.0`
- Unit: `IS4-U03`
- Event schema: `schemas/run-event-v1.schema.json`
- Record schema: `schemas/event-journal-record-v1.schema.json`
- Result schema: `schemas/event-journal-result-v1.schema.json`

## Claim boundary

The journal retains exact `incidentseal-run-event/v1` bytes in a contiguous, per-run hash chain. It is an evidence store, not authority: appending a record cannot approve a manifest, create a verification verdict, or execute a workflow. An approved-workflow writer may append only after the separate approval gate is `MATCH`; `IS4-U03` validation uses fixed synthetic records and no workflow execution.

## Deterministic identities

All identities use SHA-256 over RFC 8785 canonical JSON.

- `event_digest` hashes the complete event.
- `previous_link_digest` is the prior retained link for the same run, or the all-zero genesis digest at sequence zero.
- `link_digest` hashes exactly `schema_version=incidentseal-event-link/v1`, `sequence`, `event_digest`, and `previous_link_digest`.
- `idempotency_key` hashes exactly `schema_version=incidentseal-event-idempotency/v1`, `run_id`, `sequence`, `event_digest`, and `previous_link_digest`.

The host allocates an event ID and timestamp once, retains the exact record, and retries those same bytes. An exact existing idempotency key and exact record is `replayed` without a new row, sequence, or timestamp. Reusing a key, event ID, or run sequence for different bytes is `INVALID` with `IS_JOURNAL_CONFLICT`.

## Append and transition rules

The first event is sequence zero, `run.queued`, lifecycle `queued`, non-terminal, with the genesis predecessor. Later sequences are exactly previous sequence plus one and name the exact prior link. The approval and manifest digests are equal and constant across a run.

Allowed lifecycle movement is:

- `queued` to `running`, `cancelled`, `failed`, `stale`, or `superseded`;
- `running` to `running`, `completed`, `cancelled`, `failed`, `stale`, or `superseded`; and
- no event after `completed`, `cancelled`, `failed`, `stale`, or `superseded`.

Only `completed` carries `PASS`, `FAIL`, `INCONCLUSIVE`, or `INVALID`. Every other lifecycle carries a null verdict. Terminal event types, lifecycle, terminal flag, and run summary remain exact and independent.

`run.stale` has exactly `expected_authority_digest`, `observed_authority_digest`, and non-empty `reason`; the two digests must differ. `run.superseded` has exactly non-empty `reason` and a distinct `superseded_by_run_id`. Both are terminal records on the original run. They never delete, relabel, or rewrite that run, and a successor is a separate run with its own sequence-zero record.

## Persistence boundary

Implementation must commit one append transaction at a time, enforce unique event ID, idempotency key, and `(run_id, sequence)`, and expose ordered read-only streaming. It must store canonical event bytes plus all derived digests so export does not depend on PostgreSQL JSON formatting. No caller receives table update or delete authority; exact replay is the only no-op success.

Contract validation is dependency-free. Full Draft 2020-12 evaluation uses the already source-gated exact temporary evaluator and adds no runtime dependency. No Docker, PostgreSQL, network, secret, approval write, or protected volume is used by this contract stage.
