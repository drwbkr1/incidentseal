# Interruption recovery contract

- Contract: `INCIDENTSEAL-RECOVERY-001`
- Version: `1.0`
- Unit: `IS4-U04`
- Observation schema: `schemas/recovery-observation-v1.schema.json`
- Decision schema: `schemas/recovery-decision-v1.schema.json`

## Claim boundary

This contract classifies a closed read-only observation of one nonterminal run. It does not grant workflow authority, approve a manifest, stop a real process, append a journal row, execute a workflow, or claim that recovery works at runtime. Contract validation is dependency-free and starts no Docker surface.

The recovery decision has its own `verification_verdict`. The interrupted run retains a separate lifecycle and a separate run verdict. Recovery may validate `PASS` while correctly recording the run as `cancelled` or `failed`; it may validate `FAIL` when durable effects conflict; and it must return `INCONCLUSIVE` when custody or effects are ambiguous. Every recovery append plan keeps the run verdict null.

## Fencing and ownership

The observation binds the exact journal root, last sequence, manifest and approval digest, step boundary, replay policy, host lease, runtime ownership, exit state, and artifact/database/receipt effects.

- An active lease always defers without mutation.
- A missing or invalid lease always defers without mutation.
- A visible runtime that is unowned or ambiguously owned always defers without mutation.
- Only an expired lease plus exact runtime ownership permits `stop_owned_and_wait`.
- Stopping is an intermediate action. The host must wait, reobserve, and classify a new content-addressed observation before replaying or terminalizing.

Containers are observations, never authority. The host CLI remains the only Docker owner, and the later implementation may act only in the fixed disposable project while proving every protected volume identity before and after.

## Deterministic decisions

`observation_digest` is SHA-256 over RFC 8785 canonical JSON containing `schema_version=incidentseal-recovery-observation-identity/v1` and the complete observation. `decision_digest` is the same construction over `schema_version=incidentseal-recovery-decision-identity/v1` and the complete decision excluding its digest.

The classifier applies this precedence:

1. active, missing, or invalid lease custody defers;
2. unowned or ambiguous runtime custody defers;
3. authority mismatch stops an exactly owned running runtime, otherwise records `stale`; unavailable authority defers without append;
4. a confirmed operator cancellation records `cancelled`, while a still-running exact target is stopped and reobserved;
5. a confirmed nonzero process or container exit records lifecycle `failed`;
6. an exactly owned orphan is stopped and reobserved;
7. unknown runtime or durable effects are `INCONCLUSIVE` and never replayed;
8. conflicting durable effects are recovery `FAIL` and lifecycle `failed`;
9. replay requires an idempotent boundary and all effects confirmed absent; and
10. matching committed artifact and database effects continue without replay, recording a missing receipt before later work.

Every authorized decision records an `evidence.recorded` plan. Decisions that lack safe authority or ownership plan no append. Terminal plans may add exactly one of `run.cancelled`, `run.failed`, or `run.stale`; all retain a null run verdict.

## Frozen coverage

Twelve fixed synthetic cases cover safe replay, committed-effect continuation, ambiguous effects, confirmed cancellation, confirmed process failure, conflicting effects, authority drift, an exactly owned orphan, an active owner, an unowned orphan, a non-idempotent step, and unavailable authority. The mutation matrix proves fail-closed structure, authority, journal, boundary, lease, runtime, effect, decision, digest, terminal, and verdict behavior.

Full Draft 2020-12 validation uses the existing exact source-gated temporary evaluator. No new runtime dependency, network access during validation, secret, approval write, protected-volume access, or workflow execution is permitted.
