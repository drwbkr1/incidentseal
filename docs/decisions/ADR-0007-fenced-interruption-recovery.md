# ADR-0007: Fenced interruption recovery

- Status: accepted
- Date: 2026-08-10

## Context

A host crash can leave a journal run nonterminal while its process, container, artifact, database row, or receipt is absent, committed, ambiguous, or conflicting. Blind retry can duplicate a consequential step; blind completion can fabricate a verification verdict; and treating a visible container as authority can race a still-active host.

## Decision

Bind every reconciliation to the exact nonterminal journal root, manifest authority, recovery boundary, runtime ownership, durable effects, and a fenced host lease. A different host may act only after the lease is expired and the runtime is bound to the exact expected project. Active, missing, invalid, ambiguous, or unowned custody defers without stopping a process or appending evidence.

Permit replay only when the boundary declares the step idempotent and every durable effect is confirmed absent. Continue without replay when the exact committed artifact and database effect agree. Unknown effects are `INCONCLUSIVE`; conflicting effects are recovery `FAIL` and close the run as lifecycle `failed` with a null run verdict. Confirmed cancellation, process failure, and authority drift append distinct `cancelled`, `failed`, and `stale` lifecycle events, also with a null run verdict.

## Consequences

- A recovery evaluation verdict describes the reconciliation evidence, never the interrupted run's product verdict.
- The host may stop only an exactly owned runtime after fencing excludes an active owner, then must reobserve before terminalizing or replaying.
- Non-idempotent or ambiguous work is not retried merely to make progress.
- Every permitted decision is content-addressed to its closed observation and can be replay-checked independently.
- Real Docker, PostgreSQL, process-stop, restart, and append behavior remain an implementation gate after this contract freezes.
