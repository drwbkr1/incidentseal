# ADR-0006: Append-only event idempotency

- Status: accepted
- Date: 2026-08-09

## Context

Retries, crashes, and competing workers must not duplicate or rewrite release evidence. A random request token alone is not independently reproducible, while treating a repeated sequence as success can hide different bytes.

## Decision

Domain-separate a deterministic idempotency key over the complete canonical event digest, run ID, sequence, and prior link. Allocate event ID and timestamp once, then retry the exact record. Accept an existing key only when every canonical record byte matches; otherwise return a conflict. Independently enforce event ID and `(run_id, sequence)` uniqueness, contiguous predecessors, constant authority, lifecycle transitions, and terminal closure.

Represent staleness and supersession as terminal events on the original run. A successor receives a distinct run ID and never replaces the earlier chain.

## Consequences

- Exact retries are stable no-op replays.
- Changed retry bytes fail visibly instead of being folded into the earlier event.
- Event and link identities remain portable into receipt chains.
- The writer must retain the initially allocated event bytes across retries.
- Durable database implementation and crash reconciliation remain separate gates after this contract freezes.
