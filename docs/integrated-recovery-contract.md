# Integrated receipt and recovery matrix contract

- Contract ID: `INCIDENTSEAL-INTEGRATED-RECOVERY-001`
- Unit: `IS4-U06`
- Status: frozen candidate
- Runtime status: not started

## Claim

The integrated matrix may pass only when the host CLI repeats the complete fixed platform-validation sequence twice and preserves the exact receipt, lifecycle, recovery, restore, privilege, custody, and teardown semantics on both cycles. A collection of previously passing unit tests or source files is not integrated evidence.

The sequence has five isolated stages: portable receipt state verification; the real reliability probe with PostgreSQL plus the Python and Node runners; durable journal replay and stale/superseded streaming; fenced interruption recovery; and PostgreSQL logical backup into a different clean restore target. Each stage uses its already locked command and exact implementation. U06 does not introduce workflow execution, arbitrary commands, a shared privileged test container, or a new source of runtime authority.

## State separation

The closed twenty-case matrix keeps four verification verdicts distinct from seven lifecycle states. Exact and unbound receipt verification, missing and corrupt evidence, invalid identity, completed product PASS and FAIL, malformed input, database failure, host cancellation, stale and superseded journal streams, safe replay, ambiguous and conflicting recovery, stale recovery authority, concurrent recovery holders, clean restore, negative privileges, and teardown all have fixed expected channels and exits.

In particular, `cancelled`, `failed`, `stale`, and `superseded` do not gain a run verdict. An ambiguous recovery remains `INCONCLUSIVE`; conflicting effects remain `FAIL`; present corruption remains `FAIL`; invalid identity remains `INVALID`; and a completed product `FAIL` is not rewritten as lifecycle `failed`.

## Repeatability and identity

Both complete cycles must use the same exact image IDs, topology contract digest, semantic receipt outcomes, journal streams, recovery decisions, normalized backup TOC, restored state, and negative privileges. Every custom archive is hashed and bound by its own receipt. Raw archive bytes are not required to equal a different dump; the normalized TOC and restored schema, journal, result, and role digests must match. UUIDs, timestamps, invocation/container identities, raw archive digests, and derived receipt digests are excluded only from cross-cycle equality, never from their individual content-addressed receipts.

## Authority and custody

The host CLI alone owns Docker. The matrix accepts no manifest or arbitrary stage arguments. Containers receive no Docker socket, secret, broad host mount, privileged mode, or external network. The three protected evidence volumes are inspected before and after every stage and never mounted. All stage-specific containers, networks, volumes, archive directories, receipt bundles, and pending recovery custody must be removed before the next stage and again after each cycle. Temporary custody must be host-owned, disposable, and outside the repository and OneDrive.

## Non-claims

This contract starts no Docker container, PostgreSQL server, runner, recovery action, dump, or restore. It does not approve or execute a workflow manifest. It does not prove a dashboard, packaging, image redistribution, registry publication, downloaded release, or software release. The real composite implementation and exact public reproduction remain separate gates.
