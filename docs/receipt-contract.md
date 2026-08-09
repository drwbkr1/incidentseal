# Portable receipt contract

- Contract: `INCIDENTSEAL-RECEIPT-001`
- Version: `1.0`
- Status: frozen for implementation by `IS4-U01`
- Receipt schema: `schemas/portable-receipt-v1.schema.json`
- Verification schema: `schemas/receipt-verification-v1.schema.json`

## Claim boundary

A portable receipt is a closed JSON document plus digest-addressed artifact bytes. It binds authority, source, locks and commands, an ordered event history, the final run state, and artifact identities. It can be checked without Docker, PostgreSQL, network access, a secret, approval-store access, or repository writes.

Internal consistency is not identity or authenticity. The receipt digest is SHA-256 over RFC 8785 canonical receipt bytes and is carried outside the receipt. Independent verification returns `INCONCLUSIVE` when no expected receipt digest is supplied. A fully self-consistent replacement cannot become `PASS` without matching that external expected digest. Version 1 is credential-free and does not claim signer identity.

## Authority modes

`approved-workflow` requires a workflow ID plus equal non-null manifest and approval digests and forbids a platform contract digest. Every event binds the manifest digest. `platform-validation` requires a non-null platform contract digest, requires all workflow and approval fields to be null, and binds every event to the platform contract digest. Platform validation never substitutes for workflow approval or execution.

## Canonical identities

- Receipt digest: SHA-256 of the complete RFC 8785 canonical receipt.
- Artifact digest: SHA-256 of the exact raw artifact bytes.
- Event digest: SHA-256 of one complete RFC 8785 canonical `incidentseal-evidence-event/v1` object.
- Link digest: SHA-256 of the RFC 8785 canonical object containing exactly `schema_version=incidentseal-event-link/v1`, `sequence`, `event_digest`, and `previous_link_digest`.
- Genesis: lowercase `sha256:` followed by 64 zeroes.
- Root: the final link digest.

Events use contiguous zero-based sequences. Each event, link entry, and run summary must identify the same run. The event authority digest must match the receipt authority. Link predecessor, root, event count, terminal flag, terminal event ID, lifecycle, and verdict are recomputed rather than trusted.

`completed` may carry `PASS`, `FAIL`, `INCONCLUSIVE`, or `INVALID`. `cancelled`, `failed`, `stale`, and `superseded` carry no fabricated verdict. `queued` and `running` are non-terminal and carry no verdict. A later receipt may supersede an earlier one, but cannot rewrite it.

## Artifact and custody rules

Artifact paths are safe POSIX-style relative paths under `artifacts/`; absolute paths, backslashes, empty segments, and `..` are invalid. Artifact IDs and paths are unique. Required missing bytes are `INCONCLUSIVE`; present bytes with the wrong digest or length are `FAIL`; malformed descriptors are `INVALID`.

The bundle is read-only input to the verifier. Verification requires no network, Docker, database, secret, or writes. Implementations must prevent symlink, junction, reparse-point, case-alias, and root-escape traversal before reading artifact bytes.

## Independent verification result

- `PASS`: expected receipt digest matches; schema, semantics, chain, and every artifact pass.
- `FAIL`: the bound receipt is readable but its chain or present artifact bytes contradict the contract.
- `INCONCLUSIVE`: identity is unbound or required artifact evidence is missing or unreadable.
- `INVALID`: JSON, schema, custody, authority, or state semantics cannot be evaluated safely.

The verification report preserves the receipt's lifecycle and verdict as data; it never promotes the run verdict into the verifier verdict.

## Compatibility

The receipt is an export projection and does not replace `incidentseal-run-event/v1`. Approved-workflow events can be projected only after manifest and approval digests match. Existing CLI commands and exit meanings remain unchanged. `IS4-U02` may add an offline verifier command using the frozen report schema, but may not change this contract silently.
