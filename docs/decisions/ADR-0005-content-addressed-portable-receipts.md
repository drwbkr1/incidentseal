# ADR-0005: Content-addressed portable receipts

- Status: accepted
- Date: 2026-08-09

## Context

IncidentSeal needs evidence that remains inspectable when PostgreSQL, Docker, the dashboard, and the original checkout are unavailable. A hash chain alone detects internal reordering but cannot authenticate an attacker-created replacement unless the complete receipt identity is bound outside the receipt.

## Decision

Use a closed RFC 8785 JSON receipt with raw-byte artifact digests, canonical event digests, canonical predecessor-link digests, and an external expected digest of the complete canonical receipt. Support distinct approved-workflow and platform-validation authority modes. Require a read-only verifier to report an internally valid but externally unbound receipt as `INCONCLUSIVE`, never `PASS`.

The v1 format is credential-free and content-addressed. It proves exact identity and integrity relative to an expected digest, not signer identity or global authenticity. Artifact paths are safe relative bundle paths, and verification needs no Docker, database, network, secret, approval access, or writes.

## Consequences

- Receipts can travel with artifacts and be checked offline.
- Reordering, truncation, corruption, state collapse, and path escape fail closed.
- The external expected receipt digest becomes required evidence for `PASS`.
- Whole-bundle replacement remains indistinguishable when no trusted expected digest exists, so the result is `INCONCLUSIVE`.
- Optional signatures can be added only through a future version and source/security gate; they are not required for the local-first v1 promise.
