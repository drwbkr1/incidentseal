# ADR-0002: RFC 8785 canonical manifests and external operator approval

- Status: accepted
- Date: 2026-08-09
- Authority: `INCIDENTSEAL-PRODUCT-001`

## Context

IncidentSeal needs the same logical workflow to hash identically across formatting and property-order changes while rejecting ambiguous JSON. The approval must not live beside repository policy where Codex can silently edit both.

## Decision

Workflow v1 uses JSON Schema Draft 2020-12 and RFC 8785 JCS after strict duplicate-name, Unicode, numeric-domain, and schema checks. Floats, exponent notation, negative zero, unknown properties, and non-I-JSON integers are rejected by the v1 profile.

The operator approves one exact `sha256:` manifest digest in a restrictive local store outside repository custody. Agent-facing commands can lint, digest, inspect, compare, and verify but cannot create or replace approval. Only an interactive operator command may write the store.

## Consequences

- Formatting and object-property order do not change authority.
- Unicode content is preserved without normalization; visually similar but byte-distinct strings remain distinct policy.
- Closed schemas and integer-only numeric values make the first implementation smaller and cross-language testable.
- Approval portability requires explicit export/import work later; copying a repository does not copy authority.
- A same-user process with unrestricted host access remains outside the defended boundary.

## Rejected alternatives

- Hashing source bytes: harmless formatting changes would invalidate approval.
- Generic sorted-key JSON without a named standard: cross-language behavior would be underspecified.
- YAML: anchors, implicit typing, and parser variance add unnecessary authority ambiguity.
- Repository approval file: policy and approval could be changed together.
- A non-interactive `--yes` approval path: it would be callable by the agent whose work is being verified.
