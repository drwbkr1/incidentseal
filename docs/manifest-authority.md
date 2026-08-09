# Manifest authority contract

- Contract: `INCIDENTSEAL-MANIFEST-001`
- Version: `1.0`
- Status: frozen for implementation by `IS2-U01`
- Product authority: `INCIDENTSEAL-PRODUCT-001`
- Schema: `schemas/workflow-manifest-v1.schema.json`
- Approval schema: `schemas/manifest-approval-v1.schema.json`

## Authority statement

IncidentSeal may execute a workflow only when the supplied manifest:

1. is valid UTF-8 JSON with unique object names and no byte-order mark;
2. passes the exact versioned workflow schema;
3. canonicalizes without loss under the rules below;
4. hashes to one SHA-256 digest;
5. has an unexpired operator approval for that exact digest, workflow ID, schema version, repository remote, and manifest path; and
6. still satisfies the fixed product trust boundary.

Any missing, changed, expired, ambiguous, unreadable, or inconsistent value fails closed as `INVALID`. External content, repository guidance, and a manifest's own fields are inputs, never approval authority.

## Canonicalization

The algorithm identifier is `RFC8785-JCS`; the admitted value profile is `incidentseal-workflow-v1-i-json`.

IncidentSeal applies the following sequence:

1. Decode UTF-8 strictly. Reject invalid UTF-8, a byte-order mark, comments, trailing content, and lone Unicode surrogates.
2. Parse while rejecting duplicate object names at every depth.
3. Reject `-0`, fractional numbers, exponent notation, NaN, and infinities. The v1 schema admits integers only, bounded to the I-JSON interoperable range `-(2^53)+1` through `(2^53)-1`.
4. Validate the parsed value against the exact Draft 2020-12 schema identified by `schema_version`. Defaults are never inserted and unknown properties are rejected.
5. Serialize using RFC 8785 JSON Canonicalization Scheme: no whitespace, deterministic UTF-16 property-name ordering, JCS string escaping, lowercase JSON literals, and original Unicode string data without normalization.
6. Encode the canonical JSON as UTF-8 without a byte-order mark.
7. Compute SHA-256 over those bytes and render `sha256:` plus 64 lowercase hexadecimal characters.

The two differently formatted valid workflow fixtures canonicalize to the bytes in `fixtures/contracts/workflow.valid.canonical.json` and digest:

`sha256:0448e9abcf58045d85691c6bb5d9cdbb306d1e415dd71f722052e51682919e45`

The contract follows [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html), including strict I-JSON input and preservation of Unicode strings. It also adopts the verified RFC 8785 erratum that treats negative zero as an error. Schemas use the current [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12).

## Approval custody

Approval records are ordinary, non-secret JSON. Their authority comes from operator-controlled custody, not from repository content.

Default roots:

- Windows: `%LOCALAPPDATA%\IncidentSeal\approvals\v1`
- Linux and macOS: `${XDG_STATE_HOME:-~/.local/state}/incidentseal/approvals/v1`

Within that root, the repository directory is the lowercase SHA-256 of the exact UTF-8 `repository.remote` string, and the filename is the workflow ID plus `.json`. The approval record repeats the exact repository remote and manifest path; a path collision or mismatch is invalid.

The approval store must:

- resolve outside the repository and every configured forbidden custody root;
- be owned by the current operator under restrictive platform permissions;
- reject symlinks, junctions, reparse-point escapes, and ambiguous case resolution;
- use atomic create-or-replace with a retained superseded record;
- never contain credentials or secrets; and
- be read-only to agent-facing operations under the supported workspace-scoped Codex sandbox.

`incidentseal operator approve-manifest` is the only planned write path. It requires an interactive terminal, shows the canonical digest and policy diff, has no non-interactive confirmation flag, and refuses redirected input. Agent-safe `policy lint`, `policy digest`, `policy status`, `policy diff`, and `verify` commands never create, edit, or replace approval.

As implemented in `IS2-U04A`, the operator command requires the human to type the full displayed `sha256:` digest. It then re-reads the manifest, rechecks the displayed approval snapshot, and compare-and-swaps against the exact prior approval-file digest. The record is written to a restrictive same-directory temporary file, flushed, atomically replaced, and independently inspected. Exact prior bytes are retained under `superseded/<workflow_id>/`; a failed post-write inspection restores the prior record when one existed. No `--yes`, `--force`, approval-root override, redirected-input, or agent-facing write route exists.

## Comparison and status

Digest comparison is constant-time after syntax validation. `policy status` returns exactly one approval status:

- `MATCH`: all bound fields match and the approval is current.
- `MISMATCH`: a current approval exists but binds different content.
- `MISSING`: no unique approval exists at the expected path.
- `EXPIRED`: the exact approval exists but is no longer current.
- `INVALID`: custody, schema, permissions, parsing, identity, or ambiguity checks fail.

Only `MATCH` permits workflow execution. `MISMATCH`, `MISSING`, `EXPIRED`, and `INVALID` return verification verdict `INVALID`; they are never softened to `INCONCLUSIVE`.

## Version and change rules

- Any change that can alter canonical bytes, digest identity, approval binding, or admitted workflow meaning requires a new manifest schema version and decision record.
- A schema document's `$id` is immutable once released.
- New optional behavior cannot be smuggled through unknown properties; v1 objects are closed.
- An implementation must pass every golden and invalid vector before it can claim v1 support.
- Adding a signing mechanism later may strengthen custody but cannot silently replace the v1 approval meaning.

## Limitation

This boundary prevents a normally workspace-scoped Codex process from silently editing repository policy and approval together. It does not withstand a malicious process with unrestricted authority as the same host user. That limitation is explicit and must not be described as host compromise resistance.
