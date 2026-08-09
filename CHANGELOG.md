# Changelog

All notable IncidentSeal changes will be recorded here. The project follows Semantic Versioning once releasable software exists.

## Unreleased

### Added

- Approved product promise, trust boundary, operating authority, and non-goals.
- Portable project control plane and checkpoint `IS-0001` contract.
- Initial threat model, environment inventory, roadmap, evaluation plan, release matrix, and devlog.
- Versioned workflow-manifest, external-approval, CLI-envelope, and run-event schemas.
- RFC 8785 canonicalization vectors and dependency-free contract and mutation validators.
- Frozen host CLI and operator-owned manifest-authority contracts.
- Dependency-free manifest parser, v1 validator, RFC 8785 canonicalizer, and SHA-256 identity implementation.
- Machine-readable `policy lint` and `policy digest` commands with Windows and POSIX checkout launchers.
- Agent-safe repository guidance and 13 manifest/CLI contract tests.
- Read-only `policy status` and `policy diff` commands with distinct MATCH, MISMATCH, MISSING, EXPIRED, and INVALID states.
- External approval custody checks for repository/forbidden overlap, Windows ownership and ACLs, symlinks and reparse points, case ambiguity, and process-environment shadowing.
- Stable exit-77 rejection for agent-facing approval mutation attempts.
