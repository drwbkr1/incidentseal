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
- Repeatable 25-scenario, 50-execution fail-closed policy and custody evaluation.
- TTY-only, full-digest operator approval with fixed custody, atomic compare-and-swap replacement, exact superseded-record retention, post-write verification, and rollback.
- Portable Windows and POSIX checkout launchers validated from clean temporary custody, including native-Windows Python path conversion under Git Bash.
- Source-gated, exact-hash, temporary-only Draft 2020-12 meta-schema evaluation with four schemas, eight fixtures, and six locked Python wheel artifacts.
- Clean-copy CLI contract verification covering 38 tests, ten real-surface checks, and the 25-scenario/50-execution fail-closed matrix without Docker or real approval state.
- Public IS-0002 checkpoint verification from an exact credential-free GitHub clone, including project controls, Git object integrity, secret scanning, and full CLI-contract replay.
