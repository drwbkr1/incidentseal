# IncidentSeal devlog

## 2026-08-09 - Project authorization and custody

IncidentSeal was approved as a public, Apache-2.0, CLI-first developer verification product with a forensic-style local dashboard. The intended public repository is `drwbkr1/incidentseal`.

The original launch workspace was under OneDrive. The operator then declared OneDrive officially disconnected and prohibited its use. No project files had been created there. The canonical repository was created at `C:\Projects\Active\incidentseal` on an unborn `main` branch, and the OneDrive tree was recorded as forbidden custody.

Checkpoint `IS-0001` begins with documentation and dependency-free control records. Image pulls, package installation, Compose startup, and code dependencies remain gated until exact-source decisions exist.

## 2026-08-09 - Exact-image source gate

Public publisher, registry, license, OCI manifest, SLSA provenance, and SPDX SBOM metadata were reviewed for exact PostgreSQL 18.4 bookworm, Python 3.12.13 slim-bookworm, Node.js 24.19.0 bookworm-slim, and Dockerfile frontend 1.26.0 artifacts.

All 32 required source criteria passed. The decision authorizes only metadata retention, exact-digest recording, and a later non-executing pull for controlled inspection. It does not approve any image for runtime use or redistribution. No candidate image was pulled or run during this checkpoint.

## 2026-08-09 - First verified public checkpoint

The dependency-free baseline was committed as `b4cd51e466e8de89410b5ff58bf446a849a988d3`, pushed to the new public `drwbkr1/incidentseal` repository, and verified against remote `main`. The authenticated GitHub account, public visibility, default branch, origin URL, clean worktree, and local/remote commit equality all passed.

This closes `IS-0001` as a control and source-boundary checkpoint, not a software release. `IS-0002` now owns the manifest authority and stable CLI contract work.

## 2026-08-09 - Manifest and CLI machine-contract freeze

`IS2-U01` froze four repository-controlled JSON schemas for workflow manifests, external approvals, CLI envelopes, and run events. It also added valid and invalid workflow fixtures, RFC 8785 canonicalization vectors, a dependency-free supported-keyword schema linter, real fixture validation, and a mutation harness.

Python and Node.js independently produced the same golden SHA-256 manifest digest. Four fail-closed mutations were rejected: uncontrolled schema identity, an unknown exit code, canonical digest drift, and verdict/lifecycle-state drift. Approval records remain operator-owned and outside repository custody; no approval store or approved workflow digest exists yet.

This closes only the bounded contract-freeze unit. Full Draft 2020-12 meta-schema validation, the executable product CLI, and all Docker-backed product surfaces remain pending.

## 2026-08-09 - First real host CLI surface

`IS2-U02` implemented the first executable IncidentSeal surface without third-party packages. The checkout CLI now strictly parses and validates workflow v1 manifests, canonicalizes admitted I-JSON with RFC 8785 UTF-16 property ordering, and returns stable JSON envelopes for `policy lint` and `policy digest`.

Thirteen tests passed, including the real Windows launcher, schema-bound output, format-invariant golden digest, duplicate-key and number-domain rejection, fixed security-boundary enforcement, stable usage and I/O exits, and Unicode property ordering. A site-disabled Python probe produced the frozen digest without creating the default approval root. Pre-evidence review also closed Python bool/integer equality and untyped-enum ambiguity paths.

The CLI cannot yet inspect or write operator approval, execute workflows, access Docker, or make release claims. `IS2-U03` owns the external approval-store boundary next.

## 2026-08-09 - Read-only external approval boundary

`IS2-U03` added `policy status` and `policy diff` without adding an approval write path. The agent-facing CLI now discovers the fixed external store, validates restrictive custody and the closed approval record, compares the exact manifest digest and bound identity fields, and preserves MATCH, MISMATCH, MISSING, EXPIRED, and INVALID as distinct states. Direct agent-facing approval attempts return exit `77`.

Twenty-six tests passed. Positive approval cases used temporary custody only; the real/default approval root remained absent. Probes covered repository and forbidden-root overlap, unverified permissions, malformed approval, a real Windows junction, environment attempts to redirect Local AppData or shadow system tools, and the real launcher’s missing-approval and forbidden-mutation outputs.

The initial Windows temporary-custody run failed closed because this profile represents user access through `OWNER RIGHTS`. The final checker verifies the current owner before accepting that ACL form and still rejects any unexpected writer. No manifest is actually approved and workflow execution remains unavailable.

## 2026-08-09 - Repeated fail-closed evaluation

`IS2-U04` ran 25 deterministic scenarios twice for 50 total executions. Every scenario produced its expected distinct state or stable rejection: exact and harmlessly reordered manifests matched; semantic, repository, path, digest, and remote drift mismatched; expired, missing, malformed, future, unsafe-custody, case-ambiguous, junction, invalid-number, duplicate-key, BOM, root-override, and authority-mutation cases failed closed as specified.

Evaluation PASS does not turn negative product outcomes into PASS. The retained record preserves the observed MISMATCH, MISSING, EXPIRED, INVALID, exit `64`, and exit `77` results. No real approval was created.

The evaluation also exposed a roadmap omission: the frozen contract specifies an interactive operator-only writer, but no unit implemented it before clean-copy closure. `IS2-U04A` was inserted as a bounded temporary-custody implementation unit rather than weakening or silently skipping that gate.

## 2026-08-09 - Operator-only approval writer

`IS2-U04A` implemented the frozen human surface without exposing a machine write route. The command requires a real terminal and the full displayed digest, rechecks manifest and approval state after confirmation, compare-and-swaps the exact prior approval-file digest, writes through a restrictive temporary file, atomically replaces the active record, retains exact superseded bytes, and independently verifies MATCH.

Thirty-seven tests passed. Temporary-custody probes covered first approval, changed-manifest supersession, already-matching no-churn behavior, repository-contained custody denial, redirected input, absent `--yes`, machine-path exit `77`, manifest and approval races after the prompt, and restoration of the prior record after a forced final-verification failure.

The real/default approval root remained absent. No workflow is actually approved, and this implementation does not authorize Codex to invoke the operator command.

## 2026-08-09 - Clean-copy manifest and CLI contract

`IS2-U05` exposed and repaired two real Git Bash portability failures: the first launcher selected the Windows `python3` Store alias, and the next passed a POSIX source path to native Windows Python. The checkout launcher now probes for a working interpreter and converts its path and separator when it crosses that boundary. Thirty-eight tests pass.

The missing full Draft 2020-12 gate was closed without adding a product runtime dependency. Six evaluation wheels passed a 48-criterion source gate, were pinned to exact versions and SHA-256 digests, loaded only from temporary custody, and removed after validation. `Draft202012Validator` accepted four schemas and six valid fixtures and rejected the two schema-negative fixtures as expected.

An exact clean temporary clone of candidate `05bf4e2477b6626102b4103e94cb415533b18a95` then passed ten checks: clone cleanliness, all tests, Windows machine CLI behavior, external approval denial, Python site isolation, the Git Bash launcher, frozen contracts and mutations, full schema validation, 50 fail-closed executions, and final cleanliness. No Docker command ran and the real approval root remained absent. This closes the local contract exits only; public checkpoint verification remains separate.

## 2026-08-09 - Public IS-0002 checkpoint candidate

Remote `main` and the canonical checkout matched at `9cafb72f418edd3e3808c30fabda2e56bfee228a`. A fresh public clone replayed all ten clean-copy checks, the canonical probe, milestone and project-control validators, strict Git object verification, and a bounded credential and private-key pattern scan. A second clone with credential helpers, askpass, and terminal prompting disabled proved the public path did not require credentials.

The first cleanup encountered a read-only Git pack index; the exact verified system-temp tree remained retained until its file attributes were normalized and deletion succeeded. A receipt-formatting typo after the no-auth clone was also retained and did not alter the verified clone result. No Docker command ran, no image was acquired, and no real approval was created. IS-0003 opens with non-executing exact-image acquisition and inspection; runtime use remains gated.
