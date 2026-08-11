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

The final closure commit `e8b9823f63e3505f87490cbd87894705221a33cd` was pushed and revalidated from a second no-auth clone. Annotated marker `checkpoint-is-0002` was then pushed and independently resolved as tag object `630bc88f0860de56c51d0637260953429a6df172` peeling to that exact commit. A transient DNS push failure and two PowerShell peel-syntax verification failures are retained in the marker receipt; neither changed the checkpoint target.

## 2026-08-09 - Exact image execution gate

`IS3-U01` evaluated the actual linux/amd64 artifacts without starting any container. Exact Trivy 0.73.0 and its same-day database were independently source-gated and bootstrapped in temporary custody. Docker Scout 1.24.0 remained blocked because its executable was not Authenticode-signed. Cosign 3.1.3 also lacked Authenticode, so it did not run until the official Sigstore TUF root advanced from version 10 to 15 and the TUF artifact key independently verified the exact binary.

The initial Docker Official PostgreSQL, Node, and Python candidates failed the critical-vulnerability gate and remain preserved as superseded evidence. Lower-attack-surface replacements passed: Chainguard PostgreSQL 18.4 and Python 3.14.7 had zero detected vulnerabilities and retained signed image, SLSA, apko, and SPDX evidence; Google Distroless Node.js 24 retained exact keyless signatures plus five MEDIUM and seven LOW findings. Dockerfile frontend 1.26.0 scanner hits were reconciled against the publisher advisories and a non-running exact-binary inspection: the vulnerable daemon and OpenPGP package paths were absent from the frontend executable.

The first image lock now binds every index and linux/amd64 child digest, local image identity, SBOM, scan, provenance limitation, license boundary, and required runtime constraint. Controlled local execution is eligible only after the Compose contract is frozen. No database, runner, topology, workflow approval, image publication, or release claim has been made.

## 2026-08-09 - Closed topology contract

`IS3-U02` froze the topology before implementation. The host CLI—not a control container—is the sole Docker authority. Workflow execution requires exact approval `MATCH` with fixed rechecks, while manifest-free platform validation is limited to baked-in synthetic probes and topology-only claims. The contract binds copy-only offline builds, exact local image IDs, one internal network, no published ports, numeric non-root users, read-only roots, dropped capabilities, bounded staging outside repository custody, and preserved verdict and lifecycle states.

Dependency-free validators passed the two new schemas, the exact topology and image locks, and a normalized security projection. All 12 mutations failed closed, including container-owned Docker authority, manifest-gate bypass, repository input, external networking, root or privileged execution, repository mounting, build networking, proof-state collapse, a published PostgreSQL port, and retained capabilities. The existing four-schema machine-contract validator also remained PASS.

Two malformed read-only policy-status commands returned usage exit `64` and remain retained as `INVALID` attempts. The correct command returned approval `MISSING`, verdict `INVALID`, and exit `12`; no approval writer ran. No Docker build, Compose render, image, container, database, migration, or runner executed. `IS3-U03` owns static implementation next, and `IS3-U04` remains the first runtime unit.

## 2026-08-09 - Real static topology implementation

`IS3-U03` added the actual Compose model, three exact-frontend and exact-base copy-only Dockerfiles, an idempotent PostgreSQL migration, and standard-library-only Python and Node runners. The agent-safe `topology validate --mode platform-validation --json` command accepts no manifest, renders through the real Docker Compose CLI in generated custody, and returns a schema-valid topology-only PASS without reading approval or starting runtime resources.

The implementation lock binds every executable and rendered product input. The real render preserved all frozen commands, environments, dependencies, health checks, tmpfs settings, staged mounts, labels, numeric users, read-only roots, dropped capabilities, PID limits, internal networking, and no-pull behavior. Python and Node self-tests independently produced the same canonical input digest. Forty-one tests and 13 recomputed-lock or stale-lock implementation mutations passed.

The first full-model digest was rejected as unstable because generated staging paths changed between runs. The final model digest redacts only those generated source paths and repeated exactly. The first mutation-harness baseline also failed closed because its temporary copy omitted the locked runner fixture; the copy scope was corrected before any mutation result was accepted. No image built, and Docker shows no IncidentSeal container, network, volume, or derived image. `IS3-U04` owns the first runtime build and start.

## 2026-08-09 - First runtime startup failure

`IS3-U04` first reconciled a control-contract vocabulary defect: completed units used unsupported `completed` and `decision_value: high` values. The corrected contract validates and authorizes IS3-U04. The host CLI then built exact copy-only migration, Python, and Node images with build networking disabled and bound their local image IDs.

Two topology-only runtime attempts failed at PostgreSQL health. The first orchestrator revision cleaned the failed container before retaining logs, so that diagnostic-loss defect was fixed. The second attempt verified and reused the exact images, resumed the labeled volume, and captured the root cause: `mkdir: can't create directory '/var/lib/postgresql/data/pgdata': Permission denied`. Docker creates the new named volume root-owned, while the explicit security gate correctly forces PostgreSQL to `70:70`.

The project will not run PostgreSQL as root or use a privileged chown helper. Containers and network were removed; the failed labeled volume and three image IDs remain retained. The bounded remediation is a new exact-base, copy-only database image that establishes UID/GID 70 ownership at build time, followed by replay of every static and runtime gate.

## 2026-08-09 - Repeated topology-security runtime PASS

`IS3-U04` preserved the exact revision-1 contract, render, contract lock, failed implementation lock, three superseded derived image IDs, and failed labeled volume before remediation. Revision 2 added a fourth exact-base database build context. Its Dockerfile uses no `RUN`: it copies a fixed ownership marker as `70:70` into a new `/var/lib/postgresql/incidentseal-data` image path, which lets Docker seed that ownership into a new named volume while PostgreSQL still runs as `70:70` with a read-only root.

Static replay passed the dependency-free contract validator, all 14 semantic contract mutations, the real Compose implementation validator, and all 14 implementation mutations. The first implementation replay rejected a generated Python `__pycache__` byte in the exact build context before any build; that byte moved intact to recoverable non-OneDrive temp custody and remains an `INVALID` attempt.

The real host CLI then built four images with build network disabled, pull disabled, no cache, exact bases, and the locked Dockerfile frontend. The first revision-2 run reached PostgreSQL health and inspected the exact database, migration, Python, and Node image IDs. Fixed runner probes confirmed numeric users, read-only roots, no privilege, dropped capabilities, no-new-privileges, narrow staged mounts, denied external egress, no sensitive environment names, and no Docker or Podman endpoint. A second invocation verified and reused every exact image ID, resumed the labeled volume, repeated all probes, and passed. Both invocations removed every container and the internal network; the pass and failed volumes remain separately retained.

This is topology-security evidence only. The migration probe used `psql --version`, and the Python and Node commands were fixed isolation probes. `IS3-U05` must now execute the real migration and verify PostgreSQL schema, least privilege, persistence, restart, and teardown before database claims advance.

## 2026-08-09 - Database least-privilege FAIL

`IS3-U05` added a real `topology database-probe` machine surface with separate product and infrastructure semantics. A completed evidence run can return verdict `FAIL` and exit `10`; invalid custody, lock, or Docker state still fails closed as `INVALID`. The probe verifies the exact runtime lock, starts the retained database, executes the real migration twice, queries PostgreSQL identity and role attributes, compares the table schema and primary key, performs bounded DML, attempts forbidden DDL, restarts PostgreSQL, verifies the marker row, and tears down containers and network while retaining the labeled volume.

The first run returned the intended real-surface `FAIL`. PostgreSQL 18.4 health and identity, both migration runs, schema shape, bounded DML, restart persistence, and teardown passed. Least privilege did not: the Python and Node services are configured with the bootstrap role `incidentseal`, which is a login superuser with database and role creation, replication, and bypass-RLS authority. Its forbidden `CREATE TABLE` succeeded. The probe dropped that table before restart and retained the exact observation rather than accepting internal-network isolation as a substitute for database authorization.

U05 remains active. The bounded remediation is a new digest-bound topology revision with a bootstrap/migration role `incidentseal_admin`, an application role `incidentseal_runner`, explicit revocation of public schema creation, and only the schema/table privileges required by the runners. It must add no password, secret, external network, broad grant, root runtime, or privileged helper.

## 2026-08-09 - Least-privilege database surface PASS

The exact failing implementation and runtime locks were archived before remediation. Topology revision 3 now initializes PostgreSQL as `incidentseal_admin`, runs the one-shot migration with that bootstrap identity, and configures both language runners as `incidentseal_runner`. The idempotent migration creates or hardens the runner with every elevated role attribute disabled, revokes public database and schema creation, records `001-schema-v2`, grants connect and schema usage, and grants only `SELECT`, `INSERT`, and `UPDATE` on `verification_results`. It grants no access to the migration ledger.

Before any build, 16 semantic contract mutations and 15 real implementation mutations passed, including role-collapse and broad-grant rejections. A deliberate first-build test assumption about the temporarily absent runtime lock failed as `INVALID`; no image or container ran, and the corrected test preserves both the empty pre-build state and drift rejection.

The host CLI built four new exact images under contract digest `57ca5f96…`, reran the topology-security surface, and bound their IDs in runtime lock `0003`. Two real database probes then passed all 11 checks. PostgreSQL reported version number `180004`; migrations were repeatable; the admin and runner identities were exact; the runner had no superuser, database/role creation, replication, or bypass-RLS authority; bounded DML succeeded; DDL and migration-ledger reads failed; the marker survived restart; and teardown removed every container and network. The startup-failure, shared-superuser-failure, and revision-3 pass volumes remain separately retained.

This closes only the database exit. `IS3-U06` must execute the real Python application command against staged input and the verified runner role; U05's direct `psql` DML is not Python-runner proof.

## 2026-08-09 - Real Python runner surface PASS

`IS3-U06` added a host-owned `topology python-probe` command and fixed valid and extra-field staged requests. The probe reuses the exact revision-3 image IDs and database volume, runs the real migration, invokes the Python image's shipped default command, independently computes the expected canonical receipt, verifies the exact single output file and PostgreSQL row, inspects runtime isolation, and repeats the application with malformed input. Invalid input must fail with no result and no database row.

The first real invocation returned product `FAIL` at exit `10` even though the application exited zero and every product and security check passed: Docker Compose emitted transport status on stderr, and the host probe treated any stderr as application failure. Suppressing progress preserved the second `FAIL`; a bounded diagnostic showed the remaining bytes were an orphan warning because the inspected custom-named migration container remained until final teardown. Both exact failures and their locks are retained.

The remediation did not relax the empty application-stream gate. It removes each inspected completed one-shot container before invoking the next Compose service and retains the final fail-safe teardown. Forty-seven tests, the real static implementation validator, and all 15 implementation mutations passed. Two identical real Python invocations then passed with stable result, database, and negative-output digests. The Python container ran as `65532:65532` with read-only root, all capabilities dropped, no-new-privileges, read-only input, narrow output, internal-only networking, no sensitive environment names, and no Docker endpoint. Every container and network was removed; the exact database volume remains retained.

This closes only `EXIT-PYTHON-RUNNER`. `IS3-U07` owns the real Node command and cross-runner consistency; no workflow, recovery, dashboard, clean-clone, redistribution, or release claim advances from U06.

## 2026-08-09 - Real Node runner and cross-runner PASS

`IS3-U07` archived the exact U06 implementation and runtime locks before adding the host-owned `topology node-probe` command. The probe reuses the exact revision-3 image IDs and database volume, runs the real migration, executes the Node image's shipped default command, independently computes the expected receipt, verifies the exact single output and Node database row, and compares both language rows for the same request.

The retained Python and new Node rows share canonical input digest `47963fda...f176b` while their language-bound result digests remain intentionally distinct. The fixed malformed request exited nonzero with no result and no Node row. The Node container ran as `65532:65532` with a read-only root, all capabilities dropped, no-new-privileges, read-only input, narrow output, internal-only networking, no sensitive environment names, and no Docker endpoint.

Forty-eight tests, the real static implementation validator, and all 15 implementation mutations passed. Two identical real Node invocations produced stable result, database, cross-runner, negative-output, and teardown evidence. Every container and network was removed after each run; the exact database volume remains retained.

This closes only `EXIT-NODE-RUNNER`. `IS3-U08` owns clean-start, retained-state resume, forced failure, cancellation, restart, orphan detection, teardown, and clean-clone topology behavior. No workflow, dashboard, receipt-recovery, redistribution, or release claim advances from U07.

## 2026-08-09 - Disposable reliability candidate

`IS3-U08` first archived the exact U07 locks and froze three retained evidence volumes as immutable runtime custody. A separate fixed Compose project may create and remove only its own non-sensitive disposable volume; it cannot mount, rename, relabel, or delete the retained startup-FAIL, least-privilege-FAIL, or revision-3 PASS volumes.

Two canonical-checkout reliability runs passed. Each fresh-bootstrapped PostgreSQL, applied the migration, executed both real runners, verified exact rows, detected a tampered temporary receipt as verification `FAIL`, retained malformed requests as `INVALID`, observed a valid runner against a stopped database as lifecycle `failed`, recovered after restart, host-cancelled a bounded sleeping query with process and container exit `137`, verified three rows through another restart, detected no one-shot orphan, and removed the disposable container, network, and volume. All three retained volumes remained present.

The U08 unit remains open. This candidate must be committed and pushed before an exact credential-free public clone can replay the same control, static, test, and real reliability surfaces.

## 2026-08-09 - Credential-free reliability replay

The in-progress U08 candidate was committed and pushed as `71dca263a1e696c454b3e48fcbb394cd04d802a0`, tree `44b0626b8cb33235c3c4482cc04ffc4ced0d71b3`. An exact public clone with Git credential helpers, askpass, and terminal prompting disabled passed project-control and milestone validation, 50 tests, the static implementation validator, all 15 implementation mutations, and real reliability invocation `62db3873-08f7-41e3-b970-4ffc4f6c62f8`.

The public clone repeated all 14 real checks and the same stable digests for completed verification `FAIL`, malformed request `INVALID`, database-outage lifecycle `failed`, and host-stop lifecycle `cancelled` at process/container exit `137`. It removed the disposable container, network, and volume and preserved every protected evidence volume.

Two harness attempts remain `INVALID`: one combined command was blocked before execution, and one split attempt let PowerShell treat unittest's normal stderr summary as a terminating error before the real probe ran. The corrected split harness passed. A later local command-policy gate denied recursive removal of the clean non-OneDrive temp clone, so that non-canonical diagnostic custody remains explicit rather than being misreported as cleaned.

This closes `EXIT-REAL-TOPOLOGY`, not IS-0003 publication. `IS3-U09` must bind the closure commit, verify it from public custody, create and push `checkpoint-is-0003`, and independently verify the marker before the milestone closes.

## 2026-08-09 - Public IS-0003 checkpoint

Exact closure commit `a0c05070dd1d147aecae6b4ed686440414a3aa27`, tree `67c05a1090aef5f301525dbba6786c1050635629`, was cloned from public GitHub with credential helpers, askpass, and terminal prompting disabled. The clean clone passed project controls, the milestone contract, 50 tests, machine contracts and four mutations, topology contracts and 16 mutations, implementation validation and 15 mutations, Git object integrity, high-confidence secret scanning, and real reliability invocation `73711f49-91a7-4edc-ac09-99a59cab2e3d` with all 14 checks.

Annotated tag `checkpoint-is-0003` was created at that exact commit, pushed, and fetched independently in the credential-free clone. Local and public tag object `28eea260147265e7dd0328dcd072e134586a2ff0` both peel to `a0c05070dd1d147aecae6b4ed686440414a3aa27`. The first remote tag-absence query remains `INVALID` because its peeled ref was not quoted for PowerShell; the quoted retry established absence before tag creation.

No IncidentSeal container or network remains, and all three protected evidence volumes remain. The non-canonical U08 and U09 temp clones remain in non-OneDrive local temp custody because local command policy denied recursive cleanup; neither is canonical or a release artifact.

IS-0003 is complete, but IncidentSeal remains `0.0.0` and unreleased. The next bounded milestone is evidence and recovery: append-only portable receipts, idempotency, durable cancellation/failure records, crash recovery, verified backup/restore, and independent offline verification.

## 2026-08-09 - IS-0004 evidence-and-recovery milestone opened

After the IS-0003 closure receipts were committed and remote `main` independently matched `79c5b71930023b4c63f42ff6269d3ee95fed5b0b`, the project advanced to `IS-0004`. The immutable `checkpoint-is-0003` marker remains at `a0c05070dd1d147aecae6b4ed686440414a3aa27`; post-marker records do not move it.

The real agent-safe `policy status` surface returned approval `MISSING`, verdict `INVALID`, and exit `12` for the valid minimal fixture. Workflow execution therefore remains unavailable. IS4-U01 is contract-only and may not start Docker or write runtime evidence. Later units are ordered through portable receipts and independent offline verification, idempotent event history, interruption recovery, clean PostgreSQL restore, integrated real-surface evaluation, and a credential-free public checkpoint.

The first combined post-push verification wrapper was `INVALID` after the push had already succeeded because PowerShell rejected an inline conditional expression. Separate read-only checks then proved local and remote `main` both at `79c5b719...`, the annotated marker unchanged, and the canonical worktree clean.

## 2026-08-09 - Portable receipt contract frozen

`IS4-U01` froze a closed portable receipt and independent-verification contract before implementation. Receipt identity is SHA-256 over RFC 8785 canonical bytes; artifact identity hashes exact raw bytes; each event hashes its canonical evidence-event projection; and each link hashes a canonical predecessor object. An external expected receipt digest is required for verification `PASS`, so an internally consistent replacement without that binding remains `INCONCLUSIVE` rather than being misrepresented as authentic.

The contract distinguishes `approved-workflow` authority from built-in `platform-validation`; the latter cannot carry a workflow or approval digest and never substitutes for workflow execution. Run lifecycle and verification verdict remain independent. Artifact paths are safe relative POSIX paths under `artifacts/`, and the future verifier must require no Docker, PostgreSQL, network, secret, approval access, or writes.

The dependency-free validator reproduced receipt digest `7293ac40...`, three event digests, chain root `8aff86cd...`, and one raw artifact digest. All 14 mutations returned their expected stable rejection. The saved source gate released the same six exact evaluation-only wheels into system-temp custody; their hashes matched, and full Draft 2020-12 validation passed six schemas and eleven fixtures. The base missing-package attempt was `INVALID`. A combined cleanup wrapper and a later separately bounded cleanup were both policy-rejected, so the exact non-OneDrive temp tree remains explicitly retained. The original machine contract and all 50 tests passed; Docker runtime did not start.

## 2026-08-09 - Atomic receipt implementation candidate

`IS4-U02` now has locked `receipt materialize` and `receipt verify` commands. The writer validates source receipt and artifact bytes, writes and flushes a same-filesystem staging bundle, atomically renames it to its SHA-256 address, and verifies existing content before idempotent reuse. It rejects repository and OneDrive output plus symlink, junction, reparse, and path-escape custody. The verifier is read-only and preserves exact `PASS`, unbound `INCONCLUSIVE`, mismatched identity `INVALID`, present corruption `FAIL`, and missing required evidence `INCONCLUSIVE` outcomes.

Fifty-four tests pass. Real Windows launcher materialization and exact/unbound verification passed in disposable custody, removed that custody, and left Docker and approval state unchanged. A separate locked implementation validator repeated the real commands. U02 remains in progress until implementation mutations and credential-free clean-copy replay pass; no portable-receipt implementation exit is claimed yet.

## 2026-08-09 - Receipt implementation mutations PASS

The active implementation lock now binds the six executable receipt-path files, and every receipt command checks those exact bytes before reading or writing receipt custody. The real launcher passed first-write and idempotent materialization, exact bound verification, unbound `INCONCLUSIVE`, mismatched identity `INVALID`, corrupt evidence `FAIL`, missing required evidence `INCONCLUSIVE`, invalid stored event digest and run-summary rejection, corrupt-source rejection, repository-output denial, and no-write verification. Temporary custody was removed; Docker container history and approval state were unchanged.

All twelve implementation mutations failed closed. The mutation matrix covers stale runtime source, verdict promotion, artifact-state promotion, event and summary check bypasses, repository-custody bypass, idempotency drift, corrupt-source acceptance, and both runtime-lock entry bypasses. The evaluator specifically requires runtime drift to be rejected before materialization creates any output custody.

Four attempts remain `INVALID`. The first expanded evaluator read state-separated errors from the wrong CLI array. The first mutation pass exposed the missing pre-write custody assertion. A direct meta-validator invocation correctly lacked the evaluation-only package in base Python and was replaced by the existing source-gated temporary evaluator. Finally, the wider suite rejected the intentional new receipt CLI against the prior topology implementation lock; the exact prior topology implementation and runtime locks were archived before the active locks were rebound, after which all fifteen topology implementation mutations passed without starting a container.

U02 remains open. Its exact mutation-passing source must be committed, pushed, and replayed from credential-free public clean custody before `EXIT-PORTABLE-RECEIPTS` or `EXIT-INDEPENDENT-VERIFIER` can pass.

## 2026-08-09 - Credential-free portable receipt replay

The mutation-passing implementation was committed and pushed, then the reusable clean-copy workflow was expanded to cover the current six-schema receipt contract, topology regression locks, real receipt state matrix, and both receipt mutation suites. Exact public commit `3cdbf132225cf48e85a8413574c7e8e1d060aca0`, tree `c62c5cc29ff72d36ddd9acc31a685c0712d996aa`, was cloned from GitHub with credential helpers, interactive credential flow, and terminal prompts disabled.

The public clone passed project and IS-0004 controls plus thirteen reusable clean-copy checks: 54 tests, four machine mutations, sixteen topology-contract mutations, fifteen topology-implementation mutations, fourteen receipt-contract mutations, twelve receipt-implementation mutations, six-schema/eleven-fixture source-gated meta-validation, and fifty policy trials. Strict Git object verification and a bounded four-pattern high-confidence secret scan passed. The real policy surface remained approval `MISSING` at exit `12`.

No workflow ran. Receipt verification used no Docker, database, network, secret, approval write, or repository receipt output. Docker containers, networks, and volumes matched before and after, all three protected volumes remained, the public worktree stayed clean, and Python removed the public-clone temporary custody. A first wrapper with an incorrect abbreviated commit prefix stopped before cloning and remains `INVALID`.

This closes `EXIT-PORTABLE-RECEIPTS` and `EXIT-INDEPENDENT-VERIFIER`. It does not close durable event history or recovery. `IS4-U03` is next to freeze and implement append-only event idempotency, duplicate replay, stale, and superseded transitions.

## 2026-08-09 - Append-only event journal contract frozen

`IS4-U03` began from public closure commit `f63e8aff...` with canonical and remote `main` equal, approval `MISSING`, no IncidentSeal container or network, and all three protected evidence volumes present. The new journal contract wraps the frozen run-event schema in an immutable record with exact event, predecessor, link, and domain-separated idempotency identities.

The host allocates event ID and timestamp once and retries the exact same record. Exact replay returns `replayed` without increasing count or changing root. Different bytes under an idempotency key, event ID, or run sequence fail as a conflict. Sequences begin with queued at genesis, remain contiguous, keep one authority digest, follow explicit lifecycle transitions, and cannot append after a terminal event. Stale and superseded outcomes are terminal events on the original run and never rewrite it.

## 2026-08-10 - Durable journal candidate passes real PostgreSQL

The host-only implementation now stores exact canonical record and event bytes in PostgreSQL. A fixed-search-path security-definer function serializes each run, accepts only exact replay as a no-op, and rejects conflicting idempotency keys, event IDs, run sequences, terminal appends, and authority drift. Update, delete, and truncate triggers keep retained rows immutable. The application runner has no journal-table access, and there is no agent-facing append command.

The first implementation mutation run was `INVALID`: broadening the append function search path slipped past a validator that found the safe text on a different function. The corrected validator binds the append declaration itself and all eight implementation mutations now fail closed. The first real probe was also `INVALID` because its authority test reused an occupied sequence and correctly reached the conflict gate first. A distinct two-event test run corrected the evaluator without weakening either gate.

The corrected fixed disposable probe passed 14 checks. It inserted all seven frozen completed/stale/superseded records, replayed three without new rows, exercised the real canonical JSONL CLI at exits 0, 22, and 23, denied table mutation and runner reads, and reproduced the completed stream after PostgreSQL restart. Cleanup removed every disposable resource and the exact identities of all three protected volumes remained unchanged. No approval was read or written and no workflow ran. The candidate is ready for commit and credential-free public replay; U03 is not yet closed.

Three vectors retain seven records for completed `PASS`, stale authority, and superseded attempt histories under stable roots. Three exact replays were no-ops. All sixteen bounded mutations returned the expected schema, identity, link, sequence, conflict, state, terminal, or authority error. The dependency-free contract validator passed, and the existing six exact source-gated evaluation wheels validated three Draft 2020-12 schemas and three fixtures from removed temporary custody. No runtime or workflow executed.

U03 remains active. The next bounded improvement is the transactional durable store and read-only ordered stream in a disposable PostgreSQL project; protected volumes remain out of scope.

## 2026-08-10 - Durable event journal closes from public custody

Candidate commit `4b4cd189d3a787f2871736731b9aad1c87da344a`, tree `19f2c3194bcb1423e312f5307f8c753a5a350c6a`, was pushed and cloned from GitHub with terminal prompts and credential helpers disabled. The clean public copy passed project and milestone controls, 62 tests, every machine/topology/receipt/journal validator and mutation suite, exact-wheel schema validation, 50 fail-closed policy trials, strict Git object integrity, and a bounded zero-hit high-confidence secret scan.

Real public journal invocation `ea22b801-0c3a-43d4-87c2-1527c889e564` repeated all 14 PostgreSQL gates and the exact completed, stale, and superseded JSONL digests at exits `0`, `22`, and `23`. Seven frozen rows and three exact no-op replays remained stable through restart; conflict, terminal, authority, mutation, and runner-privilege probes failed closed. Disposable Docker custody was removed, no container or network remains, and all three protected volume identities remain exact.

Approval inspection invocation `49479a50-bb3b-4dc7-87a7-7647419f29b2` remained `MISSING`, verdict `INVALID`, exit `12`. No approval was written and no workflow ran. Local command policy denied the final exact temporary-clone deletion wrapper before it executed, so that clean, non-canonical clone remains retained outside OneDrive and outside runtime custody; the attempt remains `INVALID` instead of being hidden or circumvented.

The first final read-only binding-check wrapper contained an empty PowerShell pipe and failed parsing before it read any binding. That attempt remains `INVALID`; the corrected wrapper matched all nine exact file bindings without writing or starting runtime.

`EXIT-IDEMPOTENT-EVENTS` now passes and `IS4-U03` is complete. `IS4-U04` is next to freeze and prove host-crash, cancellation, failed-run, resume, and orphan-reconciliation boundaries without collapsing lifecycle and verification verdicts.

## 2026-08-10 - Fenced interruption-recovery contract candidate

The cycle began from clean public/local commit `c852b06d...`, approval `MISSING`, no IncidentSeal container or network, and exactly the three protected volumes. Project and milestone controls agreed that `IS4-U04` was the only authorized-ready unit.

The candidate contract binds a closed nonterminal journal snapshot, manifest authority, step boundary, replay policy, fenced host lease, runtime ownership and exit state, and artifact/database/receipt effects into content-addressed recovery observations and decisions. Only an expired lease plus exact ownership may stop a runtime. Stopping is intermediate and requires reobservation. Replay requires an idempotent boundary and all effects absent; matching committed effects continue without replay; unknown evidence defers `INCONCLUSIVE`; conflicting effects are recovery `FAIL`; confirmed cancellation, process failure, and authority drift retain distinct lifecycle outcomes. Every run verdict remains null.

Twelve frozen cases, 20 fail-closed mutations, 68 repository tests, and two full Draft 2020-12 schemas across 26 fixtures pass. The passing meta-validation used the six previously source-gated exact wheels from retained non-OneDrive custody, reverified every SHA-256, used no network, installed only into disposable evaluation custody, and removed that copy. Seven attempts remain `INVALID`: the focused test import, DNS-dependent meta wrapper, Windows wildcard search, PowerShell unittest-stderr wrapper, unsupported CLI help invocation, PowerShell CLI-search quoting, and incorrect policy fixture path. Corrected paths pass without erasing them.

No Docker runtime, PostgreSQL, process stop, journal append, protected-volume access, approval write, or workflow execution occurred. The candidate must be committed and replayed from credential-free public custody before the contract stage closes; the real host recovery surface remains a separate bounded implementation gate.

The exact candidate was committed and pushed as `5fa894cb57c8c69fab85946827be241f522acb87`, tree `0958adae2ea4d2019653058358f4ac806ea2f155`. A fresh public clone with credential helpers and prompts disabled reproduced 68 tests, all 16 earlier static validator and mutation suites, all 12 recovery cases, all 20 recovery mutations, two full schemas across 26 fixtures from six rehashed source-gated wheels, strict Git integrity, and a zero-hit four-pattern secret scan.

Public policy status remained `MISSING` / `INVALID` at exit `12` under invocation `520df331-dbf8-4350-b781-3194ed091b2e`; no approval store appeared and no workflow ran. Docker remained at zero IncidentSeal containers, zero networks, and the same three protected volume identities. Local command policy rejected the exact clone cleanup wrapper before execution, so that clean noncanonical clone remains explicitly retained outside OneDrive and runtime custody. The contract replay gate passes; the real host-only recovery implementation remains the next bounded stage.

The first closure push wrapper contained an invalid inline PowerShell ancestry expression and failed parsing before Git executed. The corrected separated command pushed closure commit `b483c581bbccd45a33707e085f30317aad8cf178`, confirmed local and remote equality, confirmed candidate ancestry, and left the canonical worktree clean. The parser attempt remains `INVALID`.

## 2026-08-10 - Host-only fenced recovery candidate passes locally

The implementation adds a separate recovery lease to PostgreSQL while leaving the workflow lease truthful and independently expired. Per-run transaction locks, row locks, exact workflow tokens, monotonically increasing recovery tokens, bounded expiry, same-holder replay, and runner denial prevent competing or application-owned recovery. The host persists the exact observation, decision, evidence record, and terminal record atomically outside the repository before any process mutation. A stop requires exact container identity, locked image, contract/run/workflow labels, numeric user, read-only root, no network, no mounts, all capabilities dropped, and Docker's canonical `no-new-privileges` setting; every stop forces reobservation.

Seventy-four repository tests and all 17 recovery implementation mutations pass. Passing real invocation `e65374af-535f-47df-b8f2-40b5b9459885` completed all 15 fixed synthetic checks: active-owner and unowned-runtime no-mutation deferral, exact orphan stop/reobserve/replay, running cancellation, retained exit-42 failure, authority stale, conflicting versus ambiguous effects, crash-after-evidence resume under a new holder, concurrent-holder exclusion, runner-table denial, restart persistence, null non-completed run verdicts, exact protected-volume identity, and complete disposable teardown. No approval was accessed or written and no workflow ran.

Fourteen implementation-cycle attempts remain `INVALID`. Validator and mutation harnesses were tightened where the new recovery functions exposed global-text assumptions; two read-only policy calls used the wrong invocation; the first real recovery probe failed closed because Docker Desktop reports standalone `SecurityOpt` as `no-new-privileges` rather than `no-new-privileges:true`; and the first final-gate wrapper used Bash here-string syntax that PowerShell rejected before validation. A separate diagnostic container with no network or mounts confirmed the daemon representation and was removed. The corrected exact check has its own fail-closed mutation, and the native-PowerShell final gate passed. Credential-free public implementation replay remains before U04 can close.

## 2026-08-10 - Fenced recovery closes from public custody

Candidate commit `7c6278f6a906bd665279fd1bc9068dc4aac2776a`, tree `58a4b2bc766ba03ae2a289e55ab12233e884e6ec`, was pushed and cloned from GitHub with prompts and credential helpers disabled. The exact public `main` branch passed project control, all 74 tests, every machine/topology/receipt/journal/recovery validator and mutation suite, and full recovery schema validation against two schemas and 26 fixtures using six rehashed retained source-gated wheels without network. Strict Git object integrity and a bounded four-pattern secret scan passed with zero matches.

Public recovery invocation `84ceb376-b2bb-43e7-a93f-46129c3472f0` repeated all 15 real checks and the same four exact image identities. Active-owner and unowned cases caused no mutation; the exact orphan stop forced reobservation and one replay; cancelled, failed, stale, ambiguous, and conflicting states retained their exits; crash-after-evidence resumed exactly once; competing recovery was excluded; runner access was denied; PostgreSQL restart preserved streams; and no non-completed event had a verdict. Teardown removed the disposable containers, network, volume, and state custody while the three protected volume identities remained exact.

Policy status stayed `MISSING` / `INVALID` at exit `12` before and after under invocations `7bd1d1d2-29fd-48d2-8a26-b45e8214cef9` and `0d1b4193-8dd0-4804-a484-6580c9f7520e`. No approval was written and no workflow ran. Three new non-product attempts remain `INVALID`: an unquoted PowerShell tree revision, a detached-HEAD project-probe assumption, and a false-positive static wrapper that used PowerShell's reserved `Args` variable. The corrected public replay is clean. The noncanonical clone remains retained outside OneDrive and runtime custody.

`EXIT-INTERRUPTION-RECOVERY` now passes, `IS4-U04` is complete, and `IS4-U05` is ready to freeze and prove PostgreSQL logical backup and clean restore.

## 2026-08-10 - Logical backup and clean-restore contract candidate

U05 began from clean public/local closure `1a8e4b94...`, approval `MISSING`, zero IncidentSeal containers and networks, and exactly the three protected volumes. Current PostgreSQL 18 guidance confirms that `pg_dump` custom archives are portable and inspectable with `pg_restore`, while roles are cluster-global and absent from a single-database dump. The contract therefore refuses to treat dump creation as PASS and never treats restored role SQL as authority.

The closed receipt binds the exact custom archive and normalized TOC, the source database and migration image IDs, a fixed disposable source with writes blocked, fixed no-owner/no-privilege dump arguments, a different clean target, error-stopping single-transaction restore arguments, and a post-restore exact migration. It then requires schema, ordered journal, verification-result, and measured two-role equivalence; denied runner schema creation, DDL, migration-ledger reads, journal reads, and recovery-fence reads; protected-volume identity; and complete teardown.

The golden receipt is RFC 8785 content-addressed at `2722f1a8...`. All 18 semantic mutations fail closed at their intended schema, authority, custody, source, archive, snapshot, command, durability, role, equivalence, privilege, or identity gate. One Draft 2020-12 schema and two fixtures passed from six rehashed retained source-gated wheels without network, and temporary evaluation custody was removed. All 80 repository tests pass. The first focused test omitted the standard `src` bootstrap and remains `INVALID`; it executed no runtime. No dump, restore, Docker, PostgreSQL, approval write, protected-volume access, or workflow execution occurred. Public contract replay is next.

## 2026-08-10 - Backup and clean-restore contract closes from public custody

Candidate commit `30513b70a9c7a2e283e4643232fa5c8b13f650c2`, tree `faebf8d3d6635598977f9b7b5ccafc81bfd31fea`, was cloned from GitHub with terminal prompts and credential helpers disabled. The exact clean public copy passed project control, all 80 tests, the 18 backup/restore mutations, every machine/topology/receipt/journal/recovery validator and mutation suite, and the one-schema/two-fixture backup meta-validation using six rehashed source-gated wheels without network. Temporary evaluation custody was removed.

Strict Git object integrity passed with the three intentionally dangling annotated checkpoint tags still present. Four bounded high-confidence secret patterns returned zero matches. Policy invocation `62bccc79-23b0-40b9-8e53-2b9c4bf4a1de` returned approval `MISSING`, verdict `INVALID`, exit `12`; no approval was written and no workflow ran. Docker remained at zero IncidentSeal containers, zero IncidentSeal networks, and exactly the same three protected volume identities. No PostgreSQL runtime started, no dump was created, and no restore was attempted.

Five resumed evaluator attempts remain separately `INVALID`: one PowerShell wrapper reinterpreted unittest stderr, three unsupported read-only help invocations exercised the frozen usage error, and one read-only digest wrapper used incompatible PowerShell syntax. The corrected supported commands passed. The clean noncanonical public clone remains outside OneDrive and runtime custody; no cleanup attempt was made.

The contract replay gate now passes, but `EXIT-BACKUP-RESTORE` does not. U05 remains active. The next bounded improvement is the fixed host-owned disposable implementation: create and hash the exact custom archive and normalized TOC, restore into a different clean volume, rerun the locked migration for role hardening, verify state and all five negative privileges after restart, prove protected-volume identity and teardown, then reproduce the implementation from credential-free public custody.

## 2026-08-10 - Host-only backup and clean-restore candidate passes locally

The fixed `topology backup-restore-probe --mode platform-validation --json` command now owns two named disposable Compose projects and volumes from the host. It freezes three synthetic journal runs and two verification results behind a live PostgreSQL table lock, proves a runner write times out, creates an exact custom-format no-owner/no-privilege dump, fsyncs and hashes it on the host, and lists it in a no-network container. A normalized TOC gate rejects cluster-global roles, databases, tablespaces, owners, and ACLs before any restore authority is admitted.

The archive is restored into a different clean volume with error-stop, single-transaction, no-owner, and no-privilege arguments. The locked migration then idempotently rebuilds and hardens the cluster-global roles. Exact schema, ordered journal, verification-result, and role digests must match; the runner must still be denied schema creation, DDL, migration-ledger reads, journal reads, and recovery-fence reads after a target restart. The host verifies all three protected volume identities before and after and removes the disposable projects, volumes, archive directory, and containers. Containers receive no Docker socket, secrets, external network, privileged mode, or broad host mounts.

Final-lock invocation `e38826ae-8d6f-4d24-a033-bd6a298d0f8e` passed all ten checks. The durable archive was `52800` bytes at `sha256:8b5a3ac0e886c22cba2353855a41238703431b6830c74fc7a7c20a2857d2f5e8`; the 20-entry normalized TOC was `sha256:122f3380f5fff86e3779c709c50070e67f0e08380efd317a5738d0e320615890`. Eighty-six tests, 21 implementation mutations, and every prior cross-surface suite pass. Approval remained `MISSING`, no workflow ran, no protected volume was mounted, and teardown left zero IncidentSeal containers or networks and exactly the three protected volumes.

Seven attempts remain `INVALID`: the first Windows archive fsync opened a read-only descriptor, two post-restore migration classifiers were too broad, the bootstrap admin role retained `CREATEDB`, their direct traceback reproductions confirmed the exact defects, and one PowerShell evidence wrapper failed parsing before execution. The corrected migration image is exact-locked at `sha256:d159285a8988fa13f510d7dc77bdeee195181d6b75dc8ef959d1f182d9013310`; its prior image remains under a history tag. Passing calibration invocation `523ca659-8b99-4b55-8255-e68e2f4efec9` is retained as `superseded` after its evidence became an input to the final runtime lock. U05 remains active until the exact committed candidate reproduces from credential-free public custody.

## 2026-08-10 - Backup and clean restore closes from public custody

Implementation candidate commit `f8c2526389ea73c157f535c2d6651ba86b8169ac`, tree `02bf08a09895b27db42bbbedab238b9e7a3679ad`, was pushed and cloned from GitHub with prompts and credential helpers disabled. The exact clean `main` branch passed project control, all 86 tests, every machine/topology/receipt/journal/recovery/backup validator and mutation suite, the 25-scenario/50-execution fail-closed authority matrix, and one backup schema across two fixtures from six rehashed source-gated wheels without network. Strict Git object integrity and four high-confidence secret patterns passed with zero matches.

Public invocation `72cda586-8994-489b-8295-043aac2b294d` repeated all ten real checks. It created and removed a fresh `52800`-byte archive at `sha256:0fca8bf4b3881e17013f82ba64a099638279a8360edc6849daf188622cc91b26`. Raw custom archive bytes are bound per receipt and may differ between dumps; the normalized 20-entry TOC and all schema, journal, verification-result, and role digests matched the canonical candidate exactly. Source writes remained fenced, the target was different and clean, all five runner privileges remained denied after restart, and teardown removed the archive plus every disposable container, network, and volume.

Policy status remained `MISSING` / `INVALID` at exit `12` before and after under invocations `4683c176-f073-4bce-9fb8-b06d873bd36b` and `d240acdd-86cf-4e56-a2aa-b37d32982ec7`; no approval was written and no workflow ran. The exact three protected volume identities stayed unchanged. Three public or closure harness attempts remain `INVALID`: one stale fixture directory, one assertion against an older envelope field, and one invalid PowerShell ancestry expression that stopped the first closure push wrapper before any Git command executed. None started runtime. The clean noncanonical clone remains outside OneDrive and runtime custody without a cleanup attempt.

`EXIT-BACKUP-RESTORE` passes, `IS4-U05` is complete, and `IS4-U06` is ready to freeze and run the integrated receipt and recovery matrix.

## 2026-08-10 - Integrated receipt and recovery contract candidate

U06 begins with a runtime-free composition contract rather than a privileged orchestration container. The host will call the already locked portable-receipt, reliability, journal, recovery, and backup/restore surfaces in five isolated stages. Six fixed command identities are admitted and arbitrary stage arguments are forbidden. Each stage must remove its disposable custody before the next stage, and the entire sequence must repeat twice.

The closed matrix has twenty cases. It keeps exact, unbound, missing, corrupt, and invalid receipt evidence distinct; completed product PASS and FAIL distinct from malformed input, database failure, and host cancellation; stale and superseded journal streams distinct; safe, ambiguous, conflicting, stale-authority, and competing-holder recovery distinct; and clean restore, negative privileges, and teardown explicit. Cross-cycle equality covers exact images, contract identity, semantic receipt outcomes, journal streams, recovery decisions, normalized TOC, restored state, and privileges. Fresh raw archive bytes remain bound by each individual receipt and are intentionally excluded from equality.

All twenty-eight semantic mutations fail closed and all 93 repository tests pass. The first exact-wheel meta-validation exposed a missing closing brace in the new schema; a direct diagnostic without the source-gated dependency and the exact diagnostic reproduction also remain `INVALID`. A later read-only gate supplied a PCRE case flag to Git's POSIX regex engine, and its first corrected pattern falsely matched a validator's forbidden `PGPASSWORD=` literal; both remain `INVALID`. The final bounded scan uses the correct regex engine, checks every exit, and requires an actual token-like quoted value. The corrected schema and both fixtures pass full Draft 2020-12 validation using six rehashed retained source-gated wheels without network, and temporary evaluator custody was removed. Docker, PostgreSQL, runners, recovery, dump, restore, approval, and workflow execution were not touched. Credential-free public contract replay is next.

## 2026-08-10 - Integrated matrix contract closes from public custody

The resumed cycle re-established exact canonical and public truth at commit `6a27a5fdcc641fa090f70e9c32615c58b6920b0b`, tree `2baf76af64d565001dece0a8efd96f622948bef0`. Docker Desktop had stopped while the goal was paused, so the host engine was restored before evaluation. No prior replay process survived, no IncidentSeal container or network existed, approval was still `MISSING`, and the three protected evidence volumes matched their exact retained identities.

The operator-paused public replay was not resumed midstream or promoted from partial output. It remains `INVALID`. The corrected evaluation restarted at the first gate and reproduced all 93 tests, every machine/topology/receipt/journal/recovery/backup validator and mutation suite, the 20-case and 28-mutation integrated contract, the 25-scenario/50-execution authority matrix, and all 13 clean-copy CLI checks. One Draft 2020-12 schema and two fixtures passed from six rehashed source-gated wheels without network; temporary evaluator custody was removed. Strict Git integrity and four bounded secret patterns passed with zero matches.

Final policy invocation `512f17fe-675f-4348-9875-f7dad54724bb` remained `MISSING` / `INVALID` at exit `12`. The replay started no container, network, PostgreSQL, runner, recovery, dump, or restore, wrote no approval, and ran no repository workflow. All three protected volume identities remained exact and the public clone remained clean. A stale ledger path and an unquoted PowerShell tree revision are retained as two additional `INVALID` read-only harness attempts. The runtime-free contract gate now passes; the next bounded stage is the separate exact implementation lock and fixed host-owned composite with two complete isolated real repetitions.

## 2026-08-10 - Integrated host implementation passes both local cycles

The implementation preserves all six frozen child CLI command identities and uses a separate argument-free host validation harness instead of changing their locked dispatcher. The harness checks zero IncidentSeal containers and networks, exactly three protected volumes, and exact protected identities before and after every stage. It invokes portable receipt states, real reliability, durable journal streaming, fenced recovery, and clean backup/restore in the frozen order, tears each stage down, and repeats the full sequence.

Final-lock invocation `dfb9e1f8-b8e3-48f4-8a01-6a82b7d25f1c` passed both complete cycles in 306.9 seconds. All forty case observations retained their exact lifecycle, run-verdict, observation-verdict, and exit channels. Receipt semantics, exact images, topology contract, journal streams, recovery decisions, normalized TOC, restored state, negative privileges, protected volumes, and teardown matched across cycles. The two fresh archives were each `52800` bytes with distinct exact archive and receipt digests; raw dump equality was correctly excluded while each archive remained content-addressed.

All 101 tests and 39 implementation mutations pass. The mutation cycle first exposed a static claim-check gap; the tightened validator now rejects any positive approval-access or workflow-execution claim. Two runtime attempts remain `INVALID`: one PowerShell evidence wrapper used an unsupported parser option after the product returned exit `12`, and invocation `4e886f6f-b7d3-4f52-b210-8bda7baa356e` exposed shortened runner evidence keys. Neither partial attempt was promoted. The corrected run removed every disposable container, network, volume, archive, and receipt directory; the three protected identities stayed exact; approval remained `MISSING`; and no workflow ran. Exact public-custody implementation replay is next.

## 2026-08-10 - Integrated implementation closes from public custody

Candidate commit `a06ab530dd4ae9d14372d797142a9910b82b4d08`, tree `5873ecf6ddbf69a7feb2b738779cb2623326f366`, was pushed and cloned from GitHub with credentials and prompts disabled. The exact clean clone passed 101 tests, every inherited validator and mutation suite, all 39 integrated implementation mutations, the 25-scenario/50-execution authority matrix, 13 clean-copy CLI checks, offline one-schema/two-fixture validation from six rehashed retained wheels, strict Git integrity, and four zero-match secret patterns.

Public invocation `c23e765c-4aa6-4d44-bee8-98725b098844` completed the same two full cycles in 286 seconds. All forty case observations retained their exact state channels. Receipt, image, contract, journal, recovery, normalized TOC, restored-state, negative-privilege, protected-volume, and teardown comparisons passed. The two new `52800`-byte archives were bound at `sha256:9fb9d0430bea58bec4ee12f8e7c588f4e67780dfc4c48b3c1e54fc8c8618654b` and `sha256:dd4522a272a2f4f410fc74f01cff3f751e3a8fcd84c115b50e7f81704ab66880`, each with its own receipt; their raw bytes were not forced equal.

Approval remained `MISSING` / `INVALID` at exit `12` before and after. The clone stayed clean, no workflow ran, all temporary and disposable custody was removed, and the three protected identities remained exact. Two public wrappers remain `INVALID`: the post-push unquoted tree expression and a follow-up query run from the temp parent after the clone itself succeeded. Neither started runtime. `EXIT-REAL-RECOVERY` now passes and IS4-U07 exact checkpoint closure is next.

## 2026-08-10 - IS-0004 closes at an independently verified public marker

Closure commit `25328dacef4d9283090bed809db75b33f613829b`, tree `b03947a405f670a0ed41f0ec1544722fdbe69d20`, was pushed and cloned from credential-free public custody. The exact closure clone passed 101 tests, all 39 integrated implementation mutations, all 28 contract mutations, the 25-scenario/50-execution authority matrix, 13 clean-copy CLI checks, offline full-schema validation from six exact wheels, strict Git integrity, and four zero-match secret patterns.

Closure invocation `9db2051a-f3ab-470d-8162-84e6237e4e8c` then passed both complete real cycles. All forty state observations and every image, contract, receipt, journal, recovery, normalized-TOC, restored-state, negative-privilege, protected-volume, and teardown comparison passed. The two fresh archive receipts remained independent. Approval was still `MISSING` at exit `12`, no workflow ran, the clone remained clean, and no disposable custody remained.

Annotated `checkpoint-is-0004` was created only after those gates passed. Tag object `60b467a7970a6fb6b5e80dcdc4dd283ab80b0acf` was pushed, fetched into the pre-marker credential-free clone, identified as an annotated tag, and peeled locally and remotely to the exact closure commit. The first unquoted remote peeled-tag query remains `INVALID`; the corrected quoted query returned both exact remote rows. All IS-0004 exits now pass. This is a verified evidence-and-recovery checkpoint, not a software release; dashboard and broader evaluation are next.

## 2026-08-10 - IS-0005 opens with the dashboard contract gate

The next cycle began by rechecking clean canonical and remote `main`, the exact `checkpoint-is-0004` tag object and peeled commit, the completed IS-0004 contract, zero IncidentSeal containers and networks, exactly the three protected volumes, and the unchanged missing-approval boundary under invocation `3c8fa4d6-1183-482d-9d79-906c14f1eb54`. No dashboard server or product runtime started.

IS-0005 is intentionally narrower than a generic observability platform. It targets one polished reusable local evidence surface plus a deterministic evaluation corpus. The dashboard must project exact repository records without becoming authority, serve only over loopback, reject write methods and non-loopback hosts, use only local assets, show checkpoint and record digests, keep every verdict/lifecycle/missing/corrupt state distinct, and remain independent from Docker and approval custody. The first unit freezes those contracts before implementation.

The planned corpus covers success, product failure, invalid input, missing evidence, policy attack, isolation attack, corrupt receipt, crash, and recovery. Real browser rendering, desktop/mobile layout, accessibility structure, failure states, repeated correctness, latency, resource use, and claim calibration are later gates. Cloud, analytics, telemetry, external fonts, packaging, registry, and release work remain outside this milestone.

## 2026-08-10 - Dashboard contract candidate passes locally

The runtime-free candidate binds the evidence view to seven exact source records and the full annotated `checkpoint-is-0004` identity. It freezes eight passed checkpoint exits, every verdict and lifecycle channel, separate missing and corrupt evidence, retained negative attempts, a loopback-only `GET`/`HEAD` serving boundary, fixed local assets, security headers, a dark forensic evidence-desk direction, and explicit desktop, mobile, keyboard, contrast, reduced-motion, and failure-state acceptance.

The nine-case corpus repeats success, product failure, invalid input, missing evidence, policy attack, isolation attack, corrupt receipt, crash, and recovery three times. Metrics include correctness, projection and render latency, peak process memory, response bytes, request failures, source coverage, and claim calibration, with zero false PASS or release claims. All 37 semantic mutations fail closed, 111 tests pass, and both schemas plus four fixtures pass Draft 2020-12 validation from six rehashed retained wheels without network.

No dashboard server, browser, Docker, PostgreSQL, runner, approval write, or workflow started. The separate future launcher avoids changing the frozen verification CLI. One read-only Git-tree wrapper remains `INVALID` because its PowerShell revision was unquoted; the corrected quoted query passed. The candidate must still be committed, pushed, and reproduced from credential-free public custody before U01 closes.

## 2026-08-11 - Dashboard contract closes from public custody

Exact public commit `2e22804a...` and tree `73c2480a...` reproduced the complete runtime-free contract from a fresh clone with credential helpers and terminal prompting disabled. All 111 tests, 37 mutations, two schemas and four fixtures, six exact offline wheels, strict Git integrity, and four zero-match secret patterns passed. The project probe found the expected IS-0005 control state and current Docker/Compose environment.

Approval remained `MISSING` / `INVALID` at exit `12`. The clean clone started no server, browser, Docker product runtime, PostgreSQL, runner, or workflow. No IncidentSeal container or network exists, and the three retained evidence volumes match their exact identities. The first authority wrapper inspected the wrong envelope object and remains `INVALID`; the corrected read-only assertion passed. The contract exit now closes, and implementation begins under the separate loopback-only launcher boundary.

## 2026-08-11 - The real loopback dashboard passes locally

The dashboard remains outside the frozen verification CLI. Its separate zero-dependency launcher verifies the exact seven-record snapshot and nine-case corpus before binding only `127.0.0.1`. It serves one semantic evidence desk, two local assets, the canonical snapshot, and a readiness document. Exact Host enforcement, no-store caching, CSP, framing denial, MIME-sniff denial, restrictive permissions, and same-origin boundaries apply to successful and rejected responses.

The final locked Windows run served 25 requests and closed itself cleanly: five GETs, five HEADs, seven write/control denials, four hostile Host denials, and four query/traversal denials. The repository did not change and no server process survived. Nine internal fixed scenario applications now render success, product failure, invalid input, missing evidence, policy attack, isolation attack, corrupt receipt, crash, and recovery with distinct labels and claim calibration; scenario selection is not exposed to HTTP.

Three launcher attempts remain `INVALID`: the first connection reset lacked request context, the second found a final daemon-thread shutdown race, and the first exact-lock wrapper expected a lock digest in the wrong envelope. The corrected server waits for request completion and the outer result now binds the implementation lock. Three passing interim candidates remain `superseded` after scenario and documentation improvements. All 125 tests and 29 implementation mutations pass. Approval is still missing, no workflow or Docker surface was accessed, and public replay remains before implementation closure.

## 2026-08-11 - Dashboard implementation closes from public custody

The clean public clone at commit `6a5d1cf8...` returned the same locked HTML, snapshot, CSS, JavaScript, and health bytes as the canonical candidate. Its real Windows launcher served all 25 requests on port `59384`, denied every fixed attack case, emitted all eight security headers, changed no repository file, and left no dashboard process or socket.

All 125 tests, both mutation suites, and offline schema validation passed again. Git object integrity and four high-confidence secret patterns passed with zero matches. Approval was `MISSING` / `INVALID` at exit `12` before and after, no workflow ran, the dashboard accessed no Docker surface, and the three protected evidence volumes remained exact. This closes server implementation, not visual acceptance: desktop/mobile rendering, keyboard behavior, accessibility structure, overflow, reduced motion, local-only browser requests, and all nine rendered states are next.

## 2026-08-11 - Rendered dashboard candidate passes after two real corrections

The first browser-visible implementation failed its frozen contrast gate: muted evidence text measured only 3.3672:1 on the brightest panel. The next revision corrected contrast but left the always-visible mobile wordmark at 30 CSS pixels against the 44 CSS pixel target requirement. Both are retained as product `FAIL` evidence. Revision 3 passes at a minimum 4.7291:1 and gives every navigation target at least 44 CSS pixels.

The final local candidate renders one desktop success view and all nine fixed mobile states without horizontal overflow. Only success displays `Claim permitted`; every failure, invalidity, missing-evidence, rejected-attack, corruption, crash, and recovery view displays `Claim withheld`. The page exposes one main landmark, labelled navigation, ten ordered headings, one three-header table, and five lists. Chrome keyboard traversal reaches the skip link, wordmark, and four section links in order with a visible lime focus outline and no trap. Reduced motion removes animation, transitions, and smooth scrolling without hiding content. Eleven JPEG screenshots are hash-bound; browser observations show only two local assets plus a denied local favicon probe, zero external requests, and zero console logs.

All 129 tests and the 37 contract, 29 implementation, and 28 browser mutations pass. Thirteen evaluator attempts remain `INVALID` without being mislabelled as product failure. The real 25-request launcher closed; approval remained missing; no workflow ran; no Docker surface was accessed; no container or network exists; and the three protected volumes remain exact. The candidate then moved to exact public replay.

## 2026-08-11 - Rendered dashboard closes from public custody

Exact credential-free public candidate commit `46639491...`, tree `b3eaef7b...`, reproduced the revision-3 and browser locks, all static suites, offline schema evaluation, the 25-request real launcher, desktop rendering, all nine mobile states, and the complete semantic and claim-calibration matrix. Ten public in-app browser captures matched their retained candidate bytes exactly. Independent Chrome traversal reproduced the seven-step focus sequence and no-trap result; its new JPEG encoding was not byte-identical to the earlier Chrome capture, but byte equality was neither claimed nor required for the semantic interaction gate.

The first public wrapper could not classify a clean detached-HEAD branch and remains `INVALID`. The corrected process put the same exact commit on a local no-track branch and restarted the entire replay from its first gate. Remote `main`, commit, tree, Git integrity, secret scan, missing approval, zero workflow execution, process teardown, zero containers and networks, and all three protected volume identities passed. `EXIT-READ-ONLY-DASHBOARD` now closes. U04 begins with bounded repeated measurement rather than adding platform scope.

## 2026-08-11 - The complete repeated dashboard evaluation passes locally

U04 freezes one no-argument evaluator rather than a benchmark framework. It runs the exact nine-state corpus in order three times. Every trial reloads all seven source records, renders one fixed state, starts a fresh loopback server, checks all five response bodies and security headers, and proves the server closed before moving on. It accepts no scenario, repetition, route, repository, network, Docker, approval, workflow, output, or performance-threshold input.

The saved candidate passed all 27 cases, 135 responses, 189 source observations, nine stable HTML identities, and three crash-to-recovery transitions. Success permitted exactly three claims; the other 24 observations withheld them, with zero false PASS or release claims. Median local projection and server-side render times were 5.174400 and 0.040700 milliseconds; median peak process memory was 28,987,392 bytes; median five-route response size was 30,523 bytes. These values document this run and do not claim browser paint or cross-machine budgets.

Thirty result mutations fail closed and all 133 tests pass. Five wrapper defects remain `INVALID`, including an incorrect volume-label assumption and a policy-status call missing its required manifest. One complete pre-lock calibration remains a `superseded` PASS, not candidate evidence. Approval is still missing, no workflow ran, no Docker custody changed, and every loopback server closed. Public replay is the remaining U04 gate.

## 2026-08-11 - Repeated evaluation closes from public custody

The fresh credential-free clone at exact commit `df8043bc...`, tree `01c23299...`, restarted the fixed evaluator from its first gate. It again passed all 27 states, 135 response checks, 189 source observations, nine stable HTML identities, three recovery transitions, and exact claim calibration. All deterministic identities and semantics matched the local candidate. Timing and memory were measured anew rather than forced equal; the public run remained within a similarly small bounded range, and fixed five-route response sizes matched exactly.

The public clone repeated all 133 tests and the 37 contract, 29 implementation, 28 browser, and 30 evaluation mutations. Strict Git integrity and four high-confidence secret patterns passed. Approval was missing before and after, no workflow ran, no Docker surface was accessed, every server closed, the three protected volumes remained exact, and Git custody stayed clean. Both evaluation exits now close. U05 will verify the exact combined checkpoint and only then create its annotated marker.

## 2026-08-11 - IS-0005 closes at an independently verified public marker

The exact closure clone at commit `04230dcc...`, tree `ec2ed653...`, started from the verified IS-0004 marker and passed all four dashboard locks, 133 tests, 124 mutations, offline schema validation, strict Git and secret integrity, the real 25-request launcher, and another complete 27-trial evaluation. The last evaluation again produced 27 correct cases, 135 clean responses, 189 source observations, nine stable HTML identities, three recovery transitions, and zero false claims. Timing and memory remained bounded observations, not release promises.

Approval remained missing before and after, no workflow ran, every local server closed, no IncidentSeal container or network exists, and all three protected volumes retain their exact identities. Only then was annotated `checkpoint-is-0005` created. Tag object `aba5e64f...` was pushed, fetched without credentials into the clean closure clone, identified as an annotated tag, and peeled locally and remotely to `04230dcc...`. IS-0005 is complete. The next milestone is portable release work, not a claim that v0.1.0 already exists.

## 2026-08-11 - IS-0006 opens with a contract-only release boundary

The new cycle reverified clean canonical and public `main` at post-marker commit `b4abd2c...`, annotated `checkpoint-is-0005` object `aba5e64f...`, peeled closure commit `04230dcc...`, the completed IS-0005 contract, Docker 29.4.3, Compose 5.1.3, zero IncidentSeal containers and networks, the exact three protected volume identities, and missing workflow approval under invocation `10b799c9...`. GitHub reports no releases and release immutability disabled. Package inventory remains `INCONCLUSIVE` because the current token lacks `read:packages`; access was not changed.

The v0.1.0 direction is deliberately small: a dependency-free Python wheel and source distribution on GitHub Releases, plus exact-digest GHCR runtime images. PyPI is excluded to avoid adding a second publishing identity or secret. Every build backend, action, scanner, SBOM/provenance tool, image, and dependency must be source-gated and digest-pinned. Image publication remains forbidden until exact notices and all `NOASSERTION` entries are reconciled. Packaged and clean-clone real CLI, Compose, PostgreSQL, runner, dashboard, receipt, recovery, teardown, download, and pull surfaces must pass before release claims.

`IS6-U01` is contract-only. It cannot build a package or image, start product runtime, publish a workflow, tag, registry artifact, or release, change access, or enable immutable releases. GitHub's current immutable-release feature is reserved for the exact irreversible-action human gate after a complete candidate exists. Four opening attempts remain distinct: an invalid Windows glob wrapper, an inconclusive aggregate remote timeout, an invalid unsupported CLI help argument, and an inconclusive package API 403.
