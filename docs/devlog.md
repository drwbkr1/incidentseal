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
