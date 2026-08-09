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
