# Disposable reliability surface

`topology reliability-probe --mode platform-validation --json` is the U08 host-owned reliability gate. It uses the exact locked images but a fixed disposable Compose project and volume. It never mounts, renames, relabels, or deletes the three digest-bound evidence volumes in `requirements/retained-runtime-volumes.lock.json`.

Each invocation requires the disposable project to be absent, starts PostgreSQL on a fresh volume, runs the real migration, executes both shipped language runners, and verifies exact output and database rows. Temporary staged custody is outside the repository and OneDrive. Runtime users, read-only roots, capabilities, no-new-privileges, mounts, internal networking, environment names, and Docker-endpoint absence are inspected again.

The probe preserves independent state dimensions with real effects:

- a tampered temporary result is a completed verification `FAIL`;
- a malformed fixed request is `INVALID` and creates no output or row;
- a valid runner invoked while PostgreSQL is stopped has lifecycle `failed` and no verification verdict;
- a host-stopped 30-second database query has lifecycle `cancelled`, no verification verdict, and observed process/container exit `137`;
- the same valid recovery request succeeds after PostgreSQL restarts; and
- all exact rows persist through a later database restart.

Only the disposable volume, containing fixed non-sensitive test rows, is removed after verified teardown. Every one-shot container is removed before the next operation, orphan detection requires only the database to remain before final teardown, and the final check requires no disposable container, network, or volume while all three protected volumes still exist.

Two canonical-checkout passes are retained in `records/evaluations/IS-0003-U08-reliability-local.json`. Exact public commit `71dca263a1e696c454b3e48fcbb394cd04d802a0` then passed control validation, 50 tests, 15 implementation mutations, and the same 14 real reliability checks without credentials. Its receipt is `records/surface-receipts/IS-0003-U08-clean-clone-reliability.json`.

The non-canonical temp clone remains in non-OneDrive local temp custody because local command policy denied recursive deletion. That explicit local residue does not change the reliability verdict: the clone was clean before and after validation, contains no secret, and every disposable Docker resource was removed. U08 is complete; U09 owns the exact closure commit and public checkpoint marker.
