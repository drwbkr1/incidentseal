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

Two canonical-checkout passes are retained in `records/evaluations/IS-0003-U08-reliability-local.json`. U08 remains open until the same committed candidate passes from an exact credential-free public clone.
