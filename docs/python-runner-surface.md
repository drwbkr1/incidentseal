# Python runner surface

`topology python-probe --mode platform-validation --json` is the host-owned real Python application gate for `IS3-U06`. It does not approve or execute a workflow manifest.

The probe first validates the active topology implementation and runtime locks. It reuses the four exact local image IDs and the exact retained revision-3 PostgreSQL volume; it does not pull, rebuild, or publish an image. Docker and Compose remain host-only.

The host creates temporary staged custody outside the repository and outside OneDrive. The fixed valid request is mounted read-only at `/incidentseal/input`; only a narrow temporary output directory is writable. The Python container runs as `65532:65532` with a read-only root, all capabilities dropped, no-new-privileges, no privileged mode, no published port, no sensitive environment name, no Docker endpoint, and only the internal data network.

For the positive path, the probe executes the image's shipped default command, independently computes the expected canonical input and result digests, verifies the exact single `result.json`, and reads the exact row back from PostgreSQL. The application command must exit zero and emit no stderr; both stream digests are retained, and the verified runs emitted neither stdout nor stderr.

For the negative path, the host replaces the staged request with a fixed extra-field fixture. The same shipped command must exit nonzero with the stable shape error, produce no result file, leave the staged bytes unchanged, and create no database row.

Completed one-shot containers are inspected and removed before the next Compose invocation. A final fail-safe teardown removes every remaining IncidentSeal container and the internal network while preserving the exact evidence-bound database volume.

The first two valid evidence attempts remain `FAIL`: the probe initially conflated Compose transport stderr with application stderr, and quiet progress then exposed a Compose orphan warning caused by retaining a completed migration container between invocations. The passing revision suppresses Compose progress and removes inspected one-shots between commands without relaxing the empty application-stream gate.

Two identical passing invocations are bound in `requirements/topology-runtime.lock.json` and evaluated in `records/evaluations/IS-0003-U06-python-runner.json`. The evaluation does not claim Node, workflow, cancellation, recovery, dashboard, clean-clone, redistribution, or release verification.
