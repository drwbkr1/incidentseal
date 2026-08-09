# Node runner surface

`topology node-probe --mode platform-validation --json` is the host-owned real Node application and cross-runner consistency gate for `IS3-U07`. It does not approve or execute a workflow manifest.

The probe validates the active implementation and runtime locks, reuses the four exact local image IDs and the exact retained revision-3 PostgreSQL volume, and starts Docker only from the host CLI. It does not pull, rebuild, publish, or give a container Docker authority.

Temporary staged custody is outside the repository and outside OneDrive. The fixed request is read-only; only the narrow Node output directory is writable. The Node container runs as `65532:65532` with read-only root, all capabilities dropped, no-new-privileges, no privileged mode, no published port, no sensitive environment name, no Docker endpoint, and only the internal data network.

The positive path executes the image's shipped default command. The host independently computes the expected canonical input and Node result digests, verifies the exact single `result.json`, and reads the exact Node row from PostgreSQL. It also requires the retained Python row to match the independently computed Python result for the same request. Both languages must share the canonical input digest and retain distinct language-bound result digests.

The negative path runs the same shipped command against the fixed extra-field fixture. It must exit nonzero with the stable request-shape error, leave the staged bytes unchanged, produce no result, and create no Node database row.

Completed one-shot containers are inspected and removed between Compose invocations. Final fail-safe teardown removes every IncidentSeal container and the internal network while preserving the exact evidence-bound database volume.

Two identical passing invocations are bound in `requirements/topology-runtime.lock.json` and evaluated in `records/evaluations/IS-0003-U07-node-runner.json`. The evaluation does not claim workflow, cancellation, forced-failure recovery, clean-clone topology, dashboard, receipt recovery, image redistribution, or release verification.
