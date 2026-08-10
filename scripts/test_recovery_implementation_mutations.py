#!/usr/bin/env python3
"""Refresh mutated recovery locks and require every unsafe implementation to fail closed."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    id: str
    path: str
    old: str
    new: str
    refresh_lock: bool = True


MUTATIONS = (
    Mutation(
        "sql-advisory-lock-removed", "containers/migration/001-schema.sql",
        "PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_run_id::text, 1));",
        "PERFORM 1;",
    ),
    Mutation("sql-row-lock-weakened", "containers/migration/001-schema.sql", "FOR UPDATE;", "FOR SHARE;"),
    Mutation(
        "sql-active-workflow-allowed", "containers/migration/001-schema.sql",
        "IF v_fence.workflow_expires_at > CURRENT_TIMESTAMP THEN", "IF false THEN",
    ),
    Mutation(
        "sql-active-recoverer-allowed", "containers/migration/001-schema.sql",
        "IF v_fence.recovery_expires_at > CURRENT_TIMESTAMP THEN", "IF false THEN",
    ),
    Mutation(
        "sql-fence-not-incremented", "containers/migration/001-schema.sql",
        "recovery_fence_token = f.recovery_fence_token + 1", "recovery_fence_token = f.recovery_fence_token",
    ),
    Mutation(
        "sql-runner-fence-read", "containers/migration/001-schema.sql",
        "GRANT SELECT, INSERT, UPDATE ON TABLE verification_results TO incidentseal_runner;",
        "GRANT SELECT, INSERT, UPDATE ON TABLE verification_results TO incidentseal_runner;\nGRANT SELECT ON TABLE incidentseal_recovery_fences TO incidentseal_runner;",
    ),
    Mutation(
        "repository-custody-allowed", "src/incidentseal/recovery_surface.py",
        "repository in candidate.parents", "False",
    ),
    Mutation(
        "atomic-replace-removed", "src/incidentseal/recovery_surface.py",
        "os.replace(temporary, target)", "target.write_bytes(temporary.read_bytes())",
    ),
    Mutation(
        "pre-action-drift-inverted", "src/incidentseal/recovery_surface.py",
        "canonical_bytes(refreshed) != canonical_bytes(observation)",
        "canonical_bytes(refreshed) == canonical_bytes(observation)",
    ),
    Mutation(
        "runtime-network-ownership-removed", "src/incidentseal/recovery_probe.py",
        'host.get("NetworkMode") == "none"', "True",
    ),
    Mutation(
        "runtime-no-new-privileges-removed", "src/incidentseal/recovery_probe.py",
        'host.get("SecurityOpt") == ["no-new-privileges"]', "True",
    ),
    Mutation(
        "runtime-mount-ownership-removed", "src/incidentseal/recovery_probe.py",
        'not (value.get("Mounts") or [])', "True",
    ),
    Mutation(
        "runtime-fence-label-removed", "src/incidentseal/recovery_probe.py",
        'labels.get("dev.incidentseal.workflow-fence-token") == str(runtime_spec["workflow_fence_token"])',
        "True",
    ),
    Mutation(
        "active-recovery-fence-ignored", "src/incidentseal/recovery_probe.py",
        "or not self._active_fence", "or False and self._active_fence",
    ),
    Mutation(
        "protected-volume-comparison-weakened", "src/incidentseal/recovery_probe.py",
        "custody_ok = protected_before == protected_after and protected.issubset(after_volumes)",
        "custody_ok = True",
    ),
    Mutation(
        "arbitrary-run-recover-exposed", "src/incidentseal/cli.py",
        'COMMANDS = {', 'COMMANDS = {\n    ("run", "recover"): "run.recover",',
    ),
    Mutation(
        "implementation-lock-digest-tampered", "requirements/recovery-implementation.lock.json",
        '"sha256": "sha256:', '"sha256": "sha256:0', refresh_lock=False,
    ),
)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def refresh_lock(root: Path, changed_path: str) -> None:
    path = root / "requirements" / "recovery-implementation.lock.json"
    lock = json.loads(path.read_text(encoding="utf-8"))
    matched = False
    for entry in lock["files"]:
        if entry["path"] == changed_path:
            entry["sha256"] = digest(root / changed_path)
            matched = True
    if not matched:
        raise RuntimeError(f"mutation path is not locked: {changed_path}")
    path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    manifest = json.loads((ROOT / "fixtures" / "recovery" / "implementation-mutations.json").read_text(encoding="utf-8"))
    if [item["id"] for item in manifest["mutations"]] != [item.id for item in MUTATIONS]:
        raise RuntimeError("recovery implementation mutation manifest differs")
    results = []
    for mutation in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="incidentseal-recovery-implementation-mutation-") as temporary:
            candidate = Path(temporary) / "repo"
            shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
            path = candidate / mutation.path
            text = path.read_text(encoding="utf-8")
            if mutation.old not in text:
                raise RuntimeError(f"mutation anchor is absent: {mutation.id}")
            path.write_text(text.replace(mutation.old, mutation.new), encoding="utf-8")
            if mutation.refresh_lock:
                refresh_lock(candidate, mutation.path)
            completed = subprocess.run(
                [sys.executable, "-B", str(candidate / "scripts" / "validate_recovery_implementation.py"), "--root", str(candidate)],
                cwd=candidate, text=True, encoding="utf-8", capture_output=True, timeout=120, check=False,
            )
            try:
                value = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                raise RuntimeError(f"mutation validator output is invalid: {mutation.id}") from error
            passed = completed.returncode == 1 and value.get("verification_verdict") == "INVALID" and not completed.stderr
            results.append({"id": mutation.id, "verification_verdict": "PASS" if passed else "FAIL"})
            if not passed:
                raise RuntimeError(f"unsafe mutation was not rejected: {mutation.id}: {completed.stdout}{completed.stderr}")
    print(json.dumps({
        "schema_version": "incidentseal-recovery-implementation-mutation-results/v1",
        "verification_verdict": "PASS",
        "mutation_count": len(results),
        "mutations": results,
        "runtime_started": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
