#!/usr/bin/env python3
"""Require every unsafe backup/restore implementation mutation to fail closed."""

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
    Mutation("source-target-project-collapsed", "src/incidentseal/backup_restore_surface.py", 'TARGET_PROJECT = "incidentseal-restore-target"', 'TARGET_PROJECT = "incidentseal-backup-source"'),
    Mutation("internal-network-removed", "src/incidentseal/backup_restore_surface.py", '"network", "create", "--driver", "bridge", "--internal"', '"network", "create", "--driver", "bridge", "--attachable"'),
    Mutation("read-only-root-removed", "src/incidentseal/backup_restore_surface.py", '"--read-only", "--security-opt"', '"--security-opt"'),
    Mutation("no-new-privileges-removed", "src/incidentseal/backup_restore_surface.py", '"no-new-privileges"', '"label"'),
    Mutation("capability-drop-removed", "src/incidentseal/backup_restore_surface.py", '"--cap-drop", "ALL"', '"--cap-add", "CHOWN"'),
    Mutation("container-secret-added", "src/incidentseal/backup_restore_surface.py", '"--env", "PGDATABASE=incidentseal"', '"--env", "PGPASSWORD=incidentseal", "--env", "PGDATABASE=incidentseal"'),
    Mutation("docker-socket-mount-added", "src/incidentseal/backup_restore_surface.py", '"--tmpfs", "/tmp:rw,nosuid,nodev,size=16777216,uid=70,gid=70,mode=0700"', '"--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock", "--tmpfs", "/tmp:rw,nosuid,nodev,size=16777216,uid=70,gid=70,mode=0700"'),
    Mutation("repository-custody-allowed", "src/incidentseal/backup_restore_surface.py", "ROOT in candidate.parents", "False"),
    Mutation("onedrive-custody-allowed", "src/incidentseal/backup_restore_surface.py", 'part.casefold() == "onedrive"', "False"),
    Mutation("source-write-fence-weakened", "src/incidentseal/backup_restore_surface.py", "IN SHARE MODE", "IN ROW SHARE MODE"),
    Mutation("snapshot-write-check-bypassed", "src/incidentseal/backup_restore_surface.py", 'return result.returncode != 0 and "statement timeout" in combined', "return True"),
    Mutation("archive-recheck-bypassed", "src/incidentseal/backup_restore_surface.py", "if _digest(archive.read_bytes()) != archive_digest:", "if False:"),
    Mutation("toc-forbidden-check-bypassed", "src/incidentseal/backup_restore_surface.py", "if TOC_FORBIDDEN_RE.search(line):", "if False:"),
    Mutation("restore-mount-made-writable", "src/incidentseal/backup_restore_surface.py", 'mount=(backup_dir, True)', 'mount=(backup_dir, False)'),
    Mutation("post-restore-migration-removed", "src/incidentseal/backup_restore_surface.py", "inspections.append(_run_migration(", "inspections.append(_run_migration_removed("),
    Mutation("migration-diagnostics-broadened", "src/incidentseal/backup_restore_surface.py", "match is None or match.group(1) not in EXPECTED_EXISTING_RELATIONS", "False"),
    Mutation("negative-privilege-check-bypassed", "src/incidentseal/backup_restore_surface.py", 'set(negative_privileges.values()) == {"denied"}', "True"),
    Mutation("restart-check-removed", "src/incidentseal/backup_restore_surface.py", '_run(docker, ["restart", TARGET_DATABASE])', '_run(docker, ["inspect", TARGET_DATABASE])'),
    Mutation("protected-volume-check-bypassed", "src/incidentseal/backup_restore_surface.py", "custody_ok = protected_before == protected_after and protected.issubset(after_volumes)", "custody_ok = True"),
    Mutation("arbitrary-backup-command-exposed", "src/incidentseal/cli.py", "COMMANDS = {", 'COMMANDS = {\n    ("backup", "restore"): "backup.restore",'),
    Mutation("implementation-lock-digest-tampered", "requirements/backup-restore-implementation.lock.json", '"sha256": "sha256:', '"sha256": "sha256:0', refresh_lock=False),
)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def refresh_lock(root: Path, changed_path: str) -> None:
    path = root / "requirements/backup-restore-implementation.lock.json"
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
    manifest = json.loads((ROOT / "fixtures/backup-restore/implementation-mutations.json").read_text(encoding="utf-8"))
    if [item["id"] for item in manifest["mutations"]] != [item.id for item in MUTATIONS]:
        raise RuntimeError("backup implementation mutation manifest differs")
    results = []
    for mutation in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="incidentseal-backup-implementation-mutation-") as temporary:
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
                [sys.executable, "-B", str(candidate / "scripts/validate_backup_restore_implementation.py"), "--root", str(candidate)],
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
        "schema_version": "incidentseal-backup-restore-implementation-mutation-results/v1",
        "verification_verdict": "PASS",
        "mutation_count": len(results),
        "mutations": results,
        "runtime_started": False,
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
