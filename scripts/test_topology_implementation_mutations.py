#!/usr/bin/env python3
"""Mutate the real topology implementation and require the host CLI to fail closed."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Mutation:
    id: str
    path: str
    old: str
    new: str
    expected_error: str
    refresh_lock: bool = True
    add_file: str | None = None


MUTATIONS = (
    Mutation(
        "database-seed-owner-drift",
        "containers/database/Dockerfile",
        "COPY --chown=70:70 volume-seed /var/lib/postgresql/incidentseal-data\n",
        "COPY --chown=0:0 volume-seed /var/lib/postgresql/incidentseal-data\n",
        "IS_TOPOLOGY_IMPLEMENTATION",
    ),
    Mutation(
        "migration-broad-grant",
        "containers/migration/001-schema.sql",
        "GRANT SELECT, INSERT, UPDATE ON TABLE verification_results TO incidentseal_runner;\n",
        "GRANT ALL PRIVILEGES ON TABLE verification_results TO incidentseal_runner;\n",
        "IS_TOPOLOGY_IMPLEMENTATION",
    ),
    Mutation("privileged-database", "compose.yaml", "    privileged: false\n", "    privileged: true\n", "IS_TOPOLOGY_RENDER"),
    Mutation("external-data-network", "compose.yaml", "    internal: true\n", "    internal: false\n", "IS_TOPOLOGY_RENDER"),
    Mutation("mutable-pull", "compose.yaml", "    pull_policy: never\n", "    pull_policy: always\n", "IS_TOPOLOGY_RENDER"),
    Mutation("writable-root", "compose.yaml", "    read_only: true\n", "    read_only: false\n", "IS_TOPOLOGY_RENDER"),
    Mutation(
        "published-database-port",
        "compose.yaml",
        "    networks:\n      - data\n    entrypoint:\n",
        "    networks:\n      - data\n    ports:\n      - \"5432:5432\"\n    entrypoint:\n",
        "IS_TOPOLOGY_RENDER",
    ),
    Mutation(
        "docker-socket-target",
        "compose.yaml",
        "        target: /incidentseal/input\n",
        "        target: /var/run/docker.sock\n",
        "IS_TOPOLOGY_RENDER",
    ),
    Mutation(
        "manifest-label-drift",
        "compose.yaml",
        "  dev.incidentseal.manifest-digest:",
        "  dev.incidentseal.manifest-authority:",
        "IS_TOPOLOGY_RENDER",
    ),
    Mutation(
        "migration-command-drift",
        "compose.yaml",
        "      - --file=/opt/incidentseal/migrations/001-schema.sql\n",
        "      - --file=/tmp/uncontrolled.sql\n",
        "IS_TOPOLOGY_RENDER",
    ),
    Mutation(
        "tmpfs-mode-drift",
        "compose.yaml",
        "      - /var/run/postgresql:size=16777216,mode=0775,uid=70,gid=70\n",
        "      - /var/run/postgresql:size=16777216,mode=0777,uid=70,gid=70\n",
        "IS_TOPOLOGY_RENDER",
    ),
    Mutation(
        "dockerfile-run",
        "containers/python-runner/Dockerfile",
        "USER 65532:65532\n",
        "RUN echo forbidden\nUSER 65532:65532\n",
        "IS_TOPOLOGY_IMPLEMENTATION",
    ),
    Mutation(
        "mutable-base",
        "containers/python-runner/Dockerfile",
        "ARG INCIDENTSEAL_PYTHON_IMAGE=cgr.dev/chainguard/python@sha256:69437de912cc3b5d36a2480b8fb0c3f658f151d8bc1978d19a6412be3a4983d5\n",
        "ARG INCIDENTSEAL_PYTHON_IMAGE=python:3.14\n",
        "IS_TOPOLOGY_IMPLEMENTATION",
    ),
    Mutation(
        "unexpected-build-context-file",
        "containers/node-runner/Dockerfile",
        "ENTRYPOINT [\"/nodejs/bin/node\"]\n",
        "ENTRYPOINT [\"/nodejs/bin/node\"]\n",
        "IS_TOPOLOGY_IMPLEMENTATION",
        add_file="containers/node-runner/unexpected.txt",
    ),
    Mutation(
        "stale-implementation-lock",
        "compose.yaml",
        "    pids_limit: 128\n",
        "    pids_limit: 129\n",
        "IS_TOPOLOGY_IMPLEMENTATION",
        refresh_lock=False,
    ),
)


def copy_root(destination: Path) -> None:
    for directory in ("containers", "src"):
        shutil.copytree(ROOT / directory, destination / directory)
    for directory in ("contracts", "requirements", "fixtures/topology", "schemas"):
        (destination / directory).mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "contracts" / "topology-v1.json", destination / "contracts" / "topology-v1.json")
    shutil.copy2(ROOT / "requirements" / "images.lock.json", destination / "requirements" / "images.lock.json")
    shutil.copy2(
        ROOT / "requirements" / "event-journal-implementation.lock.json",
        destination / "requirements" / "event-journal-implementation.lock.json",
    )
    shutil.copy2(
        ROOT / "requirements" / "recovery-implementation.lock.json",
        destination / "requirements" / "recovery-implementation.lock.json",
    )
    shutil.copy2(
        ROOT / "requirements" / "retained-runtime-volumes.lock.json",
        destination / "requirements" / "retained-runtime-volumes.lock.json",
    )
    shutil.copy2(
        ROOT / "requirements" / "topology-implementation.lock.json",
        destination / "requirements" / "topology-implementation.lock.json",
    )
    shutil.copy2(
        ROOT / "requirements" / "topology-contract.lock.json",
        destination / "requirements" / "topology-contract.lock.json",
    )
    shutil.copy2(ROOT / "fixtures" / "topology" / "render.valid.json", destination / "fixtures" / "topology" / "render.valid.json")
    shutil.copy2(
        ROOT / "fixtures" / "topology" / "runner-request.valid.json",
        destination / "fixtures" / "topology" / "runner-request.valid.json",
    )
    shutil.copy2(
        ROOT / "fixtures" / "topology" / "runner-request.invalid.extra.json",
        destination / "fixtures" / "topology" / "runner-request.invalid.extra.json",
    )
    shutil.copy2(
        ROOT / "fixtures" / "topology" / "runner-request.recovery.json",
        destination / "fixtures" / "topology" / "runner-request.recovery.json",
    )
    shutil.copy2(ROOT / "fixtures" / "topology" / "mutations.json", destination / "fixtures" / "topology" / "mutations.json")
    for name in ("topology-contract-v1.schema.json", "topology-render-v1.schema.json"):
        shutil.copy2(ROOT / "schemas" / name, destination / "schemas" / name)
    shutil.copy2(ROOT / "compose.yaml", destination / "compose.yaml")


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def refresh_lock(root: Path, path: str) -> None:
    lock_path = root / "requirements" / "topology-implementation.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    item = next(entry for entry in lock["files"] if entry["path"] == path)
    item["sha256"] = sha256_file(root / path)
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n")


def invoke(root: Path) -> tuple[int, dict[str, Any], str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-B", "-m", "incidentseal", "topology", "validate", "--mode", "platform-validation", "--json"],
        cwd=root,
        env=environment,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=60,
        check=False,
    )
    try:
        envelope = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"topology CLI emitted invalid JSON: {completed.stdout!r}") from error
    return completed.returncode, envelope, completed.stderr


def apply_mutation(root: Path, mutation: Mutation) -> None:
    path = root / mutation.path
    text = path.read_text(encoding="utf-8")
    if text.count(mutation.old) < 1:
        raise RuntimeError(f"mutation anchor is absent: {mutation.id}")
    path.write_text(text.replace(mutation.old, mutation.new, 1), encoding="utf-8", newline="\n")
    if mutation.add_file:
        added = root / mutation.add_file
        added.write_text("unexpected build context input\n", encoding="utf-8", newline="\n")
    if mutation.refresh_lock:
        refresh_lock(root, mutation.path)


def main() -> int:
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="incidentseal-implementation-mutations-") as temporary:
        base = Path(temporary) / "base"
        copy_root(base)
        baseline_code, baseline, baseline_stderr = invoke(base)
        if baseline_code != 0 or baseline.get("verdict") != "PASS" or baseline_stderr:
            raise RuntimeError(f"baseline failed: {baseline}; stderr={baseline_stderr}")
        for index, mutation in enumerate(MUTATIONS):
            case = Path(temporary) / f"case-{index:02d}"
            shutil.copytree(base, case)
            apply_mutation(case, mutation)
            code, envelope, stderr = invoke(case)
            actual = envelope.get("errors", [{}])[0].get("code")
            passed = code != 0 and envelope.get("verdict") == "INVALID" and actual == mutation.expected_error and not stderr
            results.append(
                {
                    "id": mutation.id,
                    "expected_error": mutation.expected_error,
                    "actual_error": actual,
                    "verdict": "PASS" if passed else "FAIL",
                }
            )
            if not passed:
                raise RuntimeError(f"mutation {mutation.id} failed incorrectly: {envelope}; stderr={stderr}")
    print(
        json.dumps(
            {
                "schema_version": "incidentseal-topology-implementation-mutations/v1",
                "verdict": "PASS",
                "mutations": results,
                "builds_executed": False,
                "runtime_started": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
