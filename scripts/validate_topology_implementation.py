#!/usr/bin/env python3
"""Exercise the real static topology CLI without building or starting containers."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.validate_machine_contracts import load_schema_documents, validate_schema_instance  # noqa: E402


def run(command: list[str], *, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"command failed with {completed.returncode}: {command[-1]}: {completed.stderr}")
    return completed


def parse_one_json(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    if completed.stderr or completed.stdout.count("\n") != 1 or not completed.stdout.endswith("\n"):
        raise RuntimeError("machine command stream discipline failed")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("machine command did not return an object")
    return value


def container_ids(docker: str) -> list[str]:
    completed = run([docker, "ps", "-aq"])
    return [line for line in completed.stdout.splitlines() if line]


def main() -> int:
    docker = shutil.which("docker")
    node = shutil.which("node")
    if not docker or not node:
        raise RuntimeError("Docker and Node.js are required for static implementation validation")
    before = container_ids(docker)
    python_result = parse_one_json(
        run([sys.executable, "-B", str(ROOT / "containers" / "python-runner" / "python_runner.py"), "--self-test"])
    )
    run([node, "--check", str(ROOT / "containers" / "node-runner" / "node_runner.mjs")])
    node_result = parse_one_json(
        run([node, str(ROOT / "containers" / "node-runner" / "node_runner.mjs"), "--self-test"])
    )
    if python_result["input_digest"] != node_result["input_digest"]:
        raise RuntimeError("runner canonical input digests differ")
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if os.name == "nt":
        command = [
            os.environ.get("COMSPEC", "cmd.exe"),
            "/d",
            "/c",
            str(ROOT / "incidentseal.cmd"),
            "topology",
            "validate",
            "--mode",
            "platform-validation",
            "--json",
        ]
    else:
        command = [
            str(ROOT / "incidentseal"),
            "topology",
            "validate",
            "--mode",
            "platform-validation",
            "--json",
        ]
    envelope = parse_one_json(run(command, environment=environment))
    schemas = load_schema_documents()
    validate_schema_instance(
        schemas["cli-envelope-v1.schema.json"],
        envelope,
        "cli-envelope-v1.schema.json",
        schemas,
    )
    if (
        envelope.get("command") != "topology.validate"
        or envelope.get("verdict") != "PASS"
        or envelope.get("data", {}).get("runtime_started") is not False
        or envelope.get("data", {}).get("derived_image_identity") != "synthetic-static-placeholder"
    ):
        raise RuntimeError("topology CLI did not preserve the static proof boundary")
    after = container_ids(docker)
    if before != after:
        raise RuntimeError("static validation changed Docker container history")
    print(
        json.dumps(
            {
                "schema_version": "incidentseal-topology-implementation-validation/v1",
                "verdict": "PASS",
                "compose_version": envelope["data"]["compose_version"],
                "contract_digest": envelope["data"]["contract_digest"],
                "compose_model_digest": envelope["data"]["compose_model_digest"],
                "normalized_render_digest": envelope["data"]["normalized_render_digest"],
                "runner_input_digest": python_result["input_digest"],
                "container_history_unchanged": True,
                "runtime_started": False,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
