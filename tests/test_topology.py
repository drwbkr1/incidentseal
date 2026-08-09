from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from incidentseal.cli import execute  # noqa: E402
from incidentseal import python_surface, runtime  # noqa: E402
from incidentseal.topology import CONTRACT_PATH, TopologyError  # noqa: E402


class TopologyTests(unittest.TestCase):
    def test_active_runtime_lock_binds_all_exact_image_roles(self) -> None:
        images = runtime._runtime_lock_images(runtime._sha256_file(CONTRACT_PATH))
        if not runtime.RUNTIME_LOCK_PATH.exists():
            self.assertEqual({}, images)
            return
        self.assertEqual(["database", "migration", "python-runner", "node-runner"], list(images))
        self.assertTrue(all(item["image_id"].startswith("sha256:") for item in images.values()))

    def test_runtime_lock_contract_drift_fails_closed(self) -> None:
        source = runtime.RUNTIME_LOCK_PATH
        if not source.exists():
            source = ROOT / "requirements" / "history" / "IS3-U05-database-least-privilege-failure.runtime.lock.json"
        lock = json.loads(source.read_text(encoding="utf-8"))
        lock["contract"] = {
            "path": "contracts/topology-v1.json",
            "sha256": runtime._sha256_file(CONTRACT_PATH),
            "revision": 3,
        }
        lock["topology_contract_lock"] = {
            "path": "requirements/topology-contract.lock.json",
            "sha256": runtime._sha256_file(runtime.TOPOLOGY_LOCK_PATH),
        }
        lock["implementation_lock"] = {
            "path": "requirements/topology-implementation.lock.json",
            "sha256": runtime._sha256_file(runtime.IMPLEMENTATION_LOCK_PATH),
        }
        lock["contract"]["sha256"] = "sha256:" + "f" * 64
        with tempfile.TemporaryDirectory(prefix="incidentseal-runtime-lock-test-") as temporary:
            path = Path(temporary) / "runtime.lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            with patch.object(runtime, "RUNTIME_LOCK_PATH", path):
                with self.assertRaises(TopologyError) as raised:
                    runtime._runtime_lock_images(runtime._sha256_file(CONTRACT_PATH))
        self.assertEqual("IS_RUNTIME_LOCK", raised.exception.code)

    def test_database_product_failure_uses_fail_verdict_and_exit(self) -> None:
        with patch("incidentseal.cli.database_probe", return_value={"verdict": "FAIL"}):
            envelope, exit_code = execute(["topology", "database-probe", "--mode", "platform-validation", "--json"])
        self.assertEqual(10, exit_code)
        self.assertEqual("succeeded", envelope["command_status"])
        self.assertEqual("FAIL", envelope["verdict"])

    def test_python_product_failure_uses_fail_verdict_and_exit(self) -> None:
        with patch("incidentseal.cli.python_probe", return_value={"verdict": "FAIL"}):
            envelope, exit_code = execute(["topology", "python-probe", "--mode", "platform-validation", "--json"])
        self.assertEqual(10, exit_code)
        self.assertEqual("succeeded", envelope["command_status"])
        self.assertEqual("FAIL", envelope["verdict"])

    def test_python_raw_compose_suppresses_transport_progress(self) -> None:
        completed = subprocess.CompletedProcess([], 0, "", "")
        with patch("incidentseal.python_surface.subprocess.run", return_value=completed) as run:
            python_surface._raw_compose(
                "docker",
                ["compose", "--ansi", "never"],
                {},
                ["run", "python-runner"],
            )
        self.assertEqual(
            ["docker", "compose", "--progress", "quiet", "--ansi", "never", "run", "python-runner"],
            run.call_args.args[0],
        )

    def test_python_completed_one_shots_are_removed_between_runs(self) -> None:
        names = ["migration", "python", "migration"]
        with patch("incidentseal.python_surface._run") as run:
            python_surface._remove_completed("docker", names)
        self.assertEqual([], names)
        self.assertEqual(
            [("docker", ["rm", "-f", "migration"]), ("docker", ["rm", "-f", "python"])],
            [call.args for call in run.call_args_list],
        )

    def test_non_platform_mode_is_rejected_before_docker(self) -> None:
        envelope, exit_code = execute(["topology", "validate", "--mode", "workflow-execution", "--json"])
        self.assertEqual(64, exit_code)
        self.assertEqual("IS_USAGE", envelope["errors"][0]["code"])

    def test_topology_command_rejects_manifest_argument(self) -> None:
        envelope, exit_code = execute(
            ["topology", "validate", "--mode", "platform-validation", "--manifest", "ignored.json", "--json"]
        )
        self.assertEqual(64, exit_code)
        self.assertEqual("IS_USAGE", envelope["errors"][0]["code"])

    @unittest.skipUnless(shutil.which("node"), "Node.js source self-test")
    def test_runner_self_tests_share_the_input_digest(self) -> None:
        commands = (
            [sys.executable, "-B", str(ROOT / "containers" / "python-runner" / "python_runner.py"), "--self-test"],
            ["node", str(ROOT / "containers" / "node-runner" / "node_runner.mjs"), "--self-test"],
        )
        results = []
        for command in commands:
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("", completed.stderr)
            results.append(json.loads(completed.stdout))
        self.assertEqual(results[0]["input_digest"], results[1]["input_digest"])
        self.assertEqual({"python", "node"}, {result["runner"] for result in results})
        self.assertTrue(all(result["database_verified"] is False for result in results))


if __name__ == "__main__":
    unittest.main()
