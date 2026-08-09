from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FIXTURES = ROOT / "fixtures" / "receipts"
EXPECTED = "sha256:7293ac4087873338dfbe78411c74c809efd18b2ffac0aa88e052df33d0353c77"


class ReceiptCliTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> tuple[subprocess.CompletedProcess[bytes], dict]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SRC) + os.pathsep + environment.get("PYTHONPATH", "")
        completed = subprocess.run(
            [sys.executable, "-m", "incidentseal", *arguments],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            check=False,
        )
        self.assertEqual(b"", completed.stderr)
        self.assertTrue(completed.stdout.endswith(b"\n"))
        self.assertEqual(1, completed.stdout.count(b"\n"))
        envelope = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, envelope["process_exit_code"])
        return completed, envelope

    def materialize(self, output: Path) -> tuple[dict, Path]:
        completed, envelope = self.run_cli(
            "receipt", "materialize",
            "--receipt", str(FIXTURES / "receipt.valid.json"),
            "--source-root", str(FIXTURES),
            "--output-root", str(output),
            "--json",
        )
        self.assertEqual(0, completed.returncode)
        self.assertEqual("PASS", envelope["verdict"])
        self.assertEqual(EXPECTED, envelope["data"]["receipt_digest"])
        return envelope, Path(envelope["data"]["bundle_path"])

    def test_atomic_materialize_is_idempotent_and_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="incidentseal-receipt-test-") as temporary:
            output = Path(temporary) / "output"
            first, bundle = self.materialize(output)
            self.assertTrue(first["data"]["created"])
            self.assertFalse(first["data"]["idempotent"])
            self.assertEqual(b'{"status":"PASS"}\n', (bundle / "artifacts" / "result.json").read_bytes())
            second, second_bundle = self.materialize(output)
            self.assertFalse(second["data"]["created"])
            self.assertTrue(second["data"]["idempotent"])
            self.assertEqual(bundle, second_bundle)
            self.assertEqual([], list(output.rglob("*.tmp")))

    def test_offline_verifier_preserves_identity_and_artifact_states(self) -> None:
        with tempfile.TemporaryDirectory(prefix="incidentseal-receipt-test-") as temporary:
            _written, bundle = self.materialize(Path(temporary) / "output")
            receipt = bundle / "receipt.json"
            artifact = bundle / "artifacts" / "result.json"
            before = {path.relative_to(bundle).as_posix(): path.read_bytes() for path in bundle.rglob("*") if path.is_file()}
            completed, exact = self.run_cli(
                "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle),
                "--expected-digest", EXPECTED, "--json",
            )
            self.assertEqual(0, completed.returncode)
            self.assertEqual("MATCH", exact["data"]["identity_status"])
            after = {path.relative_to(bundle).as_posix(): path.read_bytes() for path in bundle.rglob("*") if path.is_file()}
            self.assertEqual(before, after, "read-only verification changed bundle bytes")

            completed, unbound = self.run_cli(
                "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle), "--json",
            )
            self.assertEqual(11, completed.returncode)
            self.assertEqual("INCONCLUSIVE", unbound["verdict"])
            self.assertEqual("UNBOUND", unbound["data"]["identity_status"])

            completed, mismatch = self.run_cli(
                "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle),
                "--expected-digest", "sha256:" + "0" * 64, "--json",
            )
            self.assertEqual(12, completed.returncode)
            self.assertEqual("INVALID", mismatch["verdict"])

            artifact.write_bytes(b'{"status":"FAIL"}\n')
            completed, corrupt = self.run_cli(
                "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle),
                "--expected-digest", EXPECTED, "--json",
            )
            self.assertEqual(10, completed.returncode)
            self.assertEqual("FAIL", corrupt["verdict"])
            shutil.copyfile(FIXTURES / "artifacts" / "result.json", artifact)
            artifact.unlink()
            completed, missing = self.run_cli(
                "receipt", "verify", "--receipt", str(receipt), "--bundle-root", str(bundle),
                "--expected-digest", EXPECTED, "--json",
            )
            self.assertEqual(11, completed.returncode)
            self.assertEqual("INCONCLUSIVE", missing["verdict"])

    def test_missing_receipt_is_io_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="incidentseal-receipt-test-") as temporary:
            completed, envelope = self.run_cli(
                "receipt", "verify", "--receipt", str(Path(temporary) / "missing.json"),
                "--bundle-root", temporary, "--expected-digest", EXPECTED, "--json",
            )
            self.assertEqual(74, completed.returncode)
            self.assertEqual("IS_RECEIPT_READ", envelope["errors"][0]["code"])

    def test_materialize_rejects_repository_output_before_write(self) -> None:
        forbidden = ROOT / ".incidentseal-receipt-forbidden-test"
        self.assertFalse(forbidden.exists())
        completed, envelope = self.run_cli(
            "receipt", "materialize",
            "--receipt", str(FIXTURES / "receipt.valid.json"),
            "--source-root", str(FIXTURES),
            "--output-root", str(forbidden),
            "--json",
        )
        self.assertEqual(12, completed.returncode)
        self.assertEqual("IS_RECEIPT_CUSTODY", envelope["errors"][0]["code"])
        self.assertFalse(forbidden.exists())


if __name__ == "__main__":
    unittest.main()
