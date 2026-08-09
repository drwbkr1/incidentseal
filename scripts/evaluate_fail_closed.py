#!/usr/bin/env python3
"""Run the deterministic IncidentSeal IS2-U04 fail-closed scenario matrix."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterator


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FIXTURES = ROOT / "fixtures" / "contracts"
sys.path.insert(0, str(SRC))

from incidentseal.approval import (  # noqa: E402
    ApprovalStore,
    _windows_system_directory,
    default_approval_root,
    manifest_relative_path,
    repository_key,
)
from incidentseal.cli import execute  # noqa: E402
from incidentseal.manifest import ManifestError, load_manifest  # noqa: E402


NOW = datetime(2026, 8, 9, 12, 0, 0, tzinfo=UTC)
TRIALS = 2


class ScenarioContext:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.repository_root = base / "repository"
        self.repository_root.mkdir()
        (self.repository_root / ".git").mkdir()
        self.manifest_path = self.repository_root / "incidentseal.workflow.json"
        self.manifest_path.write_bytes((FIXTURES / "workflow.valid.minimal.json").read_bytes())
        self.approval_root = base / "operator-state" / "approvals" / "v1"

    def load(self, path: Path | None = None):
        return load_manifest(self.manifest_path if path is None else path)

    def approval(self) -> dict[str, Any]:
        value = json.loads((FIXTURES / "approval.valid.json").read_text(encoding="utf-8"))
        value["manifest_path"] = "incidentseal.workflow.json"
        return value

    def approval_path(
        self,
        document: Any,
        *,
        root: Path | None = None,
        directory_name: str | None = None,
        filename: str | None = None,
    ) -> Path:
        approval_root = self.approval_root if root is None else root
        remote = document.value["repository"]["remote"]
        directory = repository_key(remote) if directory_name is None else directory_name
        name = document.value["workflow_id"] + ".json" if filename is None else filename
        return approval_root / directory / name

    def write_approval(
        self,
        value: dict[str, Any] | bytes,
        document: Any,
        *,
        root: Path | None = None,
        directory_name: str | None = None,
        filename: str | None = None,
    ) -> Path:
        path = self.approval_path(
            document,
            root=root,
            directory_name=directory_name,
            filename=filename,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = value if isinstance(value, bytes) else (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
        path.write_bytes(raw)
        return path

    def inspect(
        self,
        document: Any,
        *,
        root: Path | None = None,
        repository_root: Path | None = None,
        forbidden_roots: tuple[Path, ...] = (),
        permission_checker: Callable[[Path], bool] | None = None,
    ):
        repo_root = self.repository_root if repository_root is None else repository_root
        relative = manifest_relative_path(document, repo_root)
        if relative is None:
            raise RuntimeError("scenario manifest is outside its repository")
        arguments: dict[str, Any] = {"forbidden_roots": forbidden_roots}
        if permission_checker is not None:
            arguments["permission_checker"] = permission_checker
        return ApprovalStore(self.approval_root if root is None else root, repo_root, **arguments).inspect(
            document,
            relative,
            now=NOW,
        )


@contextmanager
def scenario_context() -> Iterator[ScenarioContext]:
    with tempfile.TemporaryDirectory(prefix="incidentseal-u04-") as temporary:
        yield ScenarioContext(Path(temporary))


def _status_with_approval(mutate: Callable[[dict[str, Any]], None] | None = None) -> str:
    with scenario_context() as context:
        document = context.load()
        approval = context.approval()
        if mutate is not None:
            mutate(approval)
        context.write_approval(approval, document)
        return context.inspect(document).status


def exact_match() -> str:
    return _status_with_approval()


def reordered_format_match() -> str:
    with scenario_context() as context:
        context.manifest_path.write_bytes((FIXTURES / "workflow.valid.reordered.json").read_bytes())
        document = context.load()
        context.write_approval(context.approval(), document)
        return context.inspect(document).status


def semantic_policy_drift() -> str:
    with scenario_context() as context:
        approval_document = context.load()
        value = json.loads(context.manifest_path.read_text(encoding="utf-8"))
        value["claim"]["statement"] = "A changed release claim must not inherit approval."
        context.manifest_path.write_text(json.dumps(value), encoding="utf-8")
        changed = context.load()
        context.write_approval(context.approval(), approval_document)
        return context.inspect(changed).status


def repository_commit_drift() -> str:
    with scenario_context() as context:
        approved = context.load()
        value = json.loads(context.manifest_path.read_text(encoding="utf-8"))
        value["repository"]["commit"] = "3" * 40
        context.manifest_path.write_text(json.dumps(value), encoding="utf-8")
        changed = context.load()
        context.write_approval(context.approval(), approved)
        return context.inspect(changed).status


def manifest_path_drift() -> str:
    with scenario_context() as context:
        moved = context.repository_root / "nested" / "incidentseal.workflow.json"
        moved.parent.mkdir()
        moved.write_bytes(context.manifest_path.read_bytes())
        document = context.load(moved)
        context.write_approval(context.approval(), document)
        return context.inspect(document).status


def approval_digest_drift() -> str:
    return _status_with_approval(lambda approval: approval.__setitem__("manifest_digest", "sha256:" + "9" * 64))


def approval_remote_drift() -> str:
    return _status_with_approval(
        lambda approval: approval.__setitem__("repository_remote", "https://github.com/example/other.git")
    )


def expired_approval() -> str:
    return _status_with_approval(lambda approval: approval.__setitem__("expires_at_utc", "2026-08-09T01:00:00Z"))


def future_approval() -> str:
    return _status_with_approval(lambda approval: approval.__setitem__("approved_at_utc", "2026-08-10T00:00:00Z"))


def missing_approval() -> str:
    with scenario_context() as context:
        result = context.inspect(context.load())
        return result.status + (":NO_WRITE" if not context.approval_root.exists() else ":WROTE")


def malformed_approval() -> str:
    with scenario_context() as context:
        document = context.load()
        context.write_approval(b'{"schema_version":"wrong"}\n', document)
        return context.inspect(document).status


def repository_contained_store() -> str:
    with scenario_context() as context:
        document = context.load()
        root = context.repository_root / ".incidentseal" / "approvals"
        result = context.inspect(document, root=root)
        return result.status + (":NO_WRITE" if not root.exists() else ":WROTE")


def forbidden_root_overlap() -> str:
    with scenario_context() as context:
        document = context.load()
        result = context.inspect(document, forbidden_roots=(context.base / "operator-state",))
        return result.status


def unverified_permissions() -> str:
    with scenario_context() as context:
        document = context.load()
        context.write_approval(context.approval(), document)
        return context.inspect(document, permission_checker=lambda _path: False).status


def case_ambiguous_directory() -> str:
    with scenario_context() as context:
        document = context.load()
        directory = repository_key(document.value["repository"]["remote"]).upper()
        context.write_approval(context.approval(), document, directory_name=directory)
        return context.inspect(document).status


def case_ambiguous_filename() -> str:
    with scenario_context() as context:
        document = context.load()
        filename = (document.value["workflow_id"] + ".json").upper()
        context.write_approval(context.approval(), document, filename=filename)
        return context.inspect(document).status


def junction_approval_root() -> str:
    if os.name != "nt":
        return "NOT_APPLICABLE"
    with scenario_context() as context:
        target = context.base / "junction-target"
        target.mkdir()
        junction = context.base / "approval-junction"
        cmd = _windows_system_directory() / "cmd.exe"
        completed = subprocess.run(
            [str(cmd), "/d", "/c", "mklink", "/J", str(junction), str(target)],
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            return "PROBE_UNAVAILABLE"
        try:
            return context.inspect(context.load(), root=junction).status
        finally:
            os.rmdir(junction)


def manifest_error_fixture(name: str) -> str:
    try:
        load_manifest(FIXTURES / name)
    except ManifestError as error:
        return "INVALID:" + error.code
    return "ACCEPTED"


def network_policy_drift() -> str:
    return manifest_error_fixture("workflow.invalid.network.json")


def duplicate_key_manifest() -> str:
    return manifest_error_fixture("workflow.invalid.duplicate-key.json")


def float_manifest() -> str:
    return manifest_error_fixture("workflow.invalid.float.json")


def bom_manifest() -> str:
    with scenario_context() as context:
        context.manifest_path.write_bytes(b"\xef\xbb\xbf" + context.manifest_path.read_bytes())
        try:
            context.load()
        except ManifestError as error:
            return "INVALID:" + error.code
        return "ACCEPTED"


def authority_mutation_attempt() -> str:
    envelope, exit_code = execute(
        [
            "operator",
            "approve-manifest",
            "--manifest",
            str(FIXTURES / "workflow.valid.minimal.json"),
            "--json",
        ]
    )
    return f"{envelope['errors'][0]['code']}:{exit_code}"


def approval_root_override_attempt() -> str:
    envelope, exit_code = execute(
        [
            "policy",
            "status",
            "--manifest",
            str(FIXTURES / "workflow.valid.minimal.json"),
            "--approval-root",
            str(FIXTURES),
            "--json",
        ]
    )
    return f"{envelope['errors'][0]['code']}:{exit_code}"


def default_store_missing_read_only() -> str:
    root = default_approval_root()
    before = root.exists()
    envelope, exit_code = execute(
        ["policy", "status", "--manifest", str(FIXTURES / "workflow.valid.minimal.json"), "--json"]
    )
    after = root.exists()
    return f"{envelope['policy']['approval_status']}:{exit_code}:{before}:{after}"


def windows_environment_shadow_attempt() -> str:
    if os.name != "nt":
        return "NOT_APPLICABLE"
    actual = default_approval_root()
    prior_local = os.environ.get("LOCALAPPDATA")
    prior_path = os.environ.get("PATH")
    try:
        os.environ["LOCALAPPDATA"] = str(ROOT)
        os.environ["PATH"] = str(ROOT)
        return "STABLE" if default_approval_root() == actual else "REDIRECTED"
    finally:
        if prior_local is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = prior_local
        if prior_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = prior_path


SCENARIOS: tuple[tuple[str, str, Callable[[], str]], ...] = (
    ("exact-approval", "MATCH", exact_match),
    ("reordered-format", "MATCH", reordered_format_match),
    ("semantic-policy-drift", "MISMATCH", semantic_policy_drift),
    ("repository-commit-drift", "MISMATCH", repository_commit_drift),
    ("manifest-path-drift", "MISMATCH", manifest_path_drift),
    ("approval-digest-drift", "MISMATCH", approval_digest_drift),
    ("approval-remote-drift", "MISMATCH", approval_remote_drift),
    ("expired-approval", "EXPIRED", expired_approval),
    ("future-approval", "INVALID", future_approval),
    ("missing-approval", "MISSING:NO_WRITE", missing_approval),
    ("malformed-approval", "INVALID", malformed_approval),
    ("repository-contained-store", "INVALID:NO_WRITE", repository_contained_store),
    ("forbidden-root-overlap", "INVALID", forbidden_root_overlap),
    ("unverified-permissions", "INVALID", unverified_permissions),
    ("case-ambiguous-directory", "INVALID", case_ambiguous_directory),
    ("case-ambiguous-filename", "INVALID", case_ambiguous_filename),
    ("junction-approval-root", "INVALID" if os.name == "nt" else "NOT_APPLICABLE", junction_approval_root),
    ("network-policy-drift", "INVALID:IS_MANIFEST_SCHEMA", network_policy_drift),
    ("duplicate-key-manifest", "INVALID:IS_MANIFEST_DUPLICATE_KEY", duplicate_key_manifest),
    ("float-manifest", "INVALID:IS_MANIFEST_NUMBER_DOMAIN", float_manifest),
    ("bom-manifest", "INVALID:IS_MANIFEST_ENCODING", bom_manifest),
    (
        "authority-mutation-attempt",
        "IS_AUTHORITY_MUTATION_FORBIDDEN:77",
        authority_mutation_attempt,
    ),
    ("approval-root-override-attempt", "IS_USAGE:64", approval_root_override_attempt),
    ("default-store-read-only", "MISSING:12:False:False", default_store_missing_read_only),
    ("windows-environment-shadow", "STABLE" if os.name == "nt" else "NOT_APPLICABLE", windows_environment_shadow_attempt),
)


def main() -> int:
    results: list[dict[str, Any]] = []
    all_passed = True
    for scenario_id, expected, function in SCENARIOS:
        observed: list[str] = []
        for _trial in range(TRIALS):
            try:
                observed.append(function())
            except Exception as error:
                observed.append("ERROR:" + type(error).__name__)
        passed = observed == [expected] * TRIALS
        all_passed = all_passed and passed
        results.append(
            {
                "id": scenario_id,
                "expected": expected,
                "observed": observed,
                "status": "PASS" if passed else "FAIL",
            }
        )
    output = {
        "schema_version": "incidentseal-fail-closed-evaluation/v1",
        "observed_at_utc": datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "PASS" if all_passed else "FAIL",
        "scenario_count": len(results),
        "trials_per_scenario": TRIALS,
        "execution_count": len(results) * TRIALS,
        "real_approval_created": False,
        "third_party_dependencies": 0,
        "scenarios": results,
    }
    print(json.dumps(output, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
