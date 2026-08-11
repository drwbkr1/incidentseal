"""Host-owned execution of one externally approved, bounded workflow."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from .approval import ApprovalResult, default_approval_root, find_repository_root, inspect_document, permissions_restrictive
from .journal import JournalError, lifecycle_exit, validate_event, validate_run_id
from .manifest import ManifestDocument, ManifestError, canonical_bytes, strict_load_bytes
from .topology import CONTRACT_PATH, ROOT, _docker_executable, _sha256_file


CONTRACT_PATH_WORKFLOW = ROOT / "fixtures" / "workflow-verification" / "execution-contract.valid.json"
RUNTIME_LOCK_PATH = ROOT / "requirements" / "topology-runtime.lock.json"
MAX_FILES = 4096
MAX_BYTES = 104_857_600
ENVIRONMENT = {
    "HOME": "/tmp/home",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "TZ": "UTC",
}
ENTRYPOINTS = {"python": "/usr/bin/python", "node": "/nodejs/bin/node"}
IMAGE_ROLES = {"python": "python-runner", "node": "node-runner"}
SHA_RE = __import__("re").compile(r"^sha256:[0-9a-f]{64}$")


class WorkflowError(ValueError):
    """A stable, fail-closed workflow rejection or runtime failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int = 12,
        verdict: str | None = "INVALID",
        lifecycle: str | None = None,
        retriable: bool = False,
        data: dict[str, Any] | None = None,
        evidence: list[dict[str, str]] | None = None,
        policy: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        self.verdict = verdict
        self.lifecycle = lifecycle
        self.retriable = retriable
        self.data = data or {}
        self.evidence = evidence or []
        self.policy = policy


@dataclass(frozen=True)
class RepositorySnapshot:
    root: Path
    remote: str
    commit: str
    tree_digest: str
    entries: dict[str, tuple[str, str, str]]
    selected: tuple[str, ...]
    total_bytes: int


@dataclass(frozen=True)
class WorkflowOutcome:
    exit_code: int
    verdict: str | None
    lifecycle: str
    policy: dict[str, Any]
    data: dict[str, Any]
    evidence: list[dict[str, str]]


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(root: Path, arguments: list[str], *, binary: bool = False) -> bytes | str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkflowError("IS_WORKFLOW_GIT", "Git repository inspection could not execute", exit_code=74, verdict=None, retriable=True) from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip().splitlines()
        raise WorkflowError("IS_WORKFLOW_GIT", (detail[-1] if detail else "Git repository inspection failed")[:1000])
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise WorkflowError("IS_WORKFLOW_GIT", "Git repository metadata is not UTF-8") from error


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def _is_onedrive(path: Path) -> bool:
    return any(part.casefold().startswith("onedrive") for part in path.resolve(strict=False).parts)


def _has_reparse_or_symlink(path: Path) -> bool:
    try:
        information = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(information.st_mode):
        return True
    return bool(getattr(information, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _paths_overlap(left: str, right: str) -> bool:
    a = PurePosixPath(left)
    b = PurePosixPath(right)
    return a == b or a in b.parents or b in a.parents


def _parse_tree(raw: bytes) -> dict[str, tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            header, encoded_path = item.split(b"\t", 1)
            mode_raw, kind_raw, object_raw = header.split(b" ", 2)
            path = encoded_path.decode("utf-8", errors="strict")
            mode = mode_raw.decode("ascii")
            kind = kind_raw.decode("ascii")
            object_id = object_raw.decode("ascii")
        except (ValueError, UnicodeDecodeError) as error:
            raise WorkflowError("IS_WORKFLOW_TREE", "Git tree encoding is invalid") from error
        if path in entries or not path or path.startswith("/") or "\\" in path or ".." in PurePosixPath(path).parts:
            raise WorkflowError("IS_WORKFLOW_TREE", "Git tree path is invalid or duplicated")
        if len(object_id) not in {40, 64} or any(character not in "0123456789abcdef" for character in object_id):
            raise WorkflowError("IS_WORKFLOW_TREE", "Git tree object identity is invalid")
        entries[path] = (mode, kind, object_id)
    return entries


def _selected_inputs(document: ManifestDocument, entries: dict[str, tuple[str, str, str]]) -> tuple[tuple[str, ...], int]:
    declared: list[str] = []
    for step in document.value["steps"]:
        if step["runner"] not in ENTRYPOINTS:
            raise WorkflowError("IS_WORKFLOW_RUNNER", f"unsupported v1 runner: {step['runner']}")
        if step["command"][0] != step["runner"]:
            raise WorkflowError("IS_WORKFLOW_COMMAND", f"step {step['id']} command must begin with its runner name")
        if step["runner"] == "python":
            arguments = step["command"][1:]
            if not arguments or (arguments[0] in {"-m", "-c"} and len(arguments) < 2) or (arguments[0].startswith("-") and arguments[0] not in {"-m", "-c"}):
                raise WorkflowError("IS_WORKFLOW_COMMAND", f"step {step['id']} uses an unsupported Python v1 argument profile")
        if step["outputs"]:
            raise WorkflowError("IS_WORKFLOW_OUTPUTS", "persistent outputs are unsupported in workflow v1")
        declared.extend(step["inputs"])
    unique = sorted(set(declared))
    for index, left in enumerate(unique):
        for right in unique[index + 1 :]:
            if _paths_overlap(left, right):
                raise WorkflowError("IS_WORKFLOW_INPUT_OVERLAP", "declared workflow inputs overlap")
    selected: set[str] = set()
    for declared_path in unique:
        matches = [path for path in entries if path == declared_path or path.startswith(declared_path + "/")]
        if not matches:
            raise WorkflowError("IS_WORKFLOW_INPUT_MISSING", f"declared input is absent from the exact commit: {declared_path}")
        selected.update(matches)
    total = 0
    for path in sorted(selected):
        mode, kind, _ = entries[path]
        if mode not in {"100644", "100755"} or kind != "blob":
            label = "symlink" if mode == "120000" else "submodule" if mode == "160000" else "non-regular file"
            raise WorkflowError("IS_WORKFLOW_INPUT_TYPE", f"declared input includes a denied {label}: {path}")
        try:
            size_text = _git(find_repository_root(document.path) or document.path.parent, ["cat-file", "-s", entries[path][2]])
            total += int(str(size_text))
        except (TypeError, ValueError) as error:
            raise WorkflowError("IS_WORKFLOW_TREE", "Git blob size is invalid") from error
    if len(selected) > MAX_FILES or total > MAX_BYTES:
        raise WorkflowError("IS_WORKFLOW_INPUT_LIMIT", "declared workflow input exceeds the v1 staging limit")
    return tuple(sorted(selected)), total


def inspect_repository(document: ManifestDocument) -> RepositorySnapshot:
    """Bind a manifest to one clean, exact Git tree without Docker access."""

    root = find_repository_root(document.path)
    if root is None:
        raise WorkflowError("IS_WORKFLOW_REPOSITORY", "manifest is not inside a Git worktree")
    if _is_onedrive(root):
        raise WorkflowError("IS_WORKFLOW_REPOSITORY", "OneDrive repository custody is denied")
    remote = str(_git(root, ["remote", "get-url", "origin"]))
    commit = str(_git(root, ["rev-parse", "HEAD"]))
    if remote != document.value["repository"]["remote"]:
        raise WorkflowError("IS_WORKFLOW_REMOTE", "repository origin differs from the approved manifest")
    if commit != document.value["repository"]["commit"]:
        raise WorkflowError("IS_WORKFLOW_COMMIT", "repository HEAD differs from the approved manifest")
    status = str(_git(root, ["status", "--porcelain=v1", "--untracked-files=normal"]))
    if status:
        raise WorkflowError("IS_WORKFLOW_DIRTY", "repository worktree is not clean")
    raw = _git(root, ["ls-tree", "-r", "-z", "--full-tree", commit], binary=True)
    assert isinstance(raw, bytes)
    tree_digest = _digest(raw)
    if tree_digest != document.value["repository"]["tree_digest"]:
        raise WorkflowError("IS_WORKFLOW_TREE_DIGEST", "repository tree digest differs from the approved manifest")
    entries = _parse_tree(raw)
    for path, (mode, kind, _) in entries.items():
        if mode not in {"100644", "100755"} or kind != "blob":
            label = "symlink" if mode == "120000" else "submodule" if mode == "160000" else "non-regular file"
            raise WorkflowError("IS_WORKFLOW_INPUT_TYPE", f"repository tree includes a denied {label}: {path}")
    selected, total = _selected_inputs(document, entries)
    for step in document.value["steps"]:
        cwd = step["cwd"]
        if cwd != "." and not any(path == cwd or path.startswith(cwd + "/") for path in selected):
            raise WorkflowError("IS_WORKFLOW_CWD", f"step cwd is absent from staged inputs: {step['id']}")
    return RepositorySnapshot(root, remote, commit, tree_digest, entries, selected, total)


def _policy(document: ManifestDocument, approval: ApprovalResult) -> dict[str, Any]:
    return {
        "workflow_id": document.value["workflow_id"],
        "manifest_digest": document.digest,
        "approved_digest": approval.approved_digest,
        "approval_status": approval.status,
    }


def require_approval(
    document: ManifestDocument,
    inspector: Callable[[ManifestDocument], ApprovalResult] = inspect_document,
) -> ApprovalResult:
    result = inspector(document)
    if not result.approved:
        raise WorkflowError(
            result.error_code or "IS_APPROVAL_INVALID",
            result.message or "approval is invalid",
            policy=_policy(document, result),
            evidence=result.evidence(),
            data={"approved": False, "differences": list(result.differences)},
        )
    return result


def preflight_workflow(
    document: ManifestDocument,
    *,
    approval_inspector: Callable[[ManifestDocument], ApprovalResult] = inspect_document,
) -> tuple[ApprovalResult, RepositorySnapshot]:
    """Fail closed on authority and exact-source policy before Docker access."""

    approval = require_approval(document, approval_inspector)
    return approval, inspect_repository(document)


def default_run_root() -> Path:
    approval_root = default_approval_root()
    return approval_root.parents[1] / "runs" / "v1"


def _runtime_images() -> dict[str, str]:
    try:
        value = strict_load_bytes(RUNTIME_LOCK_PATH.read_bytes())
        images = {item["role"]: item["image_id"] for item in value["images"]}
        selected = {runner: images[role] for runner, role in IMAGE_ROLES.items()}
    except (OSError, KeyError, TypeError, ManifestError) as error:
        raise WorkflowError("IS_WORKFLOW_RUNTIME_LOCK", "exact runner image lock is unavailable or invalid") from error
    if any(not isinstance(item, str) or SHA_RE.fullmatch(item) is None for item in selected.values()):
        raise WorkflowError("IS_WORKFLOW_RUNTIME_LOCK", "runner image identity is invalid")
    return selected


def _stage(snapshot: RepositorySnapshot, destination: Path) -> None:
    destination.mkdir(parents=True, mode=0o700)
    if _has_reparse_or_symlink(destination):
        raise WorkflowError("IS_WORKFLOW_STAGING", "staging root is a symlink or reparse point")
    written = 0
    for path in snapshot.selected:
        mode, _, object_id = snapshot.entries[path]
        raw = _git(snapshot.root, ["cat-file", "blob", object_id], binary=True)
        assert isinstance(raw, bytes)
        written += len(raw)
        if written > MAX_BYTES:
            raise WorkflowError("IS_WORKFLOW_INPUT_LIMIT", "staged bytes exceed the preflight identity")
        target = destination.joinpath(*PurePosixPath(path).parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        current = target.parent
        while current != destination.parent:
            if _has_reparse_or_symlink(current):
                raise WorkflowError("IS_WORKFLOW_STAGING", "staging path contains a symlink or reparse point")
            current = current.parent
        if _inside(target, snapshot.root) or _is_onedrive(target):
            raise WorkflowError("IS_WORKFLOW_STAGING", "staging entered denied custody")
        with target.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        target.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH if mode == "100755" else 0))
    if written != snapshot.total_bytes:
        raise WorkflowError("IS_WORKFLOW_STAGING", "staged byte count differs from preflight")


def _canonical_file(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = strict_load_bytes(raw)
    except (OSError, ManifestError) as error:
        raise WorkflowError("IS_WORKFLOW_EVIDENCE", "retained workflow evidence is unreadable", exit_code=74, verdict=None, retriable=True) from error
    if canonical_bytes(value) != raw:
        raise WorkflowError("IS_WORKFLOW_EVIDENCE", "retained workflow evidence is not canonical")
    return value


class RunArchive:
    """Internal-only append writer for one externally held workflow attempt."""

    def __init__(self, root: Path, run_id: str, document: ManifestDocument, approval: ApprovalResult) -> None:
        self.root = root
        self.run_id = validate_run_id(run_id)
        self.document = document
        self.approval = approval
        self.run_dir = root / "runs" / run_id
        self.events_path = self.run_dir / "events.jsonl"
        self.records = self.run_dir / "records"
        self.sequence = 0

    def create(self) -> None:
        self.run_dir.mkdir(parents=True, mode=0o700)
        self.records.mkdir(mode=0o700)
        self.events_path.open("xb").close()

    def resume(self) -> list[dict[str, Any]]:
        events = read_archive_events(self.root, self.run_id)[0]
        self.sequence = len(events)
        return [strict_load_bytes(raw) for raw in events]

    def append(
        self,
        event_type: str,
        lifecycle: str,
        *,
        verdict: str | None = None,
        payload: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = {
            "schema_version": "incidentseal-run-event/v1",
            "event_id": str(uuid.uuid4()),
            "run_id": self.run_id,
            "sequence": self.sequence,
            "occurred_at_utc": _timestamp(),
            "event_type": event_type,
            "lifecycle": lifecycle,
            "verdict": verdict,
            "terminal": lifecycle in {"completed", "cancelled", "failed", "stale", "superseded"},
            "manifest_digest": self.document.digest,
            "approval_digest": self.approval.approved_digest,
            "payload": payload or {},
            "error": error,
        }
        validate_event(event)
        raw = canonical_bytes(event)
        with self.events_path.open("ab", buffering=0) as stream:
            stream.write(raw + b"\n")
            os.fsync(stream.fileno())
        self.sequence += 1
        return event

    def write_record(self, value: dict[str, Any]) -> tuple[Path, str]:
        raw = canonical_bytes(value)
        digest = _digest(raw)
        path = self.records / f"{digest.split(':', 1)[1]}.json"
        try:
            with path.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            if path.read_bytes() != raw:
                raise WorkflowError("IS_WORKFLOW_EVIDENCE", "content-addressed evidence collision")
        return path, digest


def _capture(raw: bytes, mode: str, maximum: int) -> dict[str, Any]:
    if len(raw) > maximum:
        raise WorkflowError("IS_WORKFLOW_CAPTURE_LIMIT", "step output exceeded the approved capture limit", exit_code=11, verdict="INCONCLUSIVE")
    result: dict[str, Any] = {"mode": mode, "byte_count": len(raw), "digest": _digest(raw), "encoding": None, "content": None}
    if mode == "full":
        result["encoding"] = "base64"
        result["content"] = base64.b64encode(raw).decode("ascii")
    elif mode == "none":
        result["digest"] = None
    return result


def _bootstrap(runner: str, command: list[str]) -> tuple[str, list[str]]:
    executable = ENTRYPOINTS[runner]
    target = [executable, *command[1:]]
    if runner == "python":
        source = (
            "import json,os,runpy,sys\n"
            "a=json.loads(os.environ['INCIDENTSEAL_ARGV'])\n"
            "e={k:os.environ[k] for k in ('HOME','PYTHONDONTWRITEBYTECODE','PYTHONHASHSEED','TZ')}\n"
            "os.environ.clear();os.environ.update(e)\n"
            "args=a[1:]\n"
            "if args[0]=='-m':\n"
            " sys.argv=[args[1],*args[2:]];runpy.run_module(args[1],run_name='__main__',alter_sys=True)\n"
            "elif args[0]=='-c':\n"
            " sys.argv=['-c',*args[2:]];scope={'__name__':'__main__','__file__':'<string>','__builtins__':__builtins__};exec(compile(args[1],'<string>','exec'),scope,scope)\n"
            "else:\n"
            " sys.argv=args;runpy.run_path(args[0],run_name='__main__')\n"
        )
        return executable, ["-c", source]
    source = "const c=require('node:child_process'),a=JSON.parse(process.env.INCIDENTSEAL_ARGV),e={HOME:process.env.HOME,PYTHONDONTWRITEBYTECODE:process.env.PYTHONDONTWRITEBYTECODE,PYTHONHASHSEED:process.env.PYTHONHASHSEED,TZ:process.env.TZ};const r=c.spawnSync(a[0],a.slice(1),{stdio:'inherit',env:e,shell:false});process.exit(r.status===null?125:r.status)"
    return executable, ["-e", source]


def _docker_call(docker: str, arguments: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run([docker, *arguments], capture_output=True, check=False, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkflowError("IS_WORKFLOW_DOCKER", "host Docker command could not execute", exit_code=21, verdict=None, lifecycle="failed", retriable=True) from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode("utf-8", errors="replace").strip().splitlines()
        raise WorkflowError("IS_WORKFLOW_DOCKER", (detail[-1] if detail else "Docker command failed")[:1000], exit_code=21, verdict=None, lifecycle="failed")
    return completed


def _container_candidates(docker: str, run_id: str) -> list[str]:
    output = _docker_call(docker, ["ps", "-aq", "--no-trunc", "--filter", f"label=dev.incidentseal.workflow-run={run_id}"]).stdout
    return [line.decode("ascii") for line in output.splitlines() if line]


def _recover_exact_container(
    docker: str,
    archive: RunArchive,
    candidates: list[str],
    prior_events: list[dict[str, Any]],
    document: ManifestDocument,
    snapshot: RepositorySnapshot,
    images: dict[str, str],
) -> str | None:
    """Reobserve and remove one exact interrupted step, or classify ambiguity."""

    if not candidates:
        return None
    open_step: dict[str, Any] | None = None
    for event in prior_events:
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if event.get("event_type") == "step.started":
            open_step = payload
        elif event.get("event_type") in {"step.completed", "step.failed"} and open_step is not None and payload.get("step_id") == open_step.get("step_id"):
            open_step = None
    if open_step is None:
        return "unknown"
    step = next((item for item in document.value["steps"] if item["id"] == open_step.get("step_id")), None)
    if step is None:
        return "unknown"
    image_id = images[step["runner"]]
    expected_labels = {
        "dev.incidentseal.workflow-run": archive.run_id,
        "dev.incidentseal.workflow-step": step["id"],
        "dev.incidentseal.manifest-digest": document.digest,
        "dev.incidentseal.workflow-contract": _sha256_file(CONTRACT_PATH_WORKFLOW),
        "dev.incidentseal.runtime-image": image_id,
    }
    exact_values: list[dict[str, Any]] = []
    for candidate in candidates:
        try:
            value = json.loads(_docker_call(docker, ["inspect", candidate]).stdout)[0]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError):
            continue
        config = value.get("Config") or {}
        host = value.get("HostConfig") or {}
        labels = config.get("Labels") or {}
        mounts = value.get("Mounts") or []
        source = Path(mounts[0].get("Source", "")).resolve(strict=False) if len(mounts) == 1 else snapshot.root
        exact_mount = (
            len(mounts) == 1
            and mounts[0].get("Type") == "bind"
            and mounts[0].get("Destination") == "/workspace"
            and mounts[0].get("RW") is False
            and source.exists()
            and not _inside(source, snapshot.root)
            and not _is_onedrive(source)
        )
        if all(
            [
                value.get("Id") == candidate,
                value.get("Image") == image_id,
                config.get("User") == "65532:65532",
                all(labels.get(key) == expected for key, expected in expected_labels.items()),
                host.get("NetworkMode") == "none",
                host.get("ReadonlyRootfs") is True,
                host.get("Privileged") is False,
                "ALL" in (host.get("CapDrop") or []),
                any(item in {"no-new-privileges", "no-new-privileges:true"} for item in (host.get("SecurityOpt") or [])),
                host.get("PidsLimit") == 64,
                host.get("Memory") == 536870912,
                exact_mount,
            ]
        ):
            exact_values.append(value)
    if len(exact_values) > 1:
        return "conflicting"
    if len(exact_values) != 1 or exact_values[0].get("Id") != open_step.get("container_id"):
        return "unknown"
    value = exact_values[0]
    container_id = value["Id"]
    if (value.get("State") or {}).get("Running") is True:
        _docker_call(docker, ["stop", "--time", "1", container_id])
    _docker_call(docker, ["rm", "--force", container_id])
    archive.append(
        "step.failed",
        "running",
        payload={"step_id": step["id"], "container_id": container_id, "reason": "exact-interrupted-runtime-reobserved"},
        error={"code": "IS_WORKFLOW_STEP_INTERRUPTED", "message": "exact interrupted runtime was reobserved before safe replay", "retriable": True},
    )
    return "replay"


def _verify_container(
    value: dict[str, Any],
    *,
    run_id: str,
    step: dict[str, Any],
    manifest_digest: str,
    image_id: str,
    stage: Path,
    bootstrap: list[str],
) -> None:
    config = value.get("Config") or {}
    host = value.get("HostConfig") or {}
    labels = config.get("Labels") or {}
    expected_labels = {
        "dev.incidentseal.workflow-run": run_id,
        "dev.incidentseal.workflow-step": step["id"],
        "dev.incidentseal.manifest-digest": manifest_digest,
        "dev.incidentseal.workflow-contract": _sha256_file(CONTRACT_PATH_WORKFLOW),
        "dev.incidentseal.runtime-image": image_id,
    }
    mounts = value.get("Mounts") or []
    exact_mount = len(mounts) == 1 and mounts[0].get("Type") == "bind" and mounts[0].get("Destination") == "/workspace" and mounts[0].get("RW") is False and Path(mounts[0].get("Source", "")).resolve(strict=False) == stage.resolve(strict=False)
    environment_names = {item.split("=", 1)[0] for item in (config.get("Env") or [])}
    allowed_environment_names = {"PATH", "SSL_CERT_FILE", "INCIDENTSEAL_ARGV", *ENVIRONMENT}
    tmpfs = host.get("Tmpfs") or {}
    tmpfs_options = set(str(tmpfs.get("/tmp", "")).split(","))
    expected_workdir = f"/workspace/{step['cwd']}" if step["cwd"] != "." else "/workspace"
    if not all(
        [
            value.get("Image") == image_id,
            config.get("User") == "65532:65532",
            config.get("Entrypoint") == [ENTRYPOINTS[step["runner"]]],
            config.get("Cmd") == bootstrap,
            config.get("WorkingDir") == expected_workdir,
            environment_names == allowed_environment_names,
            all(labels.get(key) == expected for key, expected in expected_labels.items()),
            host.get("NetworkMode") == "none",
            host.get("ReadonlyRootfs") is True,
            host.get("Privileged") is False,
            "ALL" in (host.get("CapDrop") or []),
            any(item in {"no-new-privileges", "no-new-privileges:true"} for item in (host.get("SecurityOpt") or [])),
            host.get("PidsLimit") == 64,
            host.get("Memory") == 536870912,
            tmpfs_options == {"size=67108864", "mode=0700", "uid=65532", "gid=65532"},
            exact_mount,
        ]
    ):
        raise WorkflowError("IS_WORKFLOW_RUNTIME_IDENTITY", "created workflow container differs from the approved isolation contract")


def _run_step(
    docker: str,
    archive: RunArchive,
    document: ManifestDocument,
    step: dict[str, Any],
    stage: Path,
    image_id: str,
) -> tuple[dict[str, Any], int]:
    run_id = archive.run_id
    name = f"incidentseal-workflow-{run_id[:8]}-{step['id']}"
    entrypoint, bootstrap = _bootstrap(step["runner"], step["command"])
    target = [ENTRYPOINTS[step["runner"]], *step["command"][1:]]
    arguments = [
        "create", "--name", name,
        "--label", f"dev.incidentseal.workflow-run={run_id}",
        "--label", f"dev.incidentseal.workflow-step={step['id']}",
        "--label", f"dev.incidentseal.manifest-digest={document.digest}",
        "--label", f"dev.incidentseal.workflow-contract={_sha256_file(CONTRACT_PATH_WORKFLOW)}",
        "--label", f"dev.incidentseal.runtime-image={image_id}",
        "--network", "none", "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "536870912",
        "--mount", f"type=bind,source={stage},target=/workspace,readonly",
        "--tmpfs", "/tmp:size=67108864,mode=0700,uid=65532,gid=65532",
        "--workdir", f"/workspace/{step['cwd']}" if step["cwd"] != "." else "/workspace",
        "--entrypoint", entrypoint,
    ]
    for key, value in ENVIRONMENT.items():
        arguments.extend(["--env", f"{key}={value}"])
    arguments.extend(["--env", "INCIDENTSEAL_ARGV=" + json.dumps(target, separators=(",", ":"))])
    arguments.extend([image_id, *bootstrap])
    container_id = _docker_call(docker, arguments).stdout.decode("ascii").strip()
    try:
        inspected = json.loads(_docker_call(docker, ["inspect", container_id]).stdout)[0]
        _verify_container(
            inspected,
            run_id=run_id,
            step=step,
            manifest_digest=document.digest,
            image_id=image_id,
            stage=stage,
            bootstrap=bootstrap,
        )
        archive.append("step.started", "running", payload={"step_id": step["id"], "container_id": container_id, "image_id": image_id})
        try:
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                process = subprocess.Popen([docker, "start", "--attach", container_id], stdout=stdout_file, stderr=stderr_file)
                deadline = time.monotonic() + step["timeout_seconds"]
                while process.poll() is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        _docker_call(docker, ["stop", "--time", "1", container_id])
                        process.wait(timeout=10)
                        break
                    try:
                        process.wait(timeout=min(0.2, remaining))
                    except subprocess.TimeoutExpired:
                        continue
                exit_code = process.returncode if process.returncode is not None else 124
                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout = stdout_file.read(step["capture"]["max_bytes"] + 1)
                stderr = stderr_file.read(step["capture"]["max_bytes"] + 1)
        except OSError as error:
            raise WorkflowError("IS_WORKFLOW_DOCKER", "workflow container attach failed", exit_code=21, verdict=None, lifecycle="failed", retriable=True) from error
        wait_value = json.loads(_docker_call(docker, ["inspect", "--format", "{{json .State}}", container_id]).stdout)
        observed_exit = wait_value.get("ExitCode")
        if not isinstance(observed_exit, int) or observed_exit != exit_code:
            raise WorkflowError("IS_WORKFLOW_RUNTIME_IDENTITY", "container exit evidence differs")
        record = {
            "schema_version": "incidentseal-workflow-step-record/v1",
            "run_id": run_id,
            "step_id": step["id"],
            "runner": step["runner"],
            "image_id": image_id,
            "command": step["command"],
            "container_id": container_id,
            "exit_code": exit_code,
            "expected_exit_codes": step["expected_exit_codes"],
            "stdout": _capture(stdout, step["capture"]["stdout"], step["capture"]["max_bytes"]),
            "stderr": _capture(stderr, step["capture"]["stderr"], step["capture"]["max_bytes"]),
        }
        path, digest = archive.write_record(record)
        return {"step_id": step["id"], "record_path": str(path), "record_digest": digest, "exit_code": exit_code}, exit_code
    finally:
        _docker_call(docker, ["rm", "--force", container_id])


def _active_key(document: ManifestDocument, snapshot: RepositorySnapshot) -> str:
    return _digest(canonical_bytes({
        "schema_version": "incidentseal-workflow-active-key/v1",
        "repository_remote": snapshot.remote,
        "workflow_id": document.value["workflow_id"],
        "manifest_digest": document.digest,
        "commit": snapshot.commit,
        "tree_digest": snapshot.tree_digest,
    })).split(":", 1)[1]


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    raw = canonical_bytes(value)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _state_root(root: Path, repository: Path, permission_checker: Callable[[Path], bool]) -> Path:
    resolved = root.expanduser().resolve(strict=False)
    if _inside(resolved, repository) or _inside(repository, resolved) or _is_onedrive(resolved):
        raise WorkflowError("IS_WORKFLOW_EVIDENCE_CUSTODY", "workflow state root overlaps denied custody")
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    (resolved / "runs").mkdir(exist_ok=True, mode=0o700)
    (resolved / "active").mkdir(exist_ok=True, mode=0o700)
    if not permission_checker(resolved):
        raise WorkflowError("IS_WORKFLOW_EVIDENCE_CUSTODY", "workflow state root permissions are not restrictive")
    return resolved


def execute_workflow(
    document: ManifestDocument,
    *,
    approval_inspector: Callable[[ManifestDocument], ApprovalResult] = inspect_document,
    run_root: Path | None = None,
    permission_checker: Callable[[Path], bool] = permissions_restrictive,
    docker_executable: Callable[[], str] = _docker_executable,
) -> WorkflowOutcome:
    """Execute or resume one exact approved attempt and retain its terminal truth."""

    approval, snapshot = preflight_workflow(document, approval_inspector=approval_inspector)
    policy = _policy(document, approval)
    images = _runtime_images()
    docker: str | None = None
    stage_parent = Path(tempfile.mkdtemp(prefix="incidentseal-workflow-stage-"))
    if _inside(stage_parent, snapshot.root) or _is_onedrive(stage_parent):
        shutil.rmtree(stage_parent, ignore_errors=True)
        raise WorkflowError("IS_WORKFLOW_STAGING", "temporary staging entered denied custody")
    stage = stage_parent / "workspace"
    archive: RunArchive | None = None
    active_path: Path | None = None
    try:
        _stage(snapshot, stage)
        approval = require_approval(document, approval_inspector)
        policy = _policy(document, approval)
        root = _state_root(default_run_root() if run_root is None else run_root, snapshot.root, permission_checker)
        key = _active_key(document, snapshot)
        active_path = root / "active" / f"{key}.json"
        if active_path.exists():
            active = _canonical_file(active_path)
            run_id = validate_run_id(active.get("run_id"))
            if active.get("active_key") != key:
                raise WorkflowError("IS_WORKFLOW_RECOVERY", "active workflow pointer identity differs")
            archive = RunArchive(root, run_id, document, approval)
            prior_events = archive.resume()
            if prior_events and prior_events[-1]["terminal"]:
                raise WorkflowError("IS_WORKFLOW_RECOVERY", "terminal workflow attempt cannot be resumed")
            archive.append("run.started", "running", payload={"resumed": True})
        else:
            run_id = str(uuid.uuid4())
            archive = RunArchive(root, run_id, document, approval)
            archive.create()
            prior_events = []
            archive.append("run.queued", "queued", payload={"repository_remote": snapshot.remote, "commit": snapshot.commit, "tree_digest": snapshot.tree_digest})
            archive.append("run.started", "running", payload={"resumed": False})
            _atomic_json(active_path, {"schema_version": "incidentseal-workflow-active-pointer/v1", "active_key": key, "run_id": run_id})
        try:
            docker = docker_executable()
        except Exception as error:
            raise WorkflowError(
                "IS_WORKFLOW_DOCKER",
                "host Docker executable is unavailable",
                exit_code=21,
                verdict=None,
                lifecycle="failed",
                retriable=True,
            ) from error
        for image_id in images.values():
            _docker_call(docker, ["image", "inspect", image_id])
        candidates = _container_candidates(docker, run_id)
        recovery_disposition = _recover_exact_container(
            docker, archive, candidates, prior_events, document, snapshot, images
        )
        if recovery_disposition == "conflicting":
            archive.append("run.completed", "completed", verdict="FAIL", payload={"reason": "conflicting-owned-runtime", "container_ids": candidates})
            active_path.unlink(missing_ok=True)
            return WorkflowOutcome(10, "FAIL", "completed", policy, {"run_id": run_id, "claim_permitted": False}, approval.evidence())
        if recovery_disposition == "unknown":
            archive.append("run.completed", "completed", verdict="INCONCLUSIVE", payload={"reason": "unknown-owned-runtime", "container_id": candidates[0]})
            active_path.unlink(missing_ok=True)
            return WorkflowOutcome(11, "INCONCLUSIVE", "completed", policy, {"run_id": run_id, "claim_permitted": False}, approval.evidence())
        completed_steps = {
            event["payload"].get("step_id")
            for event in prior_events
            if event.get("event_type") == "step.completed" and isinstance(event.get("payload"), dict)
        }
        step_results: dict[str, dict[str, Any]] = {}
        pending = list(document.value["steps"])
        while pending:
            progress = False
            for step in list(pending):
                if not set(step["depends_on"]) <= completed_steps:
                    continue
                pending.remove(step)
                progress = True
                if step["id"] in completed_steps:
                    continue
                approval = require_approval(document, approval_inspector)
                archive.append("policy.checked", "running", payload={"step_id": step["id"], "approval_status": "MATCH"})
                result, exit_code = _run_step(docker, archive, document, step, stage, images[step["runner"]])
                step_results[step["id"]] = result
                if exit_code not in step["expected_exit_codes"]:
                    archive.append("step.failed", "running", payload=result, error={"code": "IS_WORKFLOW_STEP_EXIT", "message": "step returned an unexpected exit code", "retriable": False})
                    archive.append("run.completed", "completed", verdict="FAIL", payload={"reason": "unexpected-step-exit", "step_id": step["id"]})
                    active_path.unlink(missing_ok=True)
                    evidence = approval.evidence() + [{"kind": "artifact", "path": result["record_path"], "digest": result["record_digest"]}]
                    return WorkflowOutcome(10, "FAIL", "completed", policy, {"run_id": run_id, "claim_permitted": False, "steps": step_results}, evidence)
                archive.append("step.completed", "running", payload=result)
                completed_steps.add(step["id"])
            if not progress:
                raise WorkflowError("IS_WORKFLOW_DEPENDENCY", "workflow dependency order could not progress")
        required = set(document.value["claim"]["required_steps"])
        if not required <= completed_steps:
            verdict, exit_code, reason = "INCONCLUSIVE", 11, "missing-required-evidence"
        else:
            verdict, exit_code, reason = "PASS", 0, "required-steps-passed"
        receipt = {
            "schema_version": "incidentseal-workflow-receipt/v1",
            "run_id": run_id,
            "workflow_id": document.value["workflow_id"],
            "manifest_digest": document.digest,
            "approval_file_digest": approval.approval_file_digest,
            "repository_remote": snapshot.remote,
            "commit": snapshot.commit,
            "tree_digest": snapshot.tree_digest,
            "verdict": verdict,
            "lifecycle": "completed",
            "reason": reason,
            "step_records": sorted(step_results.values(), key=lambda item: item["step_id"]),
        }
        receipt_path, receipt_digest = archive.write_record(receipt)
        archive.append("evidence.recorded", "running", payload={"kind": "receipt", "path": str(receipt_path), "digest": receipt_digest})
        archive.append("run.completed", "completed", verdict=verdict, payload={"reason": reason, "receipt_digest": receipt_digest})
        active_path.unlink(missing_ok=True)
        evidence = approval.evidence() + [{"kind": "receipt", "path": str(receipt_path), "digest": receipt_digest}]
        return WorkflowOutcome(exit_code, verdict, "completed", policy, {"run_id": run_id, "claim_permitted": verdict == "PASS", "steps": step_results}, evidence)
    except KeyboardInterrupt:
        if archive is None:
            raise
        candidates = [] if docker is None else _container_candidates(docker, archive.run_id)
        disposition = None if docker is None else _recover_exact_container(
            docker, archive, candidates, archive.resume(), document, snapshot, images
        )
        if disposition == "unknown":
            archive.append("run.completed", "completed", verdict="INCONCLUSIVE", payload={"reason": "unknown-owned-runtime-during-cancel"})
            if active_path is not None:
                active_path.unlink(missing_ok=True)
            return WorkflowOutcome(11, "INCONCLUSIVE", "completed", policy, {"run_id": archive.run_id, "claim_permitted": False}, approval.evidence())
        if disposition == "conflicting":
            archive.append("run.completed", "completed", verdict="FAIL", payload={"reason": "conflicting-owned-runtime-during-cancel"})
            if active_path is not None:
                active_path.unlink(missing_ok=True)
            return WorkflowOutcome(10, "FAIL", "completed", policy, {"run_id": archive.run_id, "claim_permitted": False}, approval.evidence())
        archive.append("run.cancelled", "cancelled", payload={"reason": "operator-interrupt"})
        if active_path is not None:
            active_path.unlink(missing_ok=True)
        return WorkflowOutcome(20, None, "cancelled", policy, {"run_id": archive.run_id, "claim_permitted": False}, approval.evidence())
    except WorkflowError as error:
        if archive is not None and error.code.startswith("IS_APPROVAL_"):
            observed = ((error.policy or {}).get("approved_digest") if error.policy else None) or ("sha256:" + "0" * 64)
            if observed == document.digest:
                observed = "sha256:" + "0" * 64
            archive.append(
                "run.stale",
                "stale",
                payload={"expected_authority_digest": document.digest, "observed_authority_digest": observed, "reason": error.code},
            )
            if active_path is not None:
                active_path.unlink(missing_ok=True)
            return WorkflowOutcome(
                22,
                None,
                "stale",
                error.policy or policy,
                {"run_id": archive.run_id, "claim_permitted": False},
                error.evidence or approval.evidence(),
            )
        if archive is not None and error.verdict in {"FAIL", "INCONCLUSIVE", "INVALID"} and error.lifecycle != "failed":
            archive.append(
                "step.failed",
                "running",
                payload={},
                error={"code": error.code, "message": str(error)[:1000], "retriable": error.retriable},
            )
            archive.append("run.completed", "completed", verdict=error.verdict, payload={"reason": error.code})
            if active_path is not None:
                active_path.unlink(missing_ok=True)
            return WorkflowOutcome(
                error.exit_code,
                error.verdict,
                "completed",
                error.policy or policy,
                {"run_id": archive.run_id, "claim_permitted": False},
                error.evidence or approval.evidence(),
            )
        if archive is not None and error.lifecycle == "failed":
            archive.append("run.failed", "failed", payload={}, error={"code": error.code, "message": str(error)[:1000], "retriable": error.retriable})
            if active_path is not None:
                active_path.unlink(missing_ok=True)
            error.data = {**error.data, "run_id": archive.run_id, "claim_permitted": False}
            error.policy = policy
        raise
    finally:
        shutil.rmtree(stage_parent, ignore_errors=True)


def read_archive_events(root: Path, run_id_value: str) -> tuple[list[bytes], int]:
    """Read and validate exact canonical event bytes from external workflow custody."""

    run_id = validate_run_id(run_id_value)
    events_path = root.expanduser().resolve(strict=False) / "runs" / run_id / "events.jsonl"
    try:
        raw = events_path.read_bytes()
    except FileNotFoundError:
        return [], 11
    except OSError as error:
        raise WorkflowError("IS_WORKFLOW_EVIDENCE", "workflow event archive is unavailable", exit_code=74, verdict=None, retriable=True) from error
    if not raw or not raw.endswith(b"\n"):
        raise WorkflowError("IS_WORKFLOW_EVIDENCE", "workflow event archive is empty or truncated")
    output: list[bytes] = []
    values: list[dict[str, Any]] = []
    for sequence, line in enumerate(raw.splitlines()):
        try:
            value = strict_load_bytes(line)
        except ManifestError as error:
            raise WorkflowError("IS_WORKFLOW_EVIDENCE", "workflow event archive contains invalid JSON") from error
        event = validate_event(value)
        if canonical_bytes(event) != line or event["run_id"] != run_id or event["sequence"] != sequence:
            raise WorkflowError("IS_WORKFLOW_EVIDENCE", "workflow event archive identity or order differs")
        if values and values[-1]["terminal"]:
            raise WorkflowError("IS_WORKFLOW_EVIDENCE", "workflow event archive continues after terminal state")
        output.append(line)
        values.append(event)
    return output, lifecycle_exit(values[-1])


def stream_workflow_events(run_id: str) -> tuple[list[bytes], int] | None:
    """Return a workflow archive if present; never create external custody."""

    try:
        validated = validate_run_id(run_id)
    except JournalError:
        return None
    root = default_run_root()
    path = root / "runs" / validated / "events.jsonl"
    if root.exists() and not permissions_restrictive(root):
        raise WorkflowError("IS_WORKFLOW_EVIDENCE_CUSTODY", "workflow state root permissions are not restrictive", exit_code=74, verdict=None)
    return read_archive_events(root, run_id) if path.exists() else None
