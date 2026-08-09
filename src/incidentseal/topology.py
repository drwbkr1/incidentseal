"""Static host-owned validation of the IncidentSeal Compose implementation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .manifest import ManifestError, strict_load_bytes


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "contracts" / "topology-v1.json"
COMPOSE_PATH = ROOT / "compose.yaml"
IMPLEMENTATION_LOCK_PATH = ROOT / "requirements" / "topology-implementation.lock.json"
TOPOLOGY_LOCK_PATH = ROOT / "requirements" / "topology-contract.lock.json"
RENDER_FIXTURE_PATH = ROOT / "fixtures" / "topology" / "render.valid.json"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PROJECT_NAME = "incidentseal-0123456789abcdef"
RUN_ID = "isrun-0123456789abcdef"
SYNTHETIC_IMAGES = {
    "migration": "sha256:" + "1" * 64,
    "python-runner": "sha256:" + "2" * 64,
    "node-runner": "sha256:" + "3" * 64,
}
IMPLEMENTATION_FILES = (
    "compose.yaml",
    "containers/migration/Dockerfile",
    "containers/migration/001-schema.sql",
    "containers/python-runner/Dockerfile",
    "containers/python-runner/python_runner.py",
    "containers/node-runner/Dockerfile",
    "containers/node-runner/node_runner.mjs",
    "fixtures/topology/runner-request.valid.json",
    "src/incidentseal/cli.py",
    "src/incidentseal/topology.py",
)


class TopologyError(ValueError):
    """A stable fail-closed topology implementation rejection."""

    def __init__(self, code: str, message: str, *, io_error: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.io_error = io_error


@dataclass(frozen=True)
class TopologyValidation:
    data: dict[str, Any]
    evidence: list[dict[str, str]]


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as error:
        raise TopologyError("IS_TOPOLOGY_READ", f"required topology file is unavailable: {path.name}", io_error=True) from error


def _load(path: Path) -> Any:
    try:
        return strict_load_bytes(path.read_bytes())
    except OSError as error:
        raise TopologyError("IS_TOPOLOGY_READ", f"required topology file is unavailable: {path.name}", io_error=True) from error
    except ManifestError as error:
        raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", f"invalid topology JSON: {path.name}: {error}") from error


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_implementation_lock() -> dict[str, Any]:
    lock = _load(IMPLEMENTATION_LOCK_PATH)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-topology-implementation-lock/v1":
        raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", "topology implementation lock schema is invalid")
    files = lock.get("files")
    if not isinstance(files, list) or [item.get("path") for item in files if isinstance(item, dict)] != list(IMPLEMENTATION_FILES):
        raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", "topology implementation lock scope differs from v1")
    for item in files:
        expected = item.get("sha256")
        if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
            raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", f"invalid implementation digest for {item.get('path')}")
        if _sha256_file(ROOT / item["path"]) != expected:
            raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", f"topology implementation digest mismatch: {item['path']}")
    return lock


def _validate_topology_lock() -> None:
    lock = _load(TOPOLOGY_LOCK_PATH)
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-topology-lock/v1":
        raise TopologyError("IS_TOPOLOGY_CONTRACT", "topology file lock schema is invalid")
    files = lock.get("files")
    if not isinstance(files, list) or not files:
        raise TopologyError("IS_TOPOLOGY_CONTRACT", "topology file lock has no bounded file set")
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise TopologyError("IS_TOPOLOGY_CONTRACT", "topology file lock entry is invalid")
        relative = item["path"]
        if not isinstance(relative, str) or relative.startswith(("/", "\\")) or ".." in relative.replace("\\", "/").split("/"):
            raise TopologyError("IS_TOPOLOGY_CONTRACT", "topology file lock path is unsafe")
        if item["sha256"] != _sha256_file(ROOT / relative):
            raise TopologyError("IS_TOPOLOGY_CONTRACT", f"topology file digest mismatch: {relative}")


def _validate_dockerfiles(contract: dict[str, Any]) -> None:
    try:
        image_path = ROOT / contract["image_lock"]["path"]
        if contract["image_lock"]["sha256"] != _sha256_file(image_path):
            raise TopologyError("IS_TOPOLOGY_CONTRACT", "topology contract image-lock binding differs")
        image_lock = _load(image_path)
        images = {image["role"]: image for image in image_lock["images"]}
        required_roles = {"postgresql", "python_runner", "node_runner"}
        if not required_roles <= set(images):
            raise TopologyError("IS_TOPOLOGY_CONTRACT", "topology image roles are incomplete")
    except (KeyError, TypeError) as error:
        raise TopologyError("IS_TOPOLOGY_CONTRACT", "topology image-lock shape is invalid") from error
    expected = {
        "containers/migration": (
            f"ARG INCIDENTSEAL_POSTGRES_IMAGE={images['postgresql']['index_reference']}",
            "FROM ${INCIDENTSEAL_POSTGRES_IMAGE}",
        ),
        "containers/python-runner": (
            f"ARG INCIDENTSEAL_PYTHON_IMAGE={images['python_runner']['index_reference']}",
            "FROM ${INCIDENTSEAL_PYTHON_IMAGE}",
        ),
        "containers/node-runner": (
            f"ARG INCIDENTSEAL_NODE_IMAGE={images['node_runner']['index_reference']}",
            "FROM ${INCIDENTSEAL_NODE_IMAGE}",
        ),
    }
    if list(expected) != contract["build_policy"]["contexts"]:
        raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", "Dockerfile contexts differ from the frozen contract")
    allowed = set(contract["build_policy"]["allowed_instructions"])
    frontend = f"# syntax={contract['build_policy']['frontend']}"
    expected_files = {
        "containers/migration": {"Dockerfile", "001-schema.sql"},
        "containers/python-runner": {"Dockerfile", "python_runner.py"},
        "containers/node-runner": {"Dockerfile", "node_runner.mjs"},
    }
    for context in expected:
        directory = ROOT / context
        actual_files = {item.name for item in directory.iterdir() if item.is_file()}
        if actual_files != expected_files[context]:
            raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", f"unexpected files in {context}")
        text = (directory / "Dockerfile").read_text(encoding="utf-8")
        lines = text.splitlines()
        if not lines or lines[0] != frontend:
            raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", f"{context} does not pin the exact frontend")
        if len(lines) < 3 or tuple(lines[1:3]) != expected[context]:
            raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", f"{context} does not pin its exact base image")
        if any(line.rstrip().endswith("\\") for line in lines):
            raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", f"{context} uses forbidden line continuation")
        instructions = [line.split(maxsplit=1)[0].upper() for line in lines[1:] if line and not line.startswith("#")]
        if not instructions or any(instruction not in allowed for instruction in instructions):
            raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", f"{context} uses a forbidden Dockerfile instruction")
        if "FROM" not in instructions or "COPY" not in instructions or "USER" not in instructions:
            raise TopologyError("IS_TOPOLOGY_IMPLEMENTATION", f"{context} is missing a required copy-only instruction")


def _compose_environment(contract: dict[str, Any], custody: Path) -> dict[str, str]:
    try:
        images = _load(ROOT / contract["image_lock"]["path"])["images"]
        postgresql = next(image for image in images if image["role"] == "postgresql")
    except (KeyError, TypeError, StopIteration) as error:
        raise TopologyError("IS_TOPOLOGY_CONTRACT", "PostgreSQL image binding is unavailable") from error
    environment = os.environ.copy()
    for name in list(environment):
        upper = name.upper()
        if upper.startswith("INCIDENTSEAL_") or upper.startswith("COMPOSE_") or upper in {"DOCKER_HOST", "DOCKER_CONTEXT"}:
            environment.pop(name, None)
    environment.update(
        {
            "INCIDENTSEAL_PROJECT_NAME": PROJECT_NAME,
            "INCIDENTSEAL_CONTRACT_DIGEST": _sha256_file(CONTRACT_PATH),
            "INCIDENTSEAL_MANIFEST_DIGEST": "not-used",
            "INCIDENTSEAL_RUN_ID": RUN_ID,
            "INCIDENTSEAL_POSTGRES_IMAGE": postgresql["local_image_id"],
            "INCIDENTSEAL_MIGRATION_IMAGE": SYNTHETIC_IMAGES["migration"],
            "INCIDENTSEAL_PYTHON_IMAGE": SYNTHETIC_IMAGES["python-runner"],
            "INCIDENTSEAL_NODE_IMAGE": SYNTHETIC_IMAGES["node-runner"],
            "INCIDENTSEAL_INPUT_DIR": str(custody / "input"),
            "INCIDENTSEAL_PYTHON_OUTPUT_DIR": str(custody / "python-output"),
            "INCIDENTSEAL_NODE_OUTPUT_DIR": str(custody / "node-output"),
        }
    )
    return environment


def _docker_executable() -> str:
    executable = shutil.which("docker")
    if not executable:
        raise TopologyError("IS_DOCKER_UNAVAILABLE", "Docker CLI is unavailable", io_error=True)
    try:
        resolved = Path(executable).resolve(strict=True)
    except OSError as error:
        raise TopologyError("IS_DOCKER_UNAVAILABLE", "Docker CLI cannot be resolved", io_error=True) from error
    if _inside(resolved, ROOT) or any(part.casefold() == "onedrive" for part in resolved.parts):
        raise TopologyError("IS_DOCKER_UNAVAILABLE", "Docker CLI resolved from forbidden custody", io_error=True)
    return str(resolved)


def _run_compose_config(contract: dict[str, Any]) -> tuple[dict[str, Any], str]:
    docker = _docker_executable()
    with tempfile.TemporaryDirectory(prefix="incidentseal-static-render-") as temporary:
        custody = Path(temporary).resolve(strict=True)
        if _inside(custody, ROOT) or any(part.casefold() == "onedrive" for part in custody.parts):
            raise TopologyError("IS_TOPOLOGY_CUSTODY", "static render custody overlaps a forbidden root")
        for name in ("input", "python-output", "node-output"):
            (custody / name).mkdir()
        empty_environment = custody / "empty.env"
        empty_environment.write_text("", encoding="utf-8")
        try:
            completed = subprocess.run(
                [
                    docker,
                    "compose",
                    "--ansi",
                    "never",
                    "--env-file",
                    str(empty_environment),
                    "-f",
                    str(COMPOSE_PATH),
                    "config",
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                env=_compose_environment(contract, custody),
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise TopologyError("IS_DOCKER_UNAVAILABLE", "Docker Compose config could not execute", io_error=True) from error
        if completed.returncode != 0:
            raise TopologyError("IS_COMPOSE_CONFIG", "Docker Compose rejected the frozen topology")
        if completed.stderr:
            raise TopologyError("IS_COMPOSE_CONFIG", "Docker Compose emitted unexpected diagnostics")
        try:
            model = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise TopologyError("IS_COMPOSE_CONFIG", "Docker Compose did not emit valid JSON") from error
    try:
        version = subprocess.run(
            [docker, "compose", "version", "--short"],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TopologyError("IS_DOCKER_UNAVAILABLE", "Docker Compose version could not execute", io_error=True) from error
    if version.returncode != 0 or version.stderr or not version.stdout.strip():
        raise TopologyError("IS_COMPOSE_CONFIG", "Docker Compose version is unavailable", io_error=True)
    return model, version.stdout.strip()


def _mounts(service: dict[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for mount in service.get("volumes", []):
        target = mount.get("target")
        if mount.get("type") == "volume":
            kind = "named-volume"
        elif mount.get("type") == "bind" and target == "/incidentseal/input":
            kind = "staged-input"
        elif mount.get("type") == "bind" and target == "/incidentseal/output":
            kind = "staged-output"
        else:
            raise TopologyError("IS_TOPOLOGY_RENDER", "Compose rendered an unrecognized mount")
        mode = "ro" if mount.get("read_only") is True else "rw"
        result.append({"kind": kind, "target": target, "mode": mode})
    for tmpfs in service.get("tmpfs", []):
        target = tmpfs.split(":", 1)[0] if isinstance(tmpfs, str) else tmpfs.get("target")
        result.append({"kind": "tmpfs", "target": target, "mode": "rw"})
    return result


def _validate_model_contract(model: dict[str, Any], contract: dict[str, Any], contract_digest: str) -> None:
    services = model.get("services", {})
    contract_services = {service["id"]: service for service in contract["services"]}
    staged_sources: dict[str, Path] = {}
    for service_id, expected in contract_services.items():
        actual = services.get(service_id, {})
        command = actual.get("command") or []
        if actual.get("entrypoint") != expected["entrypoint"] or command != expected["command"]:
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} command surface differs from the contract")
        if actual.get("environment", {}) != expected["environment"]:
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} environment differs from the contract")
        if actual.get("pids_limit") != expected["pids_limit"]:
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} PID limit differs from the contract")
        dependencies = actual.get("depends_on") or {}
        expected_dependencies = {item["service"]: item["condition"] for item in expected["depends_on"]}
        if set(dependencies) != set(expected_dependencies) or any(
            dependencies[name].get("condition") != condition for name, condition in expected_dependencies.items()
        ):
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} dependencies differ from the contract")
        healthcheck = actual.get("healthcheck")
        if expected["healthcheck"] is None:
            if healthcheck:
                raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} has an unexpected healthcheck")
        else:
            expected_health = {
                "test": expected["healthcheck"]["test"],
                "interval": f"{expected['healthcheck']['interval_seconds']}s",
                "timeout": f"{expected['healthcheck']['timeout_seconds']}s",
                "retries": expected["healthcheck"]["retries"],
                "start_period": f"{expected['healthcheck']['start_period_seconds']}s",
            }
            if healthcheck != expected_health:
                raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} healthcheck differs from the contract")
        expected_tmpfs = expected["tmpfs"]
        actual_tmpfs: list[dict[str, int | str]] = []
        try:
            for item in actual.get("tmpfs", []):
                if not isinstance(item, str) or ":" not in item:
                    raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} tmpfs is not explicit")
                target, options_text = item.split(":", 1)
                options = dict(part.split("=", 1) for part in options_text.split(","))
                actual_tmpfs.append(
                    {
                        "target": target,
                        "size_bytes": int(options["size"]),
                        "mode": int(options["mode"], 8),
                        "uid": int(options["uid"]),
                        "gid": int(options["gid"]),
                    }
                )
        except (KeyError, TypeError, ValueError) as error:
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} tmpfs options are invalid") from error
        if actual_tmpfs != expected_tmpfs:
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} tmpfs differs from the contract")
        labels = actual.get("labels", {})
        if labels != {
            "dev.incidentseal.contract-digest": contract_digest,
            "dev.incidentseal.manifest-digest": "not-used",
            "dev.incidentseal.run-id": RUN_ID,
        }:
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} evidence labels differ from the contract")
        for mount in actual.get("volumes", []):
            if mount.get("type") != "bind":
                continue
            source_text = mount.get("source")
            target = mount.get("target")
            if not isinstance(source_text, str) or not isinstance(target, str):
                raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} has an invalid bind mount")
            lowered = source_text.casefold()
            if "docker.sock" in lowered or "docker_engine" in lowered:
                raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} exposes a container-engine endpoint")
            source = Path(source_text).resolve(strict=False)
            if not source.is_absolute() or _inside(source, ROOT) or any(part.casefold() == "onedrive" for part in source.parts):
                raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} bind mount escaped staged custody")
            if not source.parent.name.startswith("incidentseal-static-render-"):
                raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} bind mount is not in generated staging")
            expected_name = "input" if target == "/incidentseal/input" else f"{service_id.split('-', 1)[0]}-output"
            if source.name != expected_name:
                raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} bind mount has an unexpected source")
            staged_sources[f"{service_id}:{target}"] = source
    python_input = staged_sources.get("python-runner:/incidentseal/input")
    node_input = staged_sources.get("node-runner:/incidentseal/input")
    if python_input is None or python_input != node_input:
        raise TopologyError("IS_TOPOLOGY_RENDER", "runner staged input custody differs")


def _stable_model(model: dict[str, Any]) -> dict[str, Any]:
    stable = json.loads(json.dumps(model))
    for service_id, service in stable.get("services", {}).items():
        for mount in service.get("volumes", []):
            if mount.get("type") == "bind":
                mount["source"] = (
                    "incidentseal-staged-input"
                    if mount.get("target") == "/incidentseal/input"
                    else f"incidentseal-{service_id}-output"
                )
    return stable


def _normalize(model: dict[str, Any], contract_digest: str) -> dict[str, Any]:
    services = model.get("services")
    if not isinstance(services, dict):
        raise TopologyError("IS_TOPOLOGY_RENDER", "Compose model has no service object")
    order = ("database", "migration", "python-runner", "node-runner")
    if set(services) != set(order):
        raise TopologyError("IS_TOPOLOGY_RENDER", "Compose service set differs from v1")
    normalized_services: list[dict[str, Any]] = []
    for service_id in order:
        service = services[service_id]
        if service.get("build") is not None or service.get("pull_policy") != "never":
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} permits an uncontrolled build or pull")
        if service.get("platform") != "linux/amd64" or service.get("restart") != "no":
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} platform or restart policy differs from v1")
        if service.get("security_opt") != ["no-new-privileges:true"]:
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} no-new-privileges control is missing")
        labels = service.get("labels", {})
        if set(labels) != {
            "dev.incidentseal.contract-digest",
            "dev.incidentseal.manifest-digest",
            "dev.incidentseal.run-id",
        }:
            raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} evidence labels differ from v1")
        for denied in ("ports", "secrets", "configs", "devices", "network_mode", "pid", "ipc", "uts"):
            if service.get(denied):
                raise TopologyError("IS_TOPOLOGY_RENDER", f"{service_id} rendered forbidden {denied}")
        networks = service.get("networks", {})
        network_names = list(networks) if isinstance(networks, dict) else list(networks)
        normalized_services.append(
            {
                "id": service_id,
                "image": service.get("image"),
                "user": service.get("user"),
                "read_only_root": service.get("read_only") is True,
                "privileged": service.get("privileged") is True,
                "no_new_privileges": service.get("security_opt") == ["no-new-privileges:true"],
                "cap_drop": service.get("cap_drop", []),
                "networks": network_names,
                "published_ports": service.get("ports", []),
                "mounts": _mounts(service),
                "environment_names": list(service.get("environment", {})),
            }
        )
    network = model.get("networks", {}).get("data", {})
    volume = model.get("volumes", {}).get("database-data", {})
    return {
        "schema_version": "incidentseal-topology-render/v1",
        "contract_digest": contract_digest,
        "project_name": model.get("name"),
        "operation_mode": "platform-validation",
        "services": normalized_services,
        "networks": [
            {
                "id": "data",
                "driver": network.get("driver", "bridge"),
                "internal": network.get("internal") is True,
                "attachable": network.get("attachable") is True,
                "external": network.get("external") is True,
            }
        ],
        "volumes": [
            {
                "id": "database-data",
                "driver": volume.get("driver", "local"),
                "external": volume.get("external") is True,
            }
        ],
    }


def validate_platform_topology() -> TopologyValidation:
    lock = _validate_implementation_lock()
    _validate_topology_lock()
    contract = _load(CONTRACT_PATH)
    if contract.get("authority", {}).get("control_plane") != "host-cli":
        raise TopologyError("IS_TOPOLOGY_AUTHORITY", "topology no longer grants Docker authority only to the host CLI")
    _validate_dockerfiles(contract)
    model, compose_version = _run_compose_config(contract)
    contract_digest = _sha256_file(CONTRACT_PATH)
    _validate_model_contract(model, contract, contract_digest)
    normalized = _normalize(model, contract_digest)
    expected = _load(RENDER_FIXTURE_PATH)
    if normalized != expected:
        raise TopologyError("IS_TOPOLOGY_RENDER", "real Compose security projection differs from the frozen render")
    model_bytes = json.dumps(_stable_model(model), ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    normalized_bytes = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return TopologyValidation(
        data={
            "mode": "platform-validation",
            "claim_scope": "topology-only",
            "compose_version": compose_version,
            "contract_digest": contract_digest,
            "implementation_lock_id": lock.get("lock_id"),
            "compose_model_digest": _sha256_bytes(model_bytes),
            "normalized_render_digest": _sha256_bytes(normalized_bytes),
            "normalized_render": normalized,
            "derived_image_identity": "synthetic-static-placeholder",
            "runtime_started": False,
        },
        evidence=[
            {"kind": "artifact", "path": "contracts/topology-v1.json", "digest": contract_digest},
            {"kind": "artifact", "path": "requirements/topology-implementation.lock.json", "digest": _sha256_file(IMPLEMENTATION_LOCK_PATH)},
            {"kind": "artifact", "path": "compose.yaml", "digest": _sha256_file(COMPOSE_PATH)},
        ],
    )
