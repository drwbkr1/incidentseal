#!/usr/bin/env python3
"""Dependency-free validation for the frozen IncidentSeal topology contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from validate_machine_contracts import (
    ContractError,
    SCHEMA_DIALECT,
    _lint_schema_node,
    strict_load,
    validate_schema_instance,
)


SCHEMA_NAMES = (
    "topology-contract-v1.schema.json",
    "topology-render-v1.schema.json",
)
EXPECTED_FILES = (
    "contracts/topology-v1.json",
    "schemas/topology-contract-v1.schema.json",
    "schemas/topology-render-v1.schema.json",
    "fixtures/topology/render.valid.json",
    "fixtures/topology/mutations.json",
    "requirements/images.lock.json",
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SENSITIVE_NAME_RE = re.compile(
    r"(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_KEY|DOCKER_HOST)(?:_|$)"
)


def fail(code: str, message: str) -> None:
    raise ContractError(code, message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def validate_schema_documents(root: Path) -> dict[str, dict[str, Any]]:
    documents = {name: strict_load(root / "schemas" / name) for name in SCHEMA_NAMES}
    for name, document in documents.items():
        if not isinstance(document, dict):
            fail("IS_SCHEMA_DOCUMENT", f"{name} is not an object")
        if document.get("$schema") != SCHEMA_DIALECT:
            fail("IS_SCHEMA_DOCUMENT", f"{name} dialect is not Draft 2020-12")
        expected_id = f"https://raw.githubusercontent.com/drwbkr1/incidentseal/main/schemas/{name}"
        if document.get("$id") != expected_id:
            fail("IS_SCHEMA_DOCUMENT", f"{name} does not have its stable repository-controlled $id")
        if document.get("type") != "object" or document.get("additionalProperties") is not False:
            fail("IS_SCHEMA_DOCUMENT", f"{name} top-level object is not closed")
        if not isinstance(document.get("required"), list) or not document["required"]:
            fail("IS_SCHEMA_DOCUMENT", f"{name} has no required properties")
        _lint_schema_node(document, name, documents, "#")
    return documents


def validate_authority(contract: dict[str, Any]) -> None:
    expected = {
        "control_plane": "host-cli",
        "docker_api_consumers": ["host-cli"],
        "compose_source": "host-generated-and-validated",
        "direct_compose_claim": "INVALID",
        "workflow_execution_gate": "MATCH",
        "platform_validation_input": "baked-in-fixtures-only",
        "platform_validation_claim_scope": "topology-only",
        "repository_approval_mutation": "denied",
    }
    if contract["authority"] != expected:
        fail("IS_TOPOLOGY_AUTHORITY", "host-only authority or manifest gate differs from v1")
    orchestration = contract["orchestration"]
    if orchestration["operation_modes"] != ["platform-validation", "workflow-execution"]:
        fail("IS_TOPOLOGY_AUTHORITY", "operation modes differ from v1")
    if orchestration["platform_validation"] != {
        "manifest_approval": "not-used",
        "repository_input": "denied",
        "commands": "baked-in-only",
        "claim_scope": "topology-only",
    }:
        fail("IS_TOPOLOGY_AUTHORITY", "platform validation escaped its topology-only scope")
    if orchestration["workflow_execution"] != {
        "manifest_approval": "MATCH",
        "manifest_recheck": ["before-staging", "after-staging", "before-each-runner"],
        "commands": "approved-manifest-only",
        "claim_scope": "approved-claim-only",
    }:
        fail("IS_TOPOLOGY_AUTHORITY", "workflow execution no longer requires the approved manifest")
    if orchestration["teardown"] != "host-cli-only":
        fail("IS_TOPOLOGY_AUTHORITY", "teardown authority is not host-only")


def validate_build(contract: dict[str, Any], images: dict[str, dict[str, Any]]) -> None:
    expected = {
        "frontend": images["dockerfile_frontend"]["index_reference"],
        "network": "none",
        "contexts": [
            "containers/database",
            "containers/migration",
            "containers/python-runner",
            "containers/node-runner",
        ],
        "allowed_instructions": ["ARG", "FROM", "LABEL", "COPY", "USER", "WORKDIR", "ENTRYPOINT", "CMD"],
        "run_instruction": "denied",
        "remote_add": "denied",
        "secret_mounts": "denied",
        "ssh_mounts": "denied",
        "online_dependency_resolution": "denied",
        "base_images": "image-lock-only",
        "runtime_identity": "local-image-id",
        "pull_policy": "never",
    }
    if contract["build_policy"] != expected:
        fail("IS_TOPOLOGY_BUILD", "copy-only, offline, exact-image build policy differs from v1")


def validate_network_and_volume(contract: dict[str, Any]) -> None:
    if contract["networks"] != [
        {"id": "data", "driver": "bridge", "internal": True, "attachable": False, "external": False}
    ]:
        fail("IS_TOPOLOGY_NETWORK", "the data network must be the sole internal-only network")
    if contract["volumes"] != [
        {
            "id": "database-data",
            "driver": "local",
            "external": False,
            "lifecycle": "retained-until-verified-cleanup",
        }
    ]:
        fail("IS_TOPOLOGY_NETWORK", "database storage must be a non-external named volume")


def validate_staging(contract: dict[str, Any]) -> None:
    expected = {
        "custody": "host-state-outside-repository-and-forbidden-roots",
        "repository_mount": "denied",
        "input_mount": "staged-read-only",
        "output_mount": "staged-write-only-by-convention",
        "symlinks": "denied",
        "reparse_points": "denied",
        "hardlinks": "denied",
        "special_files": "denied",
        "maximum_files": 4096,
        "maximum_total_bytes": 268435456,
        "cleanup": "after-evidence-promotion-and-verification",
    }
    if contract["staging"] != expected:
        fail("IS_TOPOLOGY_STAGING", "bounded staged custody differs from v1")


def service_projection(service: dict[str, Any]) -> dict[str, Any]:
    mounts = [
        {"kind": mount["kind"], "target": mount["target"], "mode": mount["mode"]}
        for mount in service["mounts"]
    ]
    mounts.extend(
        {"kind": "tmpfs", "target": mount["target"], "mode": "rw"}
        for mount in service["tmpfs"]
    )
    return {
        "id": service["id"],
        "user": service["user"],
        "read_only_root": service["read_only_root"],
        "privileged": service["privileged"],
        "no_new_privileges": service["no_new_privileges"],
        "cap_drop": service["cap_drop"],
        "networks": service["networks"],
        "published_ports": service["published_ports"],
        "mounts": mounts,
        "environment_names": list(service["environment"]),
    }


def validate_services(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    services = contract["services"]
    expected_ids = ["database", "migration", "python-runner", "node-runner"]
    if [service["id"] for service in services] != expected_ids:
        fail("IS_TOPOLOGY_SERVICE", "service set or order differs from v1")
    by_id = {service["id"]: service for service in services}
    expected_identity = {
        "database": ("runtime-lock", "postgresql", "containers/database", "70:70", "persistent"),
        "migration": ("runtime-lock", "postgresql", "containers/migration", "70:70", "one-shot"),
        "python-runner": (
            "runtime-lock",
            "python_runner",
            "containers/python-runner",
            "65532:65532",
            "one-shot",
        ),
        "node-runner": (
            "runtime-lock",
            "node_runner",
            "containers/node-runner",
            "65532:65532",
            "one-shot",
        ),
    }
    for service_id, service in by_id.items():
        identity = (
            service["image_source"],
            service["image_role"],
            service["build_context"],
            service["user"],
            service["lifecycle"],
        )
        if identity != expected_identity[service_id]:
            fail("IS_TOPOLOGY_SERVICE", f"{service_id} identity differs from v1")
        if (
            service["read_only_root"] is not True
            or service["privileged"] is not False
            or service["no_new_privileges"] is not True
            or service["cap_drop"] != ["ALL"]
            or service["restart"] != "no"
            or service["networks"] != ["data"]
            or service["published_ports"] != []
        ):
            fail("IS_TOPOLOGY_SERVICE", f"{service_id} runtime hardening differs from v1")
        for name in service["environment"]:
            if SENSITIVE_NAME_RE.search(name):
                fail("IS_TOPOLOGY_SERVICE", f"{service_id} environment contains a sensitive name")
        for mount in service["mounts"]:
            if mount["kind"] == "staged-input" and mount["mode"] != "ro":
                fail("IS_TOPOLOGY_SERVICE", f"{service_id} staged input is not read-only")
            if mount["kind"] == "staged-output" and mount["target"] != "/incidentseal/output":
                fail("IS_TOPOLOGY_SERVICE", f"{service_id} output target differs from v1")
            flattened = f"{mount['source']} {mount['target']}".lower()
            if "docker.sock" in flattened or "docker_engine" in flattened:
                fail("IS_TOPOLOGY_SERVICE", f"{service_id} exposes a container-engine endpoint")
    if by_id["database"]["environment"] != {
        "PGDATA": "/var/lib/postgresql/incidentseal-data/pgdata",
        "POSTGRES_DB": "incidentseal",
        "POSTGRES_HOST_AUTH_METHOD": "trust",
        "POSTGRES_USER": "incidentseal_admin",
        "TZ": "UTC",
    }:
        fail("IS_TOPOLOGY_SERVICE", "database authentication is not the frozen internal-only configuration")
    if by_id["database"]["mounts"] != [
        {
            "kind": "named-volume",
            "source": "database-data",
            "target": "/var/lib/postgresql/incidentseal-data",
            "mode": "rw",
        }
    ]:
        fail("IS_TOPOLOGY_SERVICE", "database volume does not use the ownership-seeded mount path")
    if by_id["migration"]["depends_on"] != [
        {"service": "database", "condition": "service_healthy"}
    ]:
        fail("IS_TOPOLOGY_SERVICE", "migration dependency differs from v1")
    if by_id["migration"]["entrypoint"] != ["/usr/bin/psql"] or by_id["migration"]["command"] != [
        "--host=database",
        "--username=incidentseal_admin",
        "--dbname=incidentseal",
        "--set=ON_ERROR_STOP=1",
        "--file=/opt/incidentseal/migrations/001-schema.sql",
    ]:
        fail("IS_TOPOLOGY_SERVICE", "migration does not use the bootstrap admin role")
    runner_dependencies = [
        {"service": "database", "condition": "service_healthy"},
        {"service": "migration", "condition": "service_completed_successfully"},
    ]
    for service_id in ("python-runner", "node-runner"):
        if by_id[service_id]["depends_on"] != runner_dependencies:
            fail("IS_TOPOLOGY_SERVICE", f"{service_id} dependency order differs from v1")
        kinds = [(mount["kind"], mount["target"], mount["mode"]) for mount in by_id[service_id]["mounts"]]
        if kinds != [
            ("staged-input", "/incidentseal/input", "ro"),
            ("staged-output", "/incidentseal/output", "rw"),
        ]:
            fail("IS_TOPOLOGY_SERVICE", f"{service_id} staged mounts differ from v1")
        if by_id[service_id]["environment"].get("PGUSER") != "incidentseal_runner":
            fail("IS_TOPOLOGY_SERVICE", f"{service_id} does not use the least-privilege runner role")
    return by_id


def validate_evidence(contract: dict[str, Any]) -> None:
    if contract["evidence_policy"] != {
        "preserve_verdicts": ["PASS", "FAIL", "INCONCLUSIVE", "INVALID"],
        "preserve_lifecycle": [
            "queued",
            "running",
            "completed",
            "cancelled",
            "failed",
            "stale",
            "superseded",
        ],
        "retain_attempts": "all",
        "config_render_is_runtime_proof": False,
        "source_tests_are_runtime_proof": False,
    }:
        fail("IS_TOPOLOGY_EVIDENCE", "evidence states or proof boundaries differ from v1")


def validate_image_lock(root: Path, contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    image_path = root / contract["image_lock"]["path"]
    actual_digest = sha256_file(image_path)
    if contract["image_lock"]["sha256"] != actual_digest:
        fail("IS_TOPOLOGY_IMAGE_LOCK", "topology contract does not bind the exact image lock")
    lock = strict_load(image_path)
    if lock.get("schema_version") != "incidentseal-image-lock/v1" or lock.get("platform") != {
        "os": "linux",
        "architecture": "amd64",
    }:
        fail("IS_TOPOLOGY_IMAGE_LOCK", "image lock schema or platform differs from v1")
    images = lock.get("images")
    if not isinstance(images, list):
        fail("IS_TOPOLOGY_IMAGE_LOCK", "image lock has no image list")
    by_role = {image.get("role"): image for image in images if isinstance(image, dict)}
    required = {"dockerfile_frontend", "postgresql", "python_runner", "node_runner"}
    if set(by_role) != required:
        fail("IS_TOPOLOGY_IMAGE_LOCK", "image lock roles differ from the topology")
    for role, image in by_role.items():
        if image.get("approved_for_next_unit") is not True:
            fail("IS_TOPOLOGY_IMAGE_LOCK", f"{role} is not approved for the topology unit")
        if not SHA256_RE.fullmatch(str(image.get("index_digest", ""))):
            fail("IS_TOPOLOGY_IMAGE_LOCK", f"{role} has no exact index digest")
        if image.get("local_image_id") != image.get("index_digest"):
            fail("IS_TOPOLOGY_IMAGE_LOCK", f"{role} local identity differs from its exact index digest")
    return by_role


def validate_render(
    root: Path,
    contract: dict[str, Any],
    services: dict[str, dict[str, Any]],
    images: dict[str, dict[str, Any]],
    render: dict[str, Any],
) -> None:
    if render["contract_digest"] != sha256_file(root / "contracts" / "topology-v1.json"):
        fail("IS_TOPOLOGY_DIGEST", "normalized render is not bound to the topology contract")
    if render["operation_mode"] != "platform-validation":
        fail("IS_TOPOLOGY_RENDER", "the frozen fixture must exercise platform-validation mode")
    expected_networks = [
        {key: network[key] for key in ("id", "driver", "internal", "attachable", "external")}
        for network in contract["networks"]
    ]
    expected_volumes = [
        {key: volume[key] for key in ("id", "driver", "external")}
        for volume in contract["volumes"]
    ]
    if render["networks"] != expected_networks or render["volumes"] != expected_volumes:
        fail("IS_TOPOLOGY_RENDER", "rendered networks or volumes differ from the contract")
    if [item["id"] for item in render["services"]] != list(services):
        fail("IS_TOPOLOGY_RENDER", "rendered service set or order differs from the contract")
    image_ids: list[str] = []
    for item in render["services"]:
        expected = service_projection(services[item["id"]])
        actual = {key: value for key, value in item.items() if key != "image"}
        if actual != expected:
            fail("IS_TOPOLOGY_RENDER", f"rendered {item['id']} security projection differs from the contract")
        if not SHA256_RE.fullmatch(item["image"]):
            fail("IS_TOPOLOGY_RENDER", f"rendered {item['id']} is not bound to an exact local image ID")
        image_ids.append(item["image"])
    if render["services"][0]["image"] == images["postgresql"]["local_image_id"]:
        fail("IS_TOPOLOGY_RENDER", "database render bypasses the required ownership-seeding image")
    if len(set(image_ids)) != len(image_ids):
        fail("IS_TOPOLOGY_RENDER", "rendered service image identities are not distinct")


def validate_file_lock(root: Path) -> None:
    lock = strict_load(root / "requirements" / "topology-contract.lock.json")
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-topology-lock/v1":
        fail("IS_TOPOLOGY_DIGEST", "topology file lock schema is invalid")
    files = lock.get("files")
    if not isinstance(files, list) or [item.get("path") for item in files if isinstance(item, dict)] != list(EXPECTED_FILES):
        fail("IS_TOPOLOGY_DIGEST", "topology file lock scope differs from v1")
    for item in files:
        path = root / item["path"]
        if item.get("sha256") != sha256_file(path):
            fail("IS_TOPOLOGY_DIGEST", f"topology file digest mismatch: {item['path']}")


def run(root: Path) -> dict[str, Any]:
    documents = validate_schema_documents(root)
    contract = strict_load(root / "contracts" / "topology-v1.json")
    render = strict_load(root / "fixtures" / "topology" / "render.valid.json")
    validate_schema_instance(
        documents["topology-contract-v1.schema.json"],
        contract,
        "topology-contract-v1.schema.json",
        documents,
    )
    validate_schema_instance(
        documents["topology-render-v1.schema.json"],
        render,
        "topology-render-v1.schema.json",
        documents,
    )
    if contract["revision"] != 3:
        fail("IS_TOPOLOGY_DIGEST", "active topology contract is not revision 3")
    images = validate_image_lock(root, contract)
    validate_authority(contract)
    validate_build(contract, images)
    validate_network_and_volume(contract)
    validate_staging(contract)
    services = validate_services(contract)
    validate_evidence(contract)
    validate_render(root, contract, services, images, render)
    validate_file_lock(root)
    return {
        "schema_version": "incidentseal-topology-validation/v1",
        "verdict": "PASS",
        "contract_digest": sha256_file(root / "contracts" / "topology-v1.json"),
        "schemas": list(SCHEMA_NAMES),
        "services": list(services),
        "runtime_started": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        result = run(args.root.resolve())
    except (ContractError, OSError, KeyError, TypeError) as error:
        code = error.code if isinstance(error, ContractError) else "IS_TOPOLOGY_VALIDATOR"
        print(
            json.dumps(
                {
                    "schema_version": "incidentseal-topology-validation/v1",
                    "verdict": "FAIL",
                    "error": {"code": code, "message": str(error)},
                    "runtime_started": False,
                },
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
