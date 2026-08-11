"""Closed, dependency-free v0.1.0 release-plan validator."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .manifest import canonical_bytes


class ReleaseContractError(ValueError):
    """A release plan violates the frozen IncidentSeal contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_SHA = re.compile(r"^[0-9a-f]{40}$")
_TOP_KEYS = {
    "schema_version", "release", "workflow_verification", "package", "images",
    "supply_chain", "release_assets", "real_surfaces", "evidence", "publication",
    "download_verification", "non_goals",
}
_RELEASE = {
    "product": "IncidentSeal", "version": "0.1.0", "tag": "v0.1.0",
    "base_checkpoint": "checkpoint-is-0005",
    "source_repository": "https://github.com/drwbkr1/incidentseal",
    "registry_repository": "ghcr.io/drwbkr1/incidentseal",
    "platforms": ["linux/amd64"], "source_date_epoch": 1786424840, "released": False,
}
_WORKFLOW = {
    "required_before_packaging": True,
    "command": "incidentseal verify --manifest PATH --json",
    "authority": "operator-approved-external-manifest-digest",
    "agent_can_approve": False,
    "repository_identity_required": True,
    "runners": ["python", "node"],
    "input_custody": "manifest-declared-copy-only-read-only-staging",
    "output_custody": "per-run-content-addressed-evidence-only",
    "host_owns_docker": True,
    "docker_socket": "denied",
    "secrets": "denied",
    "privileged": False,
    "host_network": False,
    "runtime_egress": "denied",
    "broad_host_mounts": "denied",
    "events": "append-only-internal-writer-read-only-agent-stream",
    "recovery": "idempotent-resume-under-approved-digest",
    "claim_rule": "all-required-steps-pass-under-current-approved-digest",
}
_PACKAGE_KEYS = {
    "name", "requires_python", "runtime_dependencies", "build_frontend", "build_backend",
    "entry_points", "artifacts", "build_repetitions", "byte_reproducible",
    "isolated_install_required", "pypi_publish",
}
_PACKAGE_ARTIFACTS = ["incidentseal-0.1.0-py3-none-any.whl", "incidentseal-0.1.0.tar.gz"]
_IMAGE_ROLES = ["database", "migration", "python-runner", "node-runner"]
_IMAGE_USERS = ["70:70", "65532:65532", "65532:65532", "65532:65532"]
_ACTIONS = [
    ("actions/checkout", "3d3c42e5aac5ba805825da76410c181273ba90b1"),
    ("actions/upload-artifact", "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
    ("actions/download-artifact", "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
    ("actions/attest-build-provenance", "4d101475d8b20a2381f78447822ac1eab6504dd8"),
    ("actions/attest-sbom", "c604332985a26aa8cf1bdc465b92731239ec6b9e"),
    ("docker/setup-buildx-action", "bb05f3f5519dd87d3ba754cc423b652a5edd6d2c"),
    ("docker/login-action", "dbcb813823bdd20940b903addbd779551569679f"),
    ("docker/build-push-action", "53b7df96c91f9c12dcc8a07bcb9ccacbed38856a"),
]
_ASSETS = [
    "incidentseal-0.1.0-py3-none-any.whl", "incidentseal-0.1.0.tar.gz",
    "incidentseal-0.1.0.spdx.json", "incidentseal-0.1.0.provenance.json",
    "incidentseal-v0.1.0-release-manifest.json", "incidentseal-v0.1.0-scan-summary.json",
    "incidentseal-v0.1.0-verification-receipt.json", "THIRD_PARTY_NOTICES.md", "SHA256SUMS",
]
_SURFACES = [
    "packaged-cli", "approved-manifest-workflow", "compose-topology", "postgresql",
    "python-runner", "node-runner", "dashboard", "portable-receipts", "recovery",
    "backup-clean-restore", "clean-install", "clean-clone", "downloaded-release-and-registry",
]
_NON_GOALS = [
    "kubernetes", "cloud-infrastructure", "multi-tenancy", "arbitrary-remote-execution",
    "pypi-publication", "paid-services", "reusable-codex-skill",
]


def _reject(code: str, message: str) -> None:
    raise ReleaseContractError(code, message)


def _exact(value: Any, keys: set[str], code: str, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _reject(code, f"{label} properties differ")
    return value


def validate_release_plan(value: Any) -> dict[str, Any]:
    """Validate the exact release plan and return its canonical identity."""

    plan = _exact(value, _TOP_KEYS, "IS_RELEASE_SCHEMA", "top-level")
    if plan["schema_version"] != "incidentseal-release-plan/v1":
        _reject("IS_RELEASE_SCHEMA", "release plan schema version differs")

    release = _exact(plan["release"], set(_RELEASE), "IS_RELEASE_IDENTITY", "release")
    if release != _RELEASE:
        _reject("IS_RELEASE_IDENTITY", "release identity or channel differs")

    workflow = _exact(plan["workflow_verification"], set(_WORKFLOW), "IS_RELEASE_WORKFLOW", "workflow verification")
    if workflow != _WORKFLOW:
        _reject("IS_RELEASE_WORKFLOW", "approved-workflow verification boundary differs")

    package = _exact(plan["package"], _PACKAGE_KEYS, "IS_RELEASE_PACKAGE", "package")
    expected_package = {
        "name": "incidentseal", "requires_python": ">=3.12", "runtime_dependencies": [],
        "build_frontend": "build==1.5.0", "build_backend": "hatchling==1.32.0",
        "entry_points": {"incidentseal": "incidentseal.cli:main", "incidentseal-dashboard": "incidentseal.dashboard_surface:main"},
        "artifacts": _PACKAGE_ARTIFACTS, "build_repetitions": 3, "byte_reproducible": True,
        "isolated_install_required": True, "pypi_publish": False,
    }
    if package != expected_package:
        _reject("IS_RELEASE_PACKAGE", "package contract differs")

    images = plan["images"]
    if not isinstance(images, list) or len(images) != 4:
        _reject("IS_RELEASE_IMAGE", "four release image roles are required")
    for index, image in enumerate(images):
        image = _exact(image, {"role", "version_tag", "authority", "runtime_user"}, "IS_RELEASE_IMAGE", "image")
        role = _IMAGE_ROLES[index]
        expected = {
            "role": role, "version_tag": f"{role}-v0.1.0", "authority": "exact-registry-digest",
            "runtime_user": _IMAGE_USERS[index],
        }
        if image != expected:
            _reject("IS_RELEASE_IMAGE", "release image role, tag, authority, or user differs")

    supply = _exact(plan["supply_chain"], {
        "source_gate", "base_image_lock", "runtime_image_lock", "redistribution_required_before_publish",
        "unresolved_noassertion_allowed", "third_party_notices_required", "sbom_format", "provenance_format",
        "package_attestation_required", "image_attestation_required", "scanner", "sbom_tool",
        "critical_findings_allowed", "high_findings_allowed", "medium_low_retained", "image_rebuilds",
        "image_digest_reproducible", "mutable_tags_are_authority", "github_actions",
    }, "IS_RELEASE_SUPPLY_CHAIN", "supply chain")
    fixed_supply = {key: value for key, value in supply.items() if key != "github_actions"}
    expected_supply = {
        "source_gate": "records/source-gates/2026-08-11-release-tooling.json",
        "base_image_lock": "requirements/images.lock.json",
        "runtime_image_lock": "requirements/topology-runtime.lock.json",
        "redistribution_required_before_publish": True, "unresolved_noassertion_allowed": False,
        "third_party_notices_required": True, "sbom_format": "SPDX-2.3-json",
        "provenance_format": "SLSA-v1-in-toto", "package_attestation_required": True,
        "image_attestation_required": True, "scanner": "grype==0.117.0",
        "sbom_tool": "syft==1.51.0-and-buildkit", "critical_findings_allowed": 0,
        "high_findings_allowed": 0, "medium_low_retained": True, "image_rebuilds": 2,
        "image_digest_reproducible": True, "mutable_tags_are_authority": False,
    }
    if fixed_supply != expected_supply:
        _reject("IS_RELEASE_SUPPLY_CHAIN", "supply-chain gate differs")
    actions = supply["github_actions"]
    if not isinstance(actions, list) or len(actions) != len(_ACTIONS):
        _reject("IS_RELEASE_SUPPLY_CHAIN", "GitHub Action set differs")
    projected: list[tuple[str, str]] = []
    for action in actions:
        action = _exact(action, {"repository", "commit"}, "IS_RELEASE_SUPPLY_CHAIN", "GitHub Action")
        if not isinstance(action["commit"], str) or not _SHA.fullmatch(action["commit"]):
            _reject("IS_RELEASE_SUPPLY_CHAIN", "GitHub Action is not pinned to a commit")
        projected.append((action["repository"], action["commit"]))
    if projected != _ACTIONS:
        _reject("IS_RELEASE_SUPPLY_CHAIN", "GitHub Action commit pin differs")

    if plan["release_assets"] != _ASSETS or len(set(plan["release_assets"])) != len(_ASSETS):
        _reject("IS_RELEASE_ASSET", "release asset set differs")
    if plan["real_surfaces"] != _SURFACES or len(set(plan["real_surfaces"])) != len(_SURFACES):
        _reject("IS_RELEASE_SURFACE", "real release surface matrix differs")

    evidence = _exact(plan["evidence"], {
        "verification_verdicts", "lifecycle_states", "retain_all_attempts", "missing_is_pass", "rendered_state_is_authority",
    }, "IS_RELEASE_EVIDENCE", "evidence")
    if evidence != {
        "verification_verdicts": ["PASS", "FAIL", "INCONCLUSIVE", "INVALID"],
        "lifecycle_states": ["queued", "running", "completed", "cancelled", "failed", "stale", "superseded"],
        "retain_all_attempts": True, "missing_is_pass": False, "rendered_state_is_authority": False,
    }:
        _reject("IS_RELEASE_EVIDENCE", "evidence distinctions differ")

    publication = _exact(plan["publication"], {
        "github_release", "ghcr", "pypi", "draft_before_publish", "complete_asset_set_before_publish",
        "annotated_tag_required", "immutable_release_required", "irreversible_human_gate",
        "built_in_github_token_only", "user_managed_secret_allowed", "minimum_permissions",
        "publish_before_all_gates",
    }, "IS_RELEASE_PUBLICATION", "publication")
    if publication != {
        "github_release": True, "ghcr": True, "pypi": False, "draft_before_publish": True,
        "complete_asset_set_before_publish": True, "annotated_tag_required": True,
        "immutable_release_required": True, "irreversible_human_gate": "IS6-U06-IMMUTABLE-PUBLICATION",
        "built_in_github_token_only": True, "user_managed_secret_allowed": False,
        "minimum_permissions": ["contents:write", "packages:write", "id-token:write", "attestations:write"],
        "publish_before_all_gates": False,
    }:
        _reject("IS_RELEASE_PUBLICATION", "publication or human-gate contract differs")

    download = _exact(plan["download_verification"], {
        "credential_free", "fresh_temporary_custody", "verify_release_immutability",
        "verify_every_asset_digest", "verify_artifact_attestations", "pull_images_by_digest",
        "replay_all_real_surfaces", "reconcile_github_release_and_ghcr", "shipping_without_verification",
    }, "IS_RELEASE_DOWNLOAD", "download verification")
    if download != {
        "credential_free": True, "fresh_temporary_custody": True, "verify_release_immutability": True,
        "verify_every_asset_digest": True, "verify_artifact_attestations": True,
        "pull_images_by_digest": True, "replay_all_real_surfaces": True,
        "reconcile_github_release_and_ghcr": True, "shipping_without_verification": False,
    }:
        _reject("IS_RELEASE_DOWNLOAD", "downloaded-release verification differs")

    if plan["non_goals"] != _NON_GOALS or len(set(plan["non_goals"])) != len(_NON_GOALS):
        _reject("IS_RELEASE_NON_GOAL", "release non-goals differ")

    digest = "sha256:" + hashlib.sha256(canonical_bytes(plan)).hexdigest()
    return {
        "schema_version": "incidentseal-release-plan-validation/v1",
        "verification_verdict": "PASS",
        "plan_digest": digest,
        "release_version": "0.1.0",
        "workflow_verification_required": True,
        "package_artifacts": 2,
        "release_assets": len(_ASSETS),
        "image_roles": 4,
        "real_surfaces": len(_SURFACES),
        "github_actions": len(_ACTIONS),
        "human_gates": 1,
        "released": False,
    }
