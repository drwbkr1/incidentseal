#!/usr/bin/env python3
"""Prove that security- and claim-relevant release-plan mutations fail closed."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from incidentseal.manifest import strict_load_bytes  # noqa: E402
from incidentseal.release_contract import ReleaseContractError, validate_release_plan  # noqa: E402


PLAN = ROOT / "fixtures" / "release" / "release-plan.valid.json"
MANIFEST = ROOT / "fixtures" / "release" / "mutations.json"
Mutator = Callable[[dict[str, Any]], None]


def _set(path: tuple[Any, ...], value: Any) -> Mutator:
    def mutate(plan: dict[str, Any]) -> None:
        target: Any = plan
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
    return mutate


def _pop(path: tuple[Any, ...]) -> Mutator:
    def mutate(plan: dict[str, Any]) -> None:
        target: Any = plan
        for part in path[:-1]:
            target = target[part]
        if isinstance(target, list):
            target.pop(path[-1])
        else:
            target.pop(path[-1])
    return mutate


MUTATORS: dict[str, Mutator] = {
    "schema-version": _set(("schema_version",), "incidentseal-release-plan/v2"),
    "unknown-top-level": _set(("unexpected",), True),
    "release-version": _set(("release", "version"), "0.1.1"),
    "release-tag": _set(("release", "tag"), "latest"),
    "release-source": _set(("release", "source_repository"), "https://example.invalid/repo"),
    "release-registry": _set(("release", "registry_repository"), "docker.io/example/incidentseal"),
    "release-platform": _set(("release", "platforms"), ["linux/arm64"]),
    "release-already-claimed": _set(("release", "released"), True),
    "workflow-not-required": _set(("workflow_verification", "required_before_packaging"), False),
    "workflow-command-drift": _set(("workflow_verification", "command"), "incidentseal verify --approve"),
    "agent-can-approve": _set(("workflow_verification", "agent_can_approve"), True),
    "workflow-docker-socket": _set(("workflow_verification", "docker_socket"), "mounted"),
    "workflow-secret": _set(("workflow_verification", "secrets"), "allowed"),
    "workflow-host-network": _set(("workflow_verification", "host_network"), True),
    "workflow-egress": _set(("workflow_verification", "runtime_egress"), "allowed"),
    "workflow-broad-mount": _set(("workflow_verification", "broad_host_mounts"), "allowed"),
    "package-runtime-dependency": _set(("package", "runtime_dependencies"), ["requests"]),
    "package-backend-drift": _set(("package", "build_backend"), "setuptools"),
    "package-entry-point-drift": _set(("package", "entry_points", "incidentseal"), "incidentseal:main"),
    "package-artifact-missing": _pop(("package", "artifacts", 1)),
    "package-no-repetition": _set(("package", "build_repetitions"), 1),
    "package-pypi-enabled": _set(("package", "pypi_publish"), True),
    "image-role-missing": _pop(("images", 3)),
    "image-user-root": _set(("images", 0, "runtime_user"), "0:0"),
    "image-mutable-authority": _set(("images", 1, "authority"), "version-tag"),
    "source-gate-drift": _set(("supply_chain", "source_gate"), "missing.json"),
    "redistribution-not-required": _set(("supply_chain", "redistribution_required_before_publish"), False),
    "noassertion-allowed": _set(("supply_chain", "unresolved_noassertion_allowed"), True),
    "notices-not-required": _set(("supply_chain", "third_party_notices_required"), False),
    "scanner-drift": _set(("supply_chain", "scanner"), "latest"),
    "critical-allowed": _set(("supply_chain", "critical_findings_allowed"), 1),
    "mutable-tags-authority": _set(("supply_chain", "mutable_tags_are_authority"), True),
    "action-floating-ref": _set(("supply_chain", "github_actions", 0, "commit"), "v7"),
    "action-pin-drift": _set(("supply_chain", "github_actions", 0, "commit"), "0" * 40),
    "release-asset-missing": _pop(("release_assets", 8)),
    "workflow-surface-missing": _pop(("real_surfaces", 1)),
    "verdict-collapsed": _pop(("evidence", "verification_verdicts", 2)),
    "lifecycle-collapsed": _pop(("evidence", "lifecycle_states", 6)),
    "attempt-retention-disabled": _set(("evidence", "retain_all_attempts"), False),
    "missing-promoted": _set(("evidence", "missing_is_pass"), True),
    "rendered-authority": _set(("evidence", "rendered_state_is_authority"), True),
    "draft-gate-disabled": _set(("publication", "draft_before_publish"), False),
    "immutability-disabled": _set(("publication", "immutable_release_required"), False),
    "human-gate-drift": _set(("publication", "irreversible_human_gate"), "none"),
    "user-secret-allowed": _set(("publication", "user_managed_secret_allowed"), True),
    "permission-missing": _pop(("publication", "minimum_permissions", 3)),
    "pre-gate-publish": _set(("publication", "publish_before_all_gates"), True),
    "credentialed-download": _set(("download_verification", "credential_free"), False),
    "asset-digest-not-verified": _set(("download_verification", "verify_every_asset_digest"), False),
    "mutable-image-pull": _set(("download_verification", "pull_images_by_digest"), False),
    "real-surface-replay-disabled": _set(("download_verification", "replay_all_real_surfaces"), False),
    "shipping-unverified": _set(("download_verification", "shipping_without_verification"), True),
    "scope-expansion": _pop(("non_goals", 0)),
}


def run() -> dict[str, Any]:
    base = strict_load_bytes(PLAN.read_bytes())
    manifest = strict_load_bytes(MANIFEST.read_bytes())
    entries = manifest.get("mutations") if isinstance(manifest, dict) else None
    if manifest.get("schema_version") != "incidentseal-release-mutations/v1" or not isinstance(entries, list):
        raise RuntimeError("mutation manifest differs")
    if [item.get("id") for item in entries] != list(MUTATORS):
        raise RuntimeError("mutation manifest order or scope differs")

    results: list[dict[str, str]] = []
    for entry in entries:
        identifier = entry["id"]
        expected = entry["expected_code"]
        candidate = deepcopy(base)
        MUTATORS[identifier](candidate)
        try:
            validate_release_plan(candidate)
        except ReleaseContractError as error:
            if error.code != expected:
                raise RuntimeError(f"{identifier} returned {error.code}, expected {expected}") from error
            results.append({"id": identifier, "status": "PASS", "error_code": error.code})
        else:
            raise RuntimeError(f"{identifier} did not fail closed")
    return {
        "schema_version": "incidentseal-release-mutation-result/v1",
        "verification_verdict": "PASS",
        "mutations": len(results),
        "passed": len(results),
        "results": results,
        "docker_accessed": False,
        "artifact_built": False,
        "release_published": False,
    }


def main() -> int:
    try:
        print(json.dumps(run(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        print(json.dumps({
            "schema_version": "incidentseal-release-mutation-result/v1",
            "verification_verdict": "INVALID",
            "error": {"code": "IS_RELEASE_MUTATION", "message": str(error)},
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
