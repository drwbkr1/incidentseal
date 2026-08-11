"""Dependency-free validation for the bounded approved-workflow execution contract."""

from __future__ import annotations

from typing import Any

from .manifest import canonical_bytes


class WorkflowContractError(ValueError):
    """A stable fail-closed workflow execution contract error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


EXPECTED: dict[str, dict[str, Any]] = {
    "identity": {
        "manifest_schema": "incidentseal-workflow/v1",
        "approval_schema": "incidentseal-manifest-approval/v1",
        "command": "incidentseal verify --manifest PATH --json",
        "event_stream_command": "incidentseal run events --run-id ID --jsonl",
    },
    "authority": {
        "required_status": "MATCH", "exact_manifest_digest": True, "exact_workflow_id": True,
        "exact_repository_remote": True, "exact_manifest_path": True, "unexpired": True,
        "agent_can_approve": False, "recheck_before_each_step": True,
        "non_match_verdict": "INVALID", "non_match_exit": 12,
    },
    "repository": {
        "manifest_inside_git_worktree": True, "origin_remote_exact": True, "head_commit_exact": True,
        "worktree_clean": True, "tree_digest_algorithm": "sha256-git-ls-tree-z-v1",
        "tree_digest_command": ["git", "ls-tree", "-r", "-z", "--full-tree", "COMMIT"],
        "tracked_regular_files_only": True, "symlinks_denied": True, "submodules_denied": True,
    },
    "staging": {
        "source": "exact-commit-declared-inputs-only", "copy_only": True,
        "read_only_runtime_mount": "/workspace", "manifest_cwd_beneath_workspace": True,
        "overlapping_inputs_denied": True, "persistent_outputs_supported": False,
        "maximum_files": 4096, "maximum_total_bytes": 104857600,
        "repository_custody_denied": True, "onedrive_custody_denied": True,
        "symlink_reparse_escape_denied": True, "temporary_staging_removed_after_terminal": True,
    },
    "runtime": {
        "supported_runners": ["python", "node"], "unsupported_runner_verdict": "INVALID",
        "unsupported_runner_exit": 12,
        "image_authority": "requirements/topology-runtime.lock.json#exact-image-id",
        "direct_argv_without_shell": True, "host_cli_owns_docker": True, "docker_socket": "denied",
        "secrets": "denied", "privileged": False, "host_network": False, "runtime_network": "none",
        "broad_host_mounts": "denied", "read_only_root": True, "numeric_user": "65532:65532",
        "capabilities": "drop-all", "no_new_privileges": True, "pids_limit": 64,
        "memory_bytes": 536870912,
        "tmpfs": "/tmp:size=67108864,mode=0700,uid=65532,gid=65532",
        "environment_allowlist": ["HOME", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "TZ"],
        "host_environment_forwarded": False, "exact_run_and_step_labels": True,
        "exact_owned_container_stop_only": True,
    },
    "evidence": {
        "state_root": "platform-default-incidentseal-runs-v1", "outside_repository": True,
        "outside_onedrive": True, "restrictive_custody": True, "append_only_events": True,
        "event_schema": "incidentseal-run-event/v1", "agent_event_stream_read_only": True,
        "event_rewrite_denied": True, "atomic_fsync_before_progress": True,
        "content_addressed_step_records": True, "capture_policy_from_manifest": True,
        "capture_limit_enforced_before_write": True, "portable_receipt_after_terminal": True,
        "verification_verdicts": ["PASS", "FAIL", "INCONCLUSIVE", "INVALID"],
        "lifecycle_states": ["queued", "running", "completed", "cancelled", "failed", "stale", "superseded"],
        "retain_attempts": "all",
    },
    "recovery": {
        "active_key": "repository-remote+workflow-id+manifest-digest+commit+tree-digest",
        "same_key_resumes_nonterminal_run": True, "different_digest_never_resumes": True,
        "terminal_run_never_rewritten": True,
        "safe_step_replay_basis": "read-only-input-no-network-no-persistent-output",
        "started_step_reobserved_before_replay": True, "unknown_owned_runtime": "INCONCLUSIVE",
        "conflicting_owned_runtime": "FAIL", "interrupt_stops_exact_owned_container": True,
        "interrupt_lifecycle": "cancelled", "interrupt_verdict": None, "interrupt_exit": 20,
    },
    "claim": {
        "required_steps_all_pass": True, "dependency_order_enforced": True,
        "unexpected_step_exit": "FAIL", "missing_required_evidence": "INCONCLUSIVE",
        "invalid_policy_input_or_custody": "INVALID", "non_completed_lifecycle_verdict": None,
        "claim_permitted_only_on_pass": True,
    },
    "cli": {
        "stdout": "one-incidentseal-cli-envelope-v1-json-line", "stderr": "diagnostics-only",
        "data_includes_run_id": True, "evidence_references_include_sha256": True,
        "process_exit_matches_envelope": True, "pass_exit": 0, "fail_exit": 10,
        "inconclusive_exit": 11, "invalid_exit": 12, "cancelled_exit": 20,
        "failed_lifecycle_exit": 21, "stale_exit": 22, "superseded_exit": 23,
    },
    "release_gate": {
        "required_before_packaging": True, "credential_free_public_replay_required": True,
        "package_build_before_pass": False,
    },
}

SECTION_CODES = {
    "identity": "IS_WORKFLOW_IDENTITY", "authority": "IS_WORKFLOW_AUTHORITY",
    "repository": "IS_WORKFLOW_REPOSITORY", "staging": "IS_WORKFLOW_STAGING",
    "runtime": "IS_WORKFLOW_RUNTIME", "evidence": "IS_WORKFLOW_EVIDENCE",
    "recovery": "IS_WORKFLOW_RECOVERY", "claim": "IS_WORKFLOW_CLAIM",
    "cli": "IS_WORKFLOW_CLI", "release_gate": "IS_WORKFLOW_RELEASE_GATE",
}


def _reject(code: str, message: str) -> None:
    raise WorkflowContractError(code, message)


def validate_execution_contract(value: Any) -> dict[str, Any]:
    top = {"schema_version", "contract_id", "revision", *EXPECTED}
    if not isinstance(value, dict) or set(value) != top:
        _reject("IS_WORKFLOW_SCHEMA", "workflow execution contract shape differs")
    if value.get("schema_version") != "incidentseal-workflow-execution-contract/v1":
        _reject("IS_WORKFLOW_SCHEMA", "workflow execution contract version differs")
    if value.get("contract_id") != "INCIDENTSEAL-WORKFLOW-EXECUTION-001" or value.get("revision") != 1:
        _reject("IS_WORKFLOW_IDENTITY", "workflow execution contract identity differs")
    for section, expected in EXPECTED.items():
        actual = value.get(section)
        if not isinstance(actual, dict) or set(actual) != set(expected):
            _reject(SECTION_CODES[section], f"workflow {section} shape differs")
        for name, required in expected.items():
            if actual.get(name) != required or type(actual.get(name)) is not type(required):
                _reject(SECTION_CODES[section], f"workflow {section} value differs: {name}")
    return {
        "schema_version": "incidentseal-workflow-execution-contract-validation/v1",
        "verification_verdict": "PASS",
        "contract_digest": "sha256:" + __import__("hashlib").sha256(canonical_bytes(value)).hexdigest(),
        "supported_runners": len(value["runtime"]["supported_runners"]),
        "verification_verdicts": len(value["evidence"]["verification_verdicts"]),
        "lifecycle_states": len(value["evidence"]["lifecycle_states"]),
        "artifact_built": False,
        "docker_accessed": False,
        "workflow_executed": False,
        "approval_written": False,
    }
