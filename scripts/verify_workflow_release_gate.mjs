#!/usr/bin/env node
/** Independently verify the exact pre-package workflow implementation lock. */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function must(condition, message) {
  if (!condition) throw new Error(message);
}

function bytes(relative) {
  return readFileSync(resolve(root, relative));
}

function json(relative) {
  return JSON.parse(bytes(relative).toString("utf8"));
}

function digest(raw) {
  return `sha256:${createHash("sha256").update(raw).digest("hex")}`;
}

try {
  const lockPath = "requirements/workflow-verification-implementation.lock.json";
  const lock = json(lockPath);
  must(lock.schema_version === "incidentseal-workflow-verification-implementation-lock/v1", "implementation lock version differs");
  must(Array.isArray(lock.files) && lock.files.length > 0, "implementation lock file set is absent");
  for (const entry of lock.files) {
    const actual = digest(bytes(entry.path));
    must(actual === entry.sha256, `implementation drift: ${entry.path}`);
  }
  must(digest(bytes(lock.workflow_contract_lock.path)) === lock.workflow_contract_lock.sha256, "workflow contract binding differs");
  must(digest(bytes(lock.topology_runtime_lock.path)) === lock.topology_runtime_lock.sha256, "topology runtime binding differs");
  must(JSON.stringify(lock.supported_runners) === JSON.stringify(["python", "node"]), "supported runners differ");
  must(JSON.stringify(lock.runtime_dependencies) === "[]", "runtime dependencies differ");
  must(lock.approval_mutation_command === false, "approval mutation command became available");
  must(lock.production_approval_written === false, "implementation evidence claims a production approval write");

  const execution = json("fixtures/workflow-verification/execution-contract.valid.json");
  const authority = execution.authority;
  const runtime = execution.runtime;
  const evidence = execution.evidence;
  must(authority.required_status === "MATCH", "required authority differs");
  must(authority.agent_can_approve === false, "agent approval boundary differs");
  must(authority.recheck_before_each_step === true, "step authority recheck differs");
  must(runtime.host_cli_owns_docker === true, "Docker ownership differs");
  must(runtime.docker_socket === "denied" && runtime.secrets === "denied", "socket or secret boundary differs");
  must(runtime.privileged === false && runtime.host_network === false, "privilege or host-network boundary differs");
  must(runtime.runtime_network === "none", "runtime network differs");
  must(runtime.broad_host_mounts === "denied" && runtime.read_only_root === true, "mount or filesystem boundary differs");
  must(runtime.numeric_user === "65532:65532" && runtime.capabilities === "drop-all", "identity or capability boundary differs");
  must(runtime.no_new_privileges === true && runtime.pids_limit === 64 && runtime.memory_bytes === 536870912, "runtime hardening differs");
  must(JSON.stringify(evidence.verification_verdicts) === JSON.stringify(["PASS", "FAIL", "INCONCLUSIVE", "INVALID"]), "verdict channels differ");
  must(JSON.stringify(evidence.lifecycle_states) === JSON.stringify(["queued", "running", "completed", "cancelled", "failed", "stale", "superseded"]), "lifecycle channels differ");

  const milestone = json("contracts/IS-0006.json");
  const u02 = milestone.units.find((unit) => unit.id === "IS6-U02");
  const u03 = milestone.units.find((unit) => unit.id === "IS6-U03");
  const workflowExit = milestone.exit_conditions.find((item) => item.id === "EXIT-APPROVED-WORKFLOW-VERIFICATION");
  must(milestone.status === "active", "release milestone is not active");
  must(u02?.status === "in_progress", "workflow verification unit is not active");
  must(u03?.status === "planned", "packaging advanced before workflow verification");
  must(workflowExit?.status === "pending", "workflow exit is not pending real approval");

  console.log(JSON.stringify({
    schema_version: "incidentseal-workflow-release-gate-node/v1",
    verification_verdict: "PASS",
    implementation_lock_digest: digest(bytes(lockPath)),
    locked_files: lock.files.length,
    supported_runners: lock.supported_runners,
    approval_mutation_command: false,
    runtime_network: "none",
    packaging_status: u03.status,
  }));
} catch (error) {
  console.error(JSON.stringify({
    schema_version: "incidentseal-workflow-release-gate-node/v1",
    verification_verdict: "INVALID",
    error: { code: "IS_WORKFLOW_RELEASE_GATE", message: String(error?.message ?? error) },
  }));
  process.exitCode = 1;
}
