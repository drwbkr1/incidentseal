"""Host-owned build and topology-only runtime security probe."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any

from .topology import (
    COMPOSE_PATH,
    CONTRACT_PATH,
    IMPLEMENTATION_LOCK_PATH,
    ROOT,
    TOPOLOGY_LOCK_PATH,
    TopologyError,
    _docker_executable,
    _load,
    _normalize,
    _sha256_file,
    validate_platform_topology,
)


RUNTIME_LOCK_PATH = ROOT / "requirements" / "topology-runtime.lock.json"


PYTHON_PROBE = textwrap.dedent("""
import json, os, pathlib, re, socket
inp=pathlib.Path(os.environ['INCIDENTSEAL_INPUT']); out=pathlib.Path(os.environ['INCIDENTSEAL_OUTPUT'])
def denied(path):
    try: pathlib.Path(path).write_text('x'); return False
    except OSError: return True
root_denied=denied('/incidentseal-root-write-probe'); input_denied=denied(inp/'.write-probe')
probe=out/'.write-probe'; probe.write_text('ok'); output_ok=probe.read_text()=='ok'; probe.unlink()
try: s=socket.create_connection(('1.1.1.1',443),2); s.close(); egress=False
except OSError: egress=True
bad=[k for k in os.environ if re.search(r'(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_KEY|DOCKER_HOST)(?:_|$)',k)]
endpoints=not any(pathlib.Path(p).exists() for p in ['/var/run/docker.sock','/run/docker.sock','/var/run/podman/podman.sock'])
r={'schema_version':'incidentseal-runner-security-probe/v1','runner':'python','uid':os.getuid(),'gid':os.getgid(),'root_write_denied':root_denied,'input_write_denied':input_denied,'output_write_allowed':output_ok,'external_egress_denied':egress,'sensitive_environment_names':bad,'docker_endpoints_absent':endpoints}
r['verdict']='PASS' if all([r['uid']==65532,r['gid']==65532,root_denied,input_denied,output_ok,egress,not bad,endpoints]) else 'FAIL'
print(json.dumps(r,separators=(',',':'),sort_keys=True))
""").strip()

NODE_PROBE = textwrap.dedent("""
const fs=require('node:fs'); const net=require('node:net');
const inp=process.env.INCIDENTSEAL_INPUT, out=process.env.INCIDENTSEAL_OUTPUT;
const denied=(p)=>{try{fs.writeFileSync(p,'x');return false}catch{return true}};
const rootDenied=denied('/incidentseal-root-write-probe'), inputDenied=denied(inp+'/.write-probe');
const op=out+'/.write-probe'; fs.writeFileSync(op,'ok'); const outputOk=fs.readFileSync(op,'utf8')==='ok'; fs.unlinkSync(op);
const bad=Object.keys(process.env).filter(k=>/(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_KEY|DOCKER_HOST)(?:_|$)/.test(k));
const endpoints=['/var/run/docker.sock','/run/docker.sock','/var/run/podman/podman.sock'].every(p=>!fs.existsSync(p));
const finish=(egress)=>{const r={schema_version:'incidentseal-runner-security-probe/v1',runner:'node',uid:process.getuid(),gid:process.getgid(),root_write_denied:rootDenied,input_write_denied:inputDenied,output_write_allowed:outputOk,external_egress_denied:egress,sensitive_environment_names:bad,docker_endpoints_absent:endpoints};r.verdict=[r.uid===65532,r.gid===65532,rootDenied,inputDenied,outputOk,egress,bad.length===0,endpoints].every(Boolean)?'PASS':'FAIL';console.log(JSON.stringify(r));process.exitCode=r.verdict==='PASS'?0:1};
const s=net.createConnection({host:'1.1.1.1',port:443}); let done=false; const end=x=>{if(done)return;done=true;s.destroy();finish(x)};s.setTimeout(2000,()=>end(true));s.on('error',()=>end(true));s.on('connect',()=>end(false));
""").strip()


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _run(docker: str, arguments: list[str], *, env: dict[str, str] | None = None, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run([docker, *arguments], cwd=ROOT, env=env, text=True, encoding="utf-8", capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TopologyError("IS_RUNTIME_DOCKER", "host Docker command could not execute", io_error=True) from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        message = detail[-1][:500] if detail else "Docker command failed"
        raise TopologyError("IS_RUNTIME_DOCKER", message)
    return result


def _image_lock(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["role"]: item for item in _load(ROOT / contract["image_lock"]["path"])["images"]}


def _runtime_lock_images(contract_digest: str) -> dict[str, dict[str, Any]]:
    if not RUNTIME_LOCK_PATH.exists():
        return {}
    lock = _load(RUNTIME_LOCK_PATH)
    try:
        contract_revision = _load(CONTRACT_PATH)["revision"]
        valid = all(
            [
                lock["schema_version"] == "incidentseal-topology-runtime-lock/v1",
                lock["contract"] == {
                    "path": "contracts/topology-v1.json",
                    "sha256": contract_digest,
                    "revision": contract_revision,
                },
                lock["topology_contract_lock"] == {
                    "path": "requirements/topology-contract.lock.json",
                    "sha256": _sha256_file(TOPOLOGY_LOCK_PATH),
                },
                lock["implementation_lock"] == {
                    "path": "requirements/topology-implementation.lock.json",
                    "sha256": _sha256_file(IMPLEMENTATION_LOCK_PATH),
                },
            ]
        )
        images = lock["images"]
        by_role = {item["role"]: item for item in images}
    except (KeyError, TypeError) as error:
        raise TopologyError("IS_RUNTIME_LOCK", "runtime lock shape is invalid") from error
    if not valid or list(by_role) != ["database", "migration", "python-runner", "node-runner"]:
        raise TopologyError("IS_RUNTIME_LOCK", "runtime lock does not bind the active topology inputs")
    return by_role


def _build_images(docker: str, contract: dict[str, Any]) -> tuple[dict[str, str], list[dict[str, Any]]]:
    digest = _sha256_file(CONTRACT_PATH)
    locked_images = _runtime_lock_images(digest)
    short = digest.split(":", 1)[1][:16]
    images = _image_lock(contract)
    builds = {
        "database": ("containers/database", "INCIDENTSEAL_POSTGRES_IMAGE", images["postgresql"]["index_reference"], "70:70"),
        "migration": ("containers/migration", "INCIDENTSEAL_POSTGRES_IMAGE", images["postgresql"]["index_reference"], "70:70"),
        "python-runner": ("containers/python-runner", "INCIDENTSEAL_PYTHON_IMAGE", images["python_runner"]["index_reference"], "65532:65532"),
        "node-runner": ("containers/node-runner", "INCIDENTSEAL_NODE_IMAGE", images["node_runner"]["index_reference"], "65532:65532"),
    }
    identities: dict[str, str] = {}
    receipts: list[dict[str, Any]] = []
    environment = os.environ.copy()
    environment["DOCKER_BUILDKIT"] = "1"
    for role, (context, arg_name, base, expected_user) in builds.items():
        tag = f"incidentseal-local/{role}:{short}"
        existing = subprocess.run([docker, "image", "inspect", tag], cwd=ROOT, text=True, encoding="utf-8", capture_output=True, check=False)
        if existing.returncode == 0:
            inspected = json.loads(existing.stdout)[0]
            labels = inspected["Config"].get("Labels") or {}
            if inspected["Config"].get("User") == expected_user and labels.get("dev.incidentseal.contract-digest") == digest and labels.get("dev.incidentseal.build-role") == role:
                if locked_images and (
                    locked_images[role].get("tag") != tag
                    or locked_images[role].get("image_id") != inspected["Id"]
                    or locked_images[role].get("user") != expected_user
                ):
                    raise TopologyError("IS_RUNTIME_LOCK", f"{role} local image differs from the runtime lock")
                identities[role] = inspected["Id"]
                receipts.append({"role": role, "tag": tag, "image_id": inspected["Id"], "build_status": "reused-verified", "build_log_digest": None})
                continue
        if locked_images:
            raise TopologyError("IS_RUNTIME_STALE", f"{role} runtime-lock image is unavailable or invalid")
        result = _run(docker, ["build", "--network=none", "--pull=false", "--no-cache", "--progress=plain", "--label", f"dev.incidentseal.contract-digest={digest}", "--label", f"dev.incidentseal.build-role={role}", "--build-arg", f"{arg_name}={base}", "--tag", tag, str(ROOT / context)], env=environment, timeout=300)
        inspected = json.loads(_run(docker, ["image", "inspect", tag]).stdout)[0]
        image_id = inspected["Id"]
        if inspected["Config"].get("User") != expected_user or not image_id.startswith("sha256:"):
            raise TopologyError("IS_RUNTIME_IMAGE", f"{role} built identity or user differs from contract")
        identities[role] = image_id
        receipts.append({"role": role, "tag": tag, "image_id": image_id, "build_status": "built", "build_log_digest": _sha((result.stdout + result.stderr).encode())})
    return identities, receipts


def _compose_env(contract: dict[str, Any], identities: dict[str, str], custody: Path) -> tuple[dict[str, str], str, str]:
    contract_digest = _sha256_file(CONTRACT_PATH)
    suffix = contract_digest.split(":", 1)[1][:16]
    project = f"incidentseal-{suffix}"
    run_id = f"isrun-{suffix}"
    env = os.environ.copy()
    for key in list(env):
        if key.upper().startswith(("INCIDENTSEAL_", "COMPOSE_")) or key.upper() in {"DOCKER_HOST", "DOCKER_CONTEXT"}:
            env.pop(key, None)
    env.update({
        "INCIDENTSEAL_PROJECT_NAME": project,
        "INCIDENTSEAL_CONTRACT_DIGEST": contract_digest,
        "INCIDENTSEAL_MANIFEST_DIGEST": "not-used",
        "INCIDENTSEAL_RUN_ID": run_id,
        "INCIDENTSEAL_DATABASE_IMAGE": identities["database"],
        "INCIDENTSEAL_MIGRATION_IMAGE": identities["migration"],
        "INCIDENTSEAL_PYTHON_IMAGE": identities["python-runner"],
        "INCIDENTSEAL_NODE_IMAGE": identities["node-runner"],
        "INCIDENTSEAL_INPUT_DIR": str(custody / "input"),
        "INCIDENTSEAL_PYTHON_OUTPUT_DIR": str(custody / "python-output"),
        "INCIDENTSEAL_NODE_OUTPUT_DIR": str(custody / "node-output"),
    })
    return env, project, run_id


def _compose_args(env_file: Path) -> list[str]:
    return ["compose", "--ansi", "never", "--env-file", str(env_file), "-f", str(COMPOSE_PATH)]


def _inspect_container(docker: str, name: str, image_id: str, user: str, network: str) -> dict[str, Any]:
    value = json.loads(_run(docker, ["inspect", name]).stdout)[0]
    host = value["HostConfig"]
    mounts = value.get("Mounts", [])
    passed = all([
        value.get("Image") == image_id,
        value["Config"].get("User") == user,
        host.get("ReadonlyRootfs") is True,
        host.get("Privileged") is False,
        "ALL" in (host.get("CapDrop") or []),
        "no-new-privileges:true" in (host.get("SecurityOpt") or []),
        not (host.get("PortBindings") or {}),
        set(value.get("NetworkSettings", {}).get("Networks", {})) == {network},
        not any("docker.sock" in str(item).lower() or "docker_engine" in str(item).lower() for item in mounts),
    ])
    if not passed:
        raise TopologyError("IS_RUNTIME_HARDENING", f"{name} runtime inspection differs from contract")
    return {"name": name, "container_id": value["Id"], "image_id": value["Image"], "user": value["Config"].get("User"), "read_only_root": host.get("ReadonlyRootfs"), "privileged": host.get("Privileged"), "cap_drop": host.get("CapDrop"), "security_opt": host.get("SecurityOpt"), "network": network, "mount_count": len(mounts)}


def runtime_probe() -> dict[str, Any]:
    static = validate_platform_topology()
    docker = _docker_executable()
    contract = _load(CONTRACT_PATH)
    identities, build_receipts = _build_images(docker, contract)
    with tempfile.TemporaryDirectory(prefix="incidentseal-runtime-") as temporary:
        custody = Path(temporary).resolve(strict=True)
        for name in ("input", "python-output", "node-output"):
            (custody / name).mkdir()
        contract_suffix = _sha256_file(CONTRACT_PATH).split(":", 1)[1][:16]
        (custody / "input" / "request.json").write_text(
            json.dumps(
                {
                    "schema_version": "incidentseal-runner-request/v1",
                    "run_id": f"isrun-{contract_suffix}",
                    "payload": {"probe": "incidentseal"},
                },
                separators=(",", ":"),
            ) + "\n",
            encoding="utf-8",
        )
        env_file = custody / "empty.env"
        env_file.write_text("", encoding="utf-8")
        env, project, run_id = _compose_env(contract, identities, custody)
        base = _compose_args(env_file)
        network = f"{project}_data"
        names = {"database": f"{project}-database-1", "migration": f"{project}-migration-probe", "python": f"{project}-python-probe", "node": f"{project}-node-probe"}
        volume = f"{project}_database-data"
        if _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip() or _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip():
            raise TopologyError("IS_RUNTIME_STALE", "pre-existing containers or network conflict with the controlled probe")
        existing_volume = _run(docker, ["volume", "ls", "-q", "--filter", f"name=^{volume}$"]).stdout.strip()
        resumed_volume = False
        if existing_volume:
            volume_inspect = json.loads(_run(docker, ["volume", "inspect", volume]).stdout)[0]
            labels = volume_inspect.get("Labels") or {}
            if labels.get("dev.incidentseal.contract-digest") != _sha256_file(CONTRACT_PATH) or labels.get("dev.incidentseal.manifest-digest") != "not-used":
                raise TopologyError("IS_RUNTIME_STALE", "pre-existing volume does not match the controlled topology")
            resumed_volume = True
        inspections: list[dict[str, Any]] = []
        probes: list[dict[str, Any]] = []
        try:
            model = json.loads(_run(docker, [*base, "config", "--format", "json"], env=env).stdout)
            normalized = _normalize(model, _sha256_file(CONTRACT_PATH))
            by_id = {item["id"]: item for item in normalized["services"]}
            expected_ids = identities
            if any(by_id[key]["image"] != value for key, value in expected_ids.items()):
                raise TopologyError("IS_RUNTIME_IMAGE", "runtime Compose render differs from actual image identities")
            _run(docker, [*base, "up", "-d", "--no-deps", "database"], env=env)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                health = json.loads(_run(docker, ["inspect", names["database"], "--format", "{{json .State.Health.Status}}"]).stdout)
                if health == "healthy":
                    break
                time.sleep(1)
            else:
                logs = subprocess.run([docker, "logs", names["database"]], cwd=ROOT, text=True, encoding="utf-8", capture_output=True, check=False)
                combined = (logs.stdout + logs.stderr).strip()
                tail = combined.splitlines()[-1][:350] if combined else "no database logs were available"
                raise TopologyError("IS_RUNTIME_HEALTH", f"PostgreSQL did not become healthy: {tail}")
            inspections.append(_inspect_container(docker, names["database"], expected_ids["database"], "70:70", network))
            migration = _run(docker, [*base, "run", "--name", names["migration"], "--no-deps", "migration", "--version"], env=env)
            probes.append({"runner": "migration", "verdict": "PASS", "output_digest": _sha(migration.stdout.encode())})
            inspections.append(_inspect_container(docker, names["migration"], identities["migration"], "70:70", network))
            python = _run(docker, [*base, "run", "--name", names["python"], "--no-deps", "python-runner", "-c", PYTHON_PROBE], env=env)
            python_probe = json.loads(python.stdout.strip().splitlines()[-1]); probes.append(python_probe)
            inspections.append(_inspect_container(docker, names["python"], identities["python-runner"], "65532:65532", network))
            node = _run(docker, [*base, "run", "--name", names["node"], "--no-deps", "node-runner", "-e", NODE_PROBE], env=env)
            node_probe = json.loads(node.stdout.strip().splitlines()[-1]); probes.append(node_probe)
            inspections.append(_inspect_container(docker, names["node"], identities["node-runner"], "65532:65532", network))
            if python_probe.get("verdict") != "PASS" or node_probe.get("verdict") != "PASS":
                raise TopologyError("IS_RUNTIME_HARDENING", "runner security probe failed")
        finally:
            for name in (names["migration"], names["python"], names["node"]):
                subprocess.run([docker, "rm", "-f", name], cwd=ROOT, capture_output=True, check=False)
            subprocess.run([docker, *base, "down", "--remove-orphans"], cwd=ROOT, env=env, capture_output=True, check=False)
        containers_left = _run(docker, ["ps", "-aq", "--filter", f"name={project}"]).stdout.strip()
        network_left = _run(docker, ["network", "ls", "-q", "--filter", f"name=^{network}$"]).stdout.strip()
        volume_left = _run(docker, ["volume", "ls", "-q", "--filter", f"name=^{volume}$"]).stdout.strip()
        if containers_left or network_left or not volume_left:
            raise TopologyError("IS_RUNTIME_TEARDOWN", "runtime teardown or retained-volume state is invalid")
        return {"schema_version": "incidentseal-runtime-probe/v1", "verdict": "PASS", "mode": "platform-validation", "claim_scope": "topology-security-only", "project_name": project, "run_id": run_id, "contract_digest": _sha256_file(CONTRACT_PATH), "static_validation": static.data, "images": build_receipts, "inspections": inspections, "probes": probes, "retained_volume": volume, "resumed_volume": resumed_volume, "containers_removed": True, "network_removed": True, "runtime_started": True}
