"""Fixed host-owned Docker/PostgreSQL backup and clean-restore probe."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any
import uuid

from .backup_restore import BackupRestoreError, PG_DUMP_ARGV, PG_RESTORE_ARGV, receipt_digest, validate_receipt
from .database import _wait_healthy
from .journal_surface import _database_psql, _volume_snapshot, append_record
from .manifest import canonical_bytes, strict_load_bytes
from .reliability_surface import _load_retained_volume_lock, _volume_names
from .runtime import _build_images, _run
from .topology import CONTRACT_PATH, ROOT, TopologyError, _docker_executable, _load, _sha256_file, validate_platform_topology


IMPLEMENTATION_LOCK = ROOT / "requirements" / "backup-restore-implementation.lock.json"
SOURCE_PROJECT = "incidentseal-backup-source"
TARGET_PROJECT = "incidentseal-restore-target"
SOURCE_VOLUME = "incidentseal-backup-source-data"
TARGET_VOLUME = "incidentseal-restore-target-data"
SOURCE_NETWORK = "incidentseal-backup-source-network"
TARGET_NETWORK = "incidentseal-restore-target-network"
SOURCE_DATABASE = "incidentseal-backup-source-database"
TARGET_DATABASE = "incidentseal-restore-target-database"
SURFACE_LABEL = "dev.incidentseal.backup-restore-surface"
EXPECTED_IMPLEMENTATION_PATHS = (
    "docs/backup-restore-implementation.md",
    "fixtures/backup-restore/implementation-mutations.json",
    "requirements/backup-restore-contract.lock.json",
    "requirements/retained-runtime-volumes.lock.json",
    "requirements/topology-runtime.lock.json",
    "scripts/test_backup_restore_implementation_mutations.py",
    "scripts/validate_backup_restore_implementation.py",
    "src/incidentseal/backup_restore.py",
    "src/incidentseal/backup_restore_surface.py",
    "src/incidentseal/cli.py",
    "tests/test_backup_restore_surface.py",
)
SECRET_ENV_RE = re.compile(r"(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_KEY|DOCKER_HOST)(?:_|$)")
TOC_FORBIDDEN_RE = re.compile(r"^[0-9]+; [0-9]+ [0-9]+ (?:ACL|DEFAULT ACL|ROLE|TABLESPACE|DATABASE)\b")
MIGRATION_NOTICE_RE = re.compile(
    r'^(?:psql:/opt/incidentseal/migrations/001-schema\.sql:[0-9]+:\s+)?NOTICE:\s+relation "([a-z0-9_]+)" already exists, skipping$'
)
EXPECTED_EXISTING_RELATIONS = {
    "verification_results",
    "incidentseal_schema_migrations",
    "incidentseal_run_events",
    "incidentseal_recovery_fences",
}


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_backup_restore_implementation_lock() -> str:
    """Require the complete host implementation to match its exact local lock."""

    try:
        lock = strict_load_bytes(IMPLEMENTATION_LOCK.read_bytes())
    except (OSError, ValueError) as error:
        raise TopologyError("IS_BACKUP_IMPLEMENTATION", "backup implementation lock is unreadable") from error
    if not isinstance(lock, dict) or lock.get("schema_version") != "incidentseal-backup-restore-implementation-lock/v1":
        raise TopologyError("IS_BACKUP_IMPLEMENTATION", "backup implementation lock version differs")
    entries = lock.get("files")
    if not isinstance(entries, list) or tuple(item.get("path") for item in entries if isinstance(item, dict)) != EXPECTED_IMPLEMENTATION_PATHS:
        raise TopologyError("IS_BACKUP_IMPLEMENTATION", "backup implementation lock scope differs")
    for entry in entries:
        path = ROOT / str(entry.get("path", ""))
        try:
            observed = _digest(path.read_bytes())
        except OSError as error:
            raise TopologyError("IS_BACKUP_IMPLEMENTATION", f"locked backup file is unavailable: {path.name}") from error
        if observed != entry.get("sha256"):
            raise TopologyError("IS_BACKUP_IMPLEMENTATION", f"backup implementation drift: {entry.get('path')}")
    bindings = {
        "backup_restore_contract_lock": "requirements/backup-restore-contract.lock.json",
        "topology_runtime_lock": "requirements/topology-runtime.lock.json",
        "protected_volume_lock": "requirements/retained-runtime-volumes.lock.json",
    }
    for field, relative in bindings.items():
        if lock.get(field) != {"path": relative, "sha256": _sha256_file(ROOT / relative)}:
            raise TopologyError("IS_BACKUP_IMPLEMENTATION", f"backup implementation {field} differs")
    if lock.get("runtime_dependencies") != []:
        raise TopologyError("IS_BACKUP_IMPLEMENTATION", "backup implementation added runtime dependencies")
    if lock.get("agent_mutation_commands") != ["topology.backup-restore-probe"]:
        raise TopologyError("IS_BACKUP_IMPLEMENTATION", "backup mutation surface differs")
    if lock.get("arbitrary_backup_restore_command") is not False:
        raise TopologyError("IS_BACKUP_IMPLEMENTATION", "arbitrary backup or restore became available")
    return _digest(IMPLEMENTATION_LOCK.read_bytes())


def _safe_custody(path: Path) -> Path:
    candidate = path.resolve(strict=True)
    if ROOT == candidate or ROOT in candidate.parents or any(part.casefold() == "onedrive" for part in candidate.parts):
        raise TopologyError("IS_BACKUP_CUSTODY", "backup custody overlaps the repository or OneDrive")
    return candidate


def _labels(project: str, run_id: str) -> list[str]:
    values = {
        SURFACE_LABEL: "platform-validation",
        "dev.incidentseal.project": project,
        "dev.incidentseal.contract-digest": _sha256_file(CONTRACT_PATH),
        "dev.incidentseal.manifest-digest": "not-used",
        "dev.incidentseal.run-id": run_id,
    }
    arguments: list[str] = []
    for key, value in values.items():
        arguments.extend(["--label", f"{key}={value}"])
    return arguments


def _create_network(docker: str, name: str, project: str, run_id: str) -> None:
    _run(docker, ["network", "create", "--driver", "bridge", "--internal", *_labels(project, run_id), name])
    value = json.loads(_run(docker, ["network", "inspect", name]).stdout)[0]
    if value.get("Internal") is not True or value.get("Attachable") is not False or value.get("Ingress") is not False:
        raise TopologyError("IS_BACKUP_NETWORK", f"{name} is not a closed internal network")


def _create_volume(docker: str, name: str, project: str, run_id: str) -> None:
    _run(docker, ["volume", "create", *_labels(project, run_id), name])
    value = json.loads(_run(docker, ["volume", "inspect", name]).stdout)[0]
    labels = value.get("Labels") or {}
    if value.get("Name") != name or labels.get(SURFACE_LABEL) != "platform-validation" or labels.get("dev.incidentseal.project") != project:
        raise TopologyError("IS_BACKUP_CUSTODY", f"{name} volume identity differs")


def _create_database(
    docker: str,
    *,
    name: str,
    project: str,
    run_id: str,
    network: str,
    volume: str,
    image_id: str,
) -> None:
    command = [
        "create", "--name", name, "--platform", "linux/amd64", "--user", "70:70",
        "--read-only", "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--pids-limit", "128", "--network", network, "--network-alias", "database",
        "--mount", f"type=volume,source={volume},target=/var/lib/postgresql/incidentseal-data",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=67108864,uid=70,gid=70,mode=1777",
        "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16777216,uid=70,gid=70,mode=0775",
        "--health-cmd", "/usr/bin/pg_isready -h 127.0.0.1 -U incidentseal_admin -d incidentseal",
        "--health-interval", "5s", "--health-timeout", "3s", "--health-retries", "20",
        "--health-start-period", "10s",
        "--env", "PGDATA=/var/lib/postgresql/incidentseal-data/pgdata",
        "--env", "POSTGRES_DB=incidentseal", "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
        "--env", "POSTGRES_USER=incidentseal_admin", "--env", "TZ=UTC",
        *_labels(project, run_id), image_id,
    ]
    _run(docker, command)
    _inspect_container(docker, name, image_id, "70:70", network, [("volume", "/var/lib/postgresql/incidentseal-data", False)])
    _run(docker, ["start", name])
    _wait_healthy(docker, name)
    _inspect_container(docker, name, image_id, "70:70", network, [("volume", "/var/lib/postgresql/incidentseal-data", False)])


def _create_actor(
    docker: str,
    *,
    name: str,
    project: str,
    run_id: str,
    network: str,
    image_id: str,
    entrypoint: str | None = None,
    arguments: list[str] | None = None,
    mount: tuple[Path, bool] | None = None,
    extra_environment: dict[str, str] | None = None,
) -> None:
    command = [
        "create", "--name", name, "--platform", "linux/amd64", "--user", "70:70",
        "--read-only", "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--pids-limit", "64", "--network", network,
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=16777216,uid=70,gid=70,mode=0700",
        "--env", "PGHOST=database", "--env", "PGUSER=incidentseal_admin",
        "--env", "PGDATABASE=incidentseal", "--env", "PGCONNECT_TIMEOUT=5", "--env", "TZ=UTC",
        *_labels(project, run_id),
    ]
    for key, value in sorted((extra_environment or {}).items()):
        command.extend(["--env", f"{key}={value}"])
    expected_mounts: list[tuple[str, str, bool]] = []
    if mount is not None:
        source, read_only = mount
        specification = f"type=bind,source={source},target=/incidentseal/backup"
        if read_only:
            specification += ",readonly"
        command.extend(["--mount", specification])
        expected_mounts.append(("bind", "/incidentseal/backup", read_only))
    if entrypoint is not None:
        command.extend(["--entrypoint", entrypoint])
    command.append(image_id)
    command.extend(arguments or [])
    _run(docker, command)
    _inspect_container(docker, name, image_id, "70:70", network, expected_mounts)


def _inspect_container(
    docker: str,
    name: str,
    image_id: str,
    user: str,
    network: str,
    expected_mounts: list[tuple[str, str, bool]],
) -> dict[str, Any]:
    value = json.loads(_run(docker, ["inspect", name]).stdout)[0]
    host = value.get("HostConfig") or {}
    labels = value.get("Config", {}).get("Labels") or {}
    mounts = value.get("Mounts") or []
    actual_mounts = sorted((item.get("Type"), item.get("Destination"), not bool(item.get("RW"))) for item in mounts)
    expected = sorted(expected_mounts)
    env_names = [item.split("=", 1)[0] for item in (value.get("Config", {}).get("Env") or [])]
    security = host.get("SecurityOpt") or []
    networks = set((value.get("NetworkSettings", {}).get("Networks") or {}).keys())
    passed = all(
        [
            value.get("Image") == image_id,
            value.get("Config", {}).get("User") == user,
            host.get("ReadonlyRootfs") is True,
            host.get("Privileged") is False,
            "ALL" in (host.get("CapDrop") or []),
            security in (["no-new-privileges"], ["no-new-privileges:true"]),
            not (host.get("PortBindings") or {}),
            host.get("NetworkMode") == network,
            networks == {network},
            actual_mounts == expected,
            not any("docker.sock" in str(item).lower() or "docker_engine" in str(item).lower() for item in mounts),
            not any(SECRET_ENV_RE.search(name_value) for name_value in env_names),
            labels.get(SURFACE_LABEL) == "platform-validation",
        ]
    )
    if not passed:
        raise TopologyError("IS_BACKUP_HARDENING", f"{name} runtime boundary differs")
    return {
        "name": name,
        "container_id": value.get("Id"),
        "image_id": value.get("Image"),
        "network": network,
        "mounts": actual_mounts,
        "read_only_root": host.get("ReadonlyRootfs"),
        "security_opt": security,
    }


def _start_actor(docker: str, name: str, *, require_empty_stderr: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [docker, "start", "--attach", name], cwd=ROOT, text=True, encoding="utf-8",
        capture_output=True, timeout=180, check=False,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip().splitlines()
        raise TopologyError("IS_BACKUP_RUNTIME", message[-1][:500] if message else f"{name} failed")
    if require_empty_stderr and result.stderr:
        raise TopologyError("IS_BACKUP_DIAGNOSTIC", f"{name} emitted stderr")
    return result


def _remove_container(docker: str, name: str) -> None:
    subprocess.run([docker, "rm", "--force", name], cwd=ROOT, capture_output=True, timeout=30, check=False)


def _query_json(docker: str, database: str, sql: str, *, user: str = "incidentseal_admin") -> Any:
    result = _database_psql(docker, database, sql, user=user)
    if result.returncode != 0:
        raise TopologyError("IS_BACKUP_DATABASE", (result.stderr or result.stdout).strip()[-500:])
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise TopologyError("IS_BACKUP_DATABASE", "database query returned no JSON")
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise TopologyError("IS_BACKUP_DATABASE", "database query did not return JSON") from error


SCHEMA_SQL = r"""SELECT jsonb_build_object(
  'tables', COALESCE((SELECT jsonb_agg(jsonb_build_object('name', c.relname, 'row_security', c.relrowsecurity, 'replica_identity', c.relreplident) ORDER BY c.relname)
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind='r'), '[]'::jsonb),
  'columns', COALESCE((SELECT jsonb_agg(jsonb_build_object('table', c.relname, 'name', a.attname, 'position', a.attnum, 'type', pg_catalog.format_type(a.atttypid,a.atttypmod), 'not_null', a.attnotnull, 'default', pg_catalog.pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attnum)
    FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
    WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped), '[]'::jsonb),
  'constraints', COALESCE((SELECT jsonb_agg(jsonb_build_object('table', c.relname, 'name', x.conname, 'type', x.contype, 'definition', pg_catalog.pg_get_constraintdef(x.oid,true)) ORDER BY c.relname,x.conname)
    FROM pg_catalog.pg_constraint x JOIN pg_catalog.pg_class c ON c.oid=x.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public'), '[]'::jsonb),
  'indexes', COALESCE((SELECT jsonb_agg(jsonb_build_object('table', t.relname, 'name', i.relname, 'definition', pg_catalog.pg_get_indexdef(i.oid)) ORDER BY t.relname,i.relname)
    FROM pg_catalog.pg_index x JOIN pg_catalog.pg_class i ON i.oid=x.indexrelid JOIN pg_catalog.pg_class t ON t.oid=x.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname='public'), '[]'::jsonb),
  'triggers', COALESCE((SELECT jsonb_agg(jsonb_build_object('table', c.relname, 'name', t.tgname, 'definition', pg_catalog.pg_get_triggerdef(t.oid,true)) ORDER BY c.relname,t.tgname)
    FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND NOT t.tgisinternal), '[]'::jsonb),
  'functions', COALESCE((SELECT jsonb_agg(jsonb_build_object('name', p.proname, 'arguments', pg_catalog.pg_get_function_identity_arguments(p.oid), 'result', pg_catalog.pg_get_function_result(p.oid), 'language', l.lanname, 'security_definer', p.prosecdef, 'config', p.proconfig, 'source', p.prosrc) ORDER BY p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid))
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_language l ON l.oid=p.prolang
    WHERE n.nspname='public' AND p.proname LIKE 'incidentseal_%'), '[]'::jsonb)
)::text;"""

JOURNAL_SQL = """SELECT COALESCE(jsonb_agg(jsonb_build_object('run_id',run_id::text,'sequence',sequence,'record_bytes',encode(record_bytes,'base64')) ORDER BY run_id,sequence),'[]'::jsonb)::text FROM public.incidentseal_run_events;"""
RESULTS_SQL = """SELECT COALESCE(jsonb_agg(jsonb_build_object('run_id',run_id,'runner',runner,'input_digest',input_digest,'result_digest',result_digest) ORDER BY run_id,runner),'[]'::jsonb)::text FROM public.verification_results;"""
ROLES_SQL = """SELECT COALESCE(jsonb_agg(jsonb_build_object('name',rolname,'superuser',rolsuper,'create_db',rolcreatedb,'create_role',rolcreaterole,'replication',rolreplication,'bypass_rls',rolbypassrls,'login',rolcanlogin) ORDER BY CASE rolname WHEN 'incidentseal_admin' THEN 0 ELSE 1 END),'[]'::jsonb)::text FROM pg_catalog.pg_roles WHERE rolname IN ('incidentseal_admin','incidentseal_runner');"""


def _measure_state(docker: str, database: str) -> dict[str, Any]:
    version = _query_json(
        docker, database,
        "SELECT jsonb_build_object('server_version_num',current_setting('server_version_num')::integer,'database',current_database())::text;",
    )
    schema = _query_json(docker, database, SCHEMA_SQL)
    journal = _query_json(docker, database, JOURNAL_SQL)
    results = _query_json(docker, database, RESULTS_SQL)
    roles = _query_json(docker, database, ROLES_SQL)
    if version != {"server_version_num": 180004, "database": "incidentseal"}:
        raise TopologyError("IS_BACKUP_SOURCE", "PostgreSQL version or database differs")
    if not isinstance(roles, list) or [item.get("name") for item in roles] != ["incidentseal_admin", "incidentseal_runner"]:
        raise TopologyError("IS_BACKUP_ROLE", "exact source role baseline is absent")
    run_ids = {item.get("run_id") for item in journal if isinstance(item, dict)}
    return {
        "postgres_version_num": version["server_version_num"],
        "schema": schema,
        "schema_digest": _digest(canonical_bytes(schema)),
        "journal": journal,
        "journal_digest": _digest(canonical_bytes(journal)),
        "journal_run_count": len(run_ids),
        "journal_event_count": len(journal),
        "verification_results": results,
        "verification_results_digest": _digest(canonical_bytes(results)),
        "verification_result_count": len(results),
        "roles": roles,
        "role_digest": _digest(canonical_bytes(roles)),
    }


def _normalize_toc(value: str) -> bytes:
    lines = [" ".join(line.split()) for line in value.splitlines() if line.strip() and not line.lstrip().startswith(";")]
    if not lines:
        raise TopologyError("IS_BACKUP_ARCHIVE", "archive TOC is empty")
    for line in lines:
        if TOC_FORBIDDEN_RE.search(line):
            raise TopologyError("IS_BACKUP_ARCHIVE", "archive TOC contains a forbidden global or privilege object")
    required = (
        "TABLE public verification_results",
        "TABLE public incidentseal_run_events",
        "TABLE DATA public verification_results",
        "TABLE DATA public incidentseal_run_events",
        "FUNCTION public incidentseal_append_event",
    )
    if any(not any(fragment in line for line in lines) for fragment in required):
        raise TopologyError("IS_BACKUP_ARCHIVE", "archive TOC omits required IncidentSeal objects")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _seed_source(docker: str, database: str) -> None:
    input_python = _digest(b"incidentseal-backup-python-input")
    result_python = _digest(b"incidentseal-backup-python-result")
    input_node = _digest(b"incidentseal-backup-node-input")
    result_node = _digest(b"incidentseal-backup-node-result")
    sql = (
        "INSERT INTO public.verification_results(run_id,runner,input_digest,result_digest) VALUES "
        f"('backup-python','python','{input_python}','{result_python}'),"
        f"('backup-node','node','{input_node}','{result_node}');"
    )
    inserted = _database_psql(docker, database, sql)
    if inserted.returncode != 0:
        raise TopologyError("IS_BACKUP_SOURCE", "synthetic verification results could not be inserted")
    vectors = json.loads((ROOT / "fixtures" / "journal" / "vectors.json").read_text(encoding="utf-8"))
    for case in vectors["cases"]:
        for record in case["records"]:
            append_record(docker, database, record)


def _migration_notice_count(stderr: str) -> int:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    matches = [MIGRATION_NOTICE_RE.fullmatch(line) for line in lines]
    if any(match is None or match.group(1) not in EXPECTED_EXISTING_RELATIONS for match in matches):
        raise TopologyError("IS_BACKUP_DIAGNOSTIC", "migration emitted an unexpected diagnostic")
    return len(lines)


def _run_migration(
    docker: str,
    *,
    name: str,
    project: str,
    run_id: str,
    network: str,
    image_id: str,
) -> dict[str, Any]:
    _create_actor(
        docker, name=name, project=project, run_id=run_id, network=network,
        image_id=image_id,
    )
    inspection = _inspect_container(docker, name, image_id, "70:70", network, [])
    result = _start_actor(docker, name, require_empty_stderr=False)
    inspection["stderr_notice_count"] = _migration_notice_count(result.stderr)
    _remove_container(docker, name)
    return inspection


def _expect_denied(docker: str, database: str, sql: str) -> bool:
    result = _database_psql(docker, database, sql, user="incidentseal_runner")
    combined = (result.stderr + result.stdout).lower()
    return result.returncode != 0 and "permission denied" in combined


def _wait_write_fence(docker: str, database: str, *, seconds: int = 20) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        active = _query_json(
            docker,
            database,
            "SELECT jsonb_build_object('sessions',count(*))::text FROM pg_catalog.pg_stat_activity WHERE application_name='incidentseal_backup_lock' AND state='active';",
        )
        if active == {"sessions": 1}:
            return
        time.sleep(0.25)
    raise TopologyError("IS_BACKUP_SNAPSHOT", "source write fence did not become active")


def _snapshot_write_is_blocked(docker: str, database: str) -> bool:
    result = _database_psql(
        docker,
        database,
        "SET statement_timeout='1s'; INSERT INTO public.verification_results(run_id,runner,input_digest,result_digest) VALUES ('forbidden','python','sha256:"
        + "1" * 64
        + "','sha256:"
        + "2" * 64
        + "');",
        user="incidentseal_runner",
    )
    combined = (result.stderr + result.stdout).lower()
    return result.returncode != 0 and "statement timeout" in combined


def backup_restore_probe() -> dict[str, Any]:
    """Create, inspect, restore, verify, restart, and remove one fixed synthetic backup."""

    static = validate_platform_topology()
    implementation_lock_digest = validate_backup_restore_implementation_lock()
    docker = _docker_executable()
    volume_lock, protected = _load_retained_volume_lock(docker)
    protected_before = _volume_snapshot(docker, protected)
    before_volumes = _volume_names(docker)
    contract = _load(CONTRACT_PATH)
    identities, image_receipts = _build_images(docker, contract)
    source_run = "isrun-backup-source"
    target_run = "isrun-restore-target"
    fixed_containers = {
        SOURCE_DATABASE,
        TARGET_DATABASE,
        "incidentseal-backup-source-migration",
        "incidentseal-backup-source-write-fence",
        "incidentseal-backup-source-dump",
        "incidentseal-backup-toc-inspector",
        "incidentseal-restore-target-restore",
        "incidentseal-restore-target-migration",
    }
    fixed_networks = {SOURCE_NETWORK, TARGET_NETWORK}
    fixed_volumes = {SOURCE_VOLUME, TARGET_VOLUME}
    checks: list[dict[str, Any]] = []
    inspections: list[dict[str, Any]] = []
    source_state: dict[str, Any] | None = None
    restored_state: dict[str, Any] | None = None
    restart_state: dict[str, Any] | None = None
    archive_digest: str | None = None
    archive_bytes = 0
    toc_digest: str | None = None
    toc_entries = 0
    negative_privileges: dict[str, str] = {}
    custody_path: Path | None = None

    def check(check_id: str, passed: bool, observed: Any) -> None:
        checks.append({"id": check_id, "status": "PASS" if passed else "FAIL", "observed": observed})
        if not passed:
            raise TopologyError("IS_BACKUP_VERIFICATION", f"{check_id} failed")

    stale_containers = [name for name in fixed_containers if _run(docker, ["ps", "-aq", "--filter", f"name=^{name}$"]).stdout.strip()]
    stale_networks = [name for name in fixed_networks if _run(docker, ["network", "ls", "-q", "--filter", f"name=^{name}$"]).stdout.strip()]
    stale_volumes = fixed_volumes.intersection(before_volumes)
    if stale_containers or stale_networks or stale_volumes:
        raise TopologyError("IS_BACKUP_STALE", "fixed backup/restore custody already exists")

    with tempfile.TemporaryDirectory(prefix="incidentseal-backup-restore-") as temporary:
        custody = _safe_custody(Path(temporary))
        custody_path = custody
        backup_dir = custody / "backup"
        backup_dir.mkdir()
        archive = backup_dir / "incidentseal.dump"
        try:
            _create_network(docker, SOURCE_NETWORK, SOURCE_PROJECT, source_run)
            _create_volume(docker, SOURCE_VOLUME, SOURCE_PROJECT, source_run)
            _create_database(
                docker, name=SOURCE_DATABASE, project=SOURCE_PROJECT, run_id=source_run,
                network=SOURCE_NETWORK, volume=SOURCE_VOLUME, image_id=identities["database"],
            )
            inspections.append(_inspect_container(
                docker, SOURCE_DATABASE, identities["database"], "70:70", SOURCE_NETWORK,
                [("volume", "/var/lib/postgresql/incidentseal-data", False)],
            ))
            inspections.append(_run_migration(
                docker, name="incidentseal-backup-source-migration", project=SOURCE_PROJECT,
                run_id=source_run, network=SOURCE_NETWORK, image_id=identities["migration"],
            ))
            _seed_source(docker, SOURCE_DATABASE)
            source_state = _measure_state(docker, SOURCE_DATABASE)
            check(
                "source-synthetic-state",
                source_state["journal_run_count"] == 3
                and source_state["journal_event_count"] == 7
                and source_state["verification_result_count"] == 2,
                {"journal_runs": source_state["journal_run_count"], "journal_events": source_state["journal_event_count"], "verification_results": source_state["verification_result_count"]},
            )

            lock_sql = (
                "BEGIN; LOCK TABLE public.verification_results, public.incidentseal_schema_migrations, "
                "public.incidentseal_run_events, public.incidentseal_recovery_fences IN SHARE MODE; "
                "SELECT pg_sleep(300);"
            )
            _create_actor(
                docker, name="incidentseal-backup-source-write-fence", project=SOURCE_PROJECT,
                run_id=source_run, network=SOURCE_NETWORK, image_id=identities["migration"],
                entrypoint="/usr/bin/psql",
                arguments=[
                    "--host=database", "--username=incidentseal_admin", "--dbname=incidentseal",
                    "--set=ON_ERROR_STOP=1", f"--command={lock_sql}",
                ],
                extra_environment={"PGAPPNAME": "incidentseal_backup_lock"},
            )
            _run(docker, ["start", "incidentseal-backup-source-write-fence"])
            _wait_write_fence(docker, SOURCE_DATABASE)
            check(
                "source-writes-blocked",
                _snapshot_write_is_blocked(docker, SOURCE_DATABASE),
                {"relation_share_fence": True, "write_statement_timeout_seconds": 1},
            )

            _create_actor(
                docker, name="incidentseal-backup-source-dump", project=SOURCE_PROJECT,
                run_id=source_run, network=SOURCE_NETWORK, image_id=identities["migration"],
                entrypoint="/usr/bin/pg_dump", arguments=PG_DUMP_ARGV[1:], mount=(backup_dir, False),
            )
            inspections.append(_inspect_container(
                docker, "incidentseal-backup-source-dump", identities["migration"], "70:70", SOURCE_NETWORK,
                [("bind", "/incidentseal/backup", False)],
            ))
            _start_actor(docker, "incidentseal-backup-source-dump")
            _remove_container(docker, "incidentseal-backup-source-dump")
            if not archive.is_file():
                raise TopologyError("IS_BACKUP_ARCHIVE", "pg_dump did not create the fixed archive")
            with archive.open("r+b") as stream:
                stream.flush()
                os.fsync(stream.fileno())
                stream.seek(0)
                archive_raw = stream.read()
            archive_digest = _digest(archive_raw)
            archive_bytes = len(archive_raw)
            check("custom-archive-created", archive_bytes > 0, {"digest": archive_digest, "bytes": archive_bytes})
            _remove_container(docker, "incidentseal-backup-source-write-fence")

            _create_actor(
                docker, name="incidentseal-backup-toc-inspector", project=SOURCE_PROJECT,
                run_id=source_run, network="none", image_id=identities["migration"],
                entrypoint="/usr/bin/pg_restore", arguments=["--list", "/incidentseal/backup/incidentseal.dump"],
                mount=(backup_dir, True),
            )
            toc_result = _start_actor(docker, "incidentseal-backup-toc-inspector")
            normalized_toc = _normalize_toc(toc_result.stdout)
            toc_digest = _digest(normalized_toc)
            toc_entries = len(normalized_toc.splitlines())
            _remove_container(docker, "incidentseal-backup-toc-inspector")
            check("normalized-toc-bound", toc_entries > 0, {"digest": toc_digest, "entries": toc_entries})

            _create_network(docker, TARGET_NETWORK, TARGET_PROJECT, target_run)
            _create_volume(docker, TARGET_VOLUME, TARGET_PROJECT, target_run)
            _create_database(
                docker, name=TARGET_DATABASE, project=TARGET_PROJECT, run_id=target_run,
                network=TARGET_NETWORK, volume=TARGET_VOLUME, image_id=identities["database"],
            )
            inspections.append(_inspect_container(
                docker, TARGET_DATABASE, identities["database"], "70:70", TARGET_NETWORK,
                [("volume", "/var/lib/postgresql/incidentseal-data", False)],
            ))
            clean_tables = _query_json(
                docker, TARGET_DATABASE,
                "SELECT COALESCE(jsonb_agg(tablename ORDER BY tablename),'[]'::jsonb)::text FROM pg_catalog.pg_tables WHERE schemaname='public';",
            )
            check("clean-distinct-target", clean_tables == [], {"target_project": TARGET_PROJECT, "target_volume": TARGET_VOLUME})

            if _digest(archive.read_bytes()) != archive_digest:
                raise TopologyError("IS_BACKUP_ARCHIVE", "archive bytes changed before restore")
            _create_actor(
                docker, name="incidentseal-restore-target-restore", project=TARGET_PROJECT,
                run_id=target_run, network=TARGET_NETWORK, image_id=identities["migration"],
                entrypoint="/usr/bin/pg_restore", arguments=PG_RESTORE_ARGV[1:], mount=(backup_dir, True),
            )
            inspections.append(_inspect_container(
                docker, "incidentseal-restore-target-restore", identities["migration"], "70:70", TARGET_NETWORK,
                [("bind", "/incidentseal/backup", True)],
            ))
            _start_actor(docker, "incidentseal-restore-target-restore")
            _remove_container(docker, "incidentseal-restore-target-restore")
            inspections.append(_run_migration(
                docker, name="incidentseal-restore-target-migration", project=TARGET_PROJECT,
                run_id=target_run, network=TARGET_NETWORK, image_id=identities["migration"],
            ))
            restored_state = _measure_state(docker, TARGET_DATABASE)
            equivalence = all(
                restored_state[key] == source_state[key]
                for key in ("schema_digest", "journal_digest", "verification_results_digest", "role_digest")
            )
            check(
                "restored-state-equivalence", equivalence,
                {key: restored_state[key] for key in ("schema_digest", "journal_digest", "verification_results_digest", "role_digest")},
            )

            negative_sql = {
                "runner_schema_create": "CREATE SCHEMA incidentseal_forbidden_schema;",
                "runner_ddl": "CREATE TABLE public.incidentseal_forbidden_table(id integer);",
                "runner_migration_read": "SELECT migration_id FROM public.incidentseal_schema_migrations;",
                "runner_journal_read": "SELECT run_id FROM public.incidentseal_run_events;",
                "runner_recovery_fence_read": "SELECT run_id FROM public.incidentseal_recovery_fences;",
            }
            for check_id, sql in negative_sql.items():
                denied = _expect_denied(docker, TARGET_DATABASE, sql)
                negative_privileges[check_id] = "denied" if denied else "allowed"
            check("restored-negative-privileges", set(negative_privileges.values()) == {"denied"}, negative_privileges)

            _run(docker, ["restart", TARGET_DATABASE])
            _wait_healthy(docker, TARGET_DATABASE)
            restart_state = _measure_state(docker, TARGET_DATABASE)
            check(
                "restart-persistence",
                all(restart_state[key] == restored_state[key] for key in ("schema_digest", "journal_digest", "verification_results_digest", "role_digest")),
                {key: restart_state[key] for key in ("schema_digest", "journal_digest", "verification_results_digest", "role_digest")},
            )
        finally:
            for name in fixed_containers:
                _remove_container(docker, name)
            for name in fixed_networks:
                subprocess.run([docker, "network", "rm", name], cwd=ROOT, capture_output=True, timeout=30, check=False)
            for name in fixed_volumes:
                subprocess.run([docker, "volume", "rm", name], cwd=ROOT, capture_output=True, timeout=30, check=False)

    after_volumes = _volume_names(docker)
    protected_after = _volume_snapshot(docker, protected)
    remaining_containers = _run(docker, ["ps", "-aq", "--filter", f"label={SURFACE_LABEL}=platform-validation"]).stdout.splitlines()
    remaining_networks = [name for name in fixed_networks if _run(docker, ["network", "ls", "-q", "--filter", f"name=^{name}$"]).stdout.strip()]
    remaining_volumes = fixed_volumes.intersection(after_volumes)
    custody_ok = protected_before == protected_after and protected.issubset(after_volumes)
    teardown_ok = not remaining_containers and not remaining_networks and not remaining_volumes
    check("protected-volume-identities-unchanged", custody_ok, {"before": protected_before, "after": protected_after})
    check("disposable-teardown", teardown_ok, {"containers": remaining_containers, "networks": remaining_networks, "volumes": sorted(remaining_volumes)})
    if custody_path is None or custody_path.exists():
        raise TopologyError("IS_BACKUP_CUSTODY", "temporary archive custody remained")
    if source_state is None or restored_state is None or restart_state is None or archive_digest is None or toc_digest is None:
        raise TopologyError("IS_BACKUP_VERIFICATION", "backup/restore evidence is incomplete")

    receipt = {
        "schema_version": "incidentseal-backup-restore-receipt/v1",
        "backup_id": str(uuid.uuid4()),
        "created_at_utc": _now(),
        "authority": {"mode": "platform-validation", "contract_digest": _sha256_file(CONTRACT_PATH)},
        "source": {
            "project_name": SOURCE_PROJECT,
            "disposable": True,
            "database_image_id": identities["database"],
            "migration_image_id": identities["migration"],
            "postgres_version_num": source_state["postgres_version_num"],
            "database_name": "incidentseal",
            "schema_digest": source_state["schema_digest"],
            "journal": {
                "run_count": source_state["journal_run_count"],
                "event_count": source_state["journal_event_count"],
                "ordered_stream_digest": source_state["journal_digest"],
            },
            "verification_results": {
                "row_count": source_state["verification_result_count"],
                "rows_digest": source_state["verification_results_digest"],
            },
            "role_digest": source_state["role_digest"],
        },
        "backup": {
            "format": "postgresql-custom-v1",
            "archive_digest": archive_digest,
            "archive_bytes": archive_bytes,
            "normalized_toc_digest": toc_digest,
            "toc_entries": toc_entries,
            "source_writes_blocked": True,
            "pg_dump_argv": PG_DUMP_ARGV,
            "stderr_policy": "empty",
            "fsync_required": True,
        },
        "roles": {
            "mode": "verified-baseline-not-restored-from-dump",
            "roles_digest": source_state["role_digest"],
            "items": source_state["roles"],
        },
        "restore": {
            "clean_target": True,
            "target_project_name": TARGET_PROJECT,
            "target_volume_name": TARGET_VOLUME,
            "source_archive_digest": archive_digest,
            "pg_restore_argv": PG_RESTORE_ARGV,
            "post_restore_migration_image_id": identities["migration"],
            "exit_code": 0,
            "stderr_policy": "empty",
            "schema_digest": restored_state["schema_digest"],
            "role_digest": restored_state["role_digest"],
            "journal_digest": restored_state["journal_digest"],
            "verification_results_digest": restored_state["verification_results_digest"],
            "negative_privileges": negative_privileges,
            "protected_volumes_unchanged": True,
            "disposable_teardown": True,
        },
        "verification_verdict": "PASS",
        "receipt_digest": "sha256:" + "0" * 64,
    }
    receipt["receipt_digest"] = receipt_digest(receipt)
    try:
        validate_receipt(receipt)
    except BackupRestoreError as error:
        raise TopologyError(error.code, str(error)) from error
    return {
        "schema_version": "incidentseal-backup-restore-probe/v1",
        "verdict": "PASS",
        "mode": "platform-validation",
        "claim_scope": "fixed-synthetic-postgresql-logical-backup-and-clean-restore-only",
        "contract_digest": _sha256_file(CONTRACT_PATH),
        "backup_restore_implementation_lock_digest": implementation_lock_digest,
        "images": image_receipts,
        "checks": checks,
        "inspections": inspections,
        "receipt": receipt,
        "protected_volumes": sorted(protected),
        "containers_removed": True,
        "networks_removed": True,
        "volumes_removed": True,
        "archive_custody_removed": True,
        "approval_accessed": False,
        "workflow_executed": False,
        "runtime_started": True,
        "static_validation": static.data,
        "retained_volume_lock_id": volume_lock["lock_id"],
    }
