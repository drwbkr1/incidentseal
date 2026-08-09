#!/usr/bin/env python3
"""Minimal standard-library IncidentSeal Python runner."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import struct
import sys
from pathlib import Path
from typing import Any


RUN_ID_RE = re.compile(r"^isrun-[0-9a-f]{16}$")


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be", errors="surrogatepass")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") if not isinstance(value, dict) else _canonical_object(value).encode("utf-8")


def _canonical_text(value: Any) -> str:
    if isinstance(value, dict):
        return _canonical_object(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical_text(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _canonical_object(value: dict[str, Any]) -> str:
    return "{" + ",".join(
        json.dumps(key, ensure_ascii=False) + ":" + _canonical_text(value[key])
        for key in sorted(value, key=_utf16_key)
    ) + "}"


def validate_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "run_id", "payload"}:
        raise ValueError("request shape is invalid")
    if value["schema_version"] != "incidentseal-runner-request/v1":
        raise ValueError("request schema is invalid")
    if not isinstance(value["run_id"], str) or RUN_ID_RE.fullmatch(value["run_id"]) is None:
        raise ValueError("run_id is invalid")
    if not isinstance(value["payload"], dict):
        raise ValueError("payload must be an object")
    return value


def _read_exact(stream: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise RuntimeError("PostgreSQL connection closed unexpectedly")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_message(stream: socket.socket) -> tuple[bytes, bytes]:
    message_type = _read_exact(stream, 1)
    length = struct.unpack("!I", _read_exact(stream, 4))[0]
    if length < 4 or length > 16 * 1024 * 1024:
        raise RuntimeError("PostgreSQL message length is invalid")
    return message_type, _read_exact(stream, length - 4)


def _error_text(payload: bytes) -> str:
    fields: list[str] = []
    for field in payload.rstrip(b"\x00").split(b"\x00"):
        if len(field) > 1 and field[:1] in {b"S", b"C", b"M"}:
            fields.append(field[1:].decode("utf-8", errors="replace"))
    return " | ".join(fields) or "PostgreSQL returned an error"


def _connect() -> socket.socket:
    host = os.environ.get("PGHOST", "database")
    port = int(os.environ.get("PGPORT", "5432"))
    user = os.environ.get("PGUSER", "incidentseal")
    database = os.environ.get("PGDATABASE", "incidentseal")
    stream = socket.create_connection((host, port), timeout=5)
    stream.settimeout(10)
    parameters = (
        b"user\x00" + user.encode() + b"\x00"
        + b"database\x00" + database.encode() + b"\x00"
        + b"client_encoding\x00UTF8\x00"
        + b"application_name\x00incidentseal-python\x00\x00"
    )
    body = struct.pack("!I", 196608) + parameters
    stream.sendall(struct.pack("!I", len(body) + 4) + body)
    authenticated = False
    while True:
        kind, payload = _read_message(stream)
        if kind == b"R":
            method = struct.unpack("!I", payload[:4])[0]
            if method != 0:
                raise RuntimeError(f"unsupported PostgreSQL authentication method {method}")
            authenticated = True
        elif kind == b"E":
            raise RuntimeError(_error_text(payload))
        elif kind == b"Z":
            if not authenticated:
                raise RuntimeError("PostgreSQL became ready without AuthenticationOk")
            return stream


def _quote(value: str) -> str:
    if "\x00" in value or len(value) > 256:
        raise ValueError("SQL value is outside the bounded domain")
    return "'" + value.replace("'", "''") + "'"


def write_database_result(run_id: str, input_digest: str, result_digest: str) -> list[str]:
    values = ",".join(_quote(item) for item in (run_id, "python", input_digest, result_digest))
    query = (
        "INSERT INTO verification_results (run_id,runner,input_digest,result_digest) VALUES ("
        + values
        + ") ON CONFLICT (run_id,runner) DO UPDATE SET input_digest=EXCLUDED.input_digest,"
        "result_digest=EXCLUDED.result_digest RETURNING run_id,runner,input_digest,result_digest;"
    )
    stream = _connect()
    row: list[str] | None = None
    try:
        payload = query.encode("utf-8") + b"\x00"
        stream.sendall(b"Q" + struct.pack("!I", len(payload) + 4) + payload)
        while True:
            kind, body = _read_message(stream)
            if kind == b"D":
                count = struct.unpack("!H", body[:2])[0]
                position = 2
                values_out: list[str] = []
                for _ in range(count):
                    length = struct.unpack("!i", body[position:position + 4])[0]
                    position += 4
                    if length < 0:
                        raise RuntimeError("unexpected PostgreSQL NULL")
                    values_out.append(body[position:position + length].decode("utf-8"))
                    position += length
                row = values_out
            elif kind == b"E":
                raise RuntimeError(_error_text(body))
            elif kind == b"Z":
                break
    finally:
        stream.close()
    expected = [run_id, "python", input_digest, result_digest]
    if row != expected:
        raise RuntimeError("PostgreSQL returned an unexpected result row")
    return row


def build_result(request: dict[str, Any], *, write_database: bool) -> dict[str, Any]:
    input_digest = "sha256:" + hashlib.sha256(canonical_bytes(request)).hexdigest()
    result_digest = "sha256:" + hashlib.sha256((input_digest + "|python").encode()).hexdigest()
    if write_database:
        write_database_result(request["run_id"], input_digest, result_digest)
    return {
        "schema_version": "incidentseal-runner-result/v1",
        "run_id": request["run_id"],
        "runner": "python",
        "input_digest": input_digest,
        "result_digest": result_digest,
        "database_verified": write_database,
    }


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        request = validate_request({"schema_version": "incidentseal-runner-request/v1", "run_id": "isrun-0123456789abcdef", "payload": {"probe": "incidentseal"}})
        print(json.dumps(build_result(request, write_database=False), separators=(",", ":"), sort_keys=True))
        return 0
    if sys.argv[1:]:
        raise ValueError("runner accepts no arguments")
    input_root = Path(os.environ.get("INCIDENTSEAL_INPUT", "/incidentseal/input"))
    output_root = Path(os.environ.get("INCIDENTSEAL_OUTPUT", "/incidentseal/output"))
    request = validate_request(json.loads((input_root / "request.json").read_text(encoding="utf-8")))
    result = build_result(request, write_database=True)
    temporary = output_root / ".result.json.tmp"
    final = output_root / "result.json"
    temporary.write_text(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, final)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"IncidentSeal Python runner failed: {error}", file=sys.stderr)
        raise SystemExit(1)
