#!/usr/bin/env node
"use strict";

import { createHash } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";
import net from "node:net";


const RUN_ID_RE = /^isrun-[0-9a-f]{16}$/;


function canonicalText(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("request numbers must be safe integers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalText).join(",")}]`;
  if (typeof value === "object") {
    const members = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalText(value[key])}`);
    return `{${members.join(",")}}`;
  }
  throw new Error("request contains an unsupported JSON value");
}


function validateRequest(value) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error("request shape is invalid");
  }
  const keys = Object.keys(value).sort();
  if (JSON.stringify(keys) !== JSON.stringify(["payload", "run_id", "schema_version"])) {
    throw new Error("request shape is invalid");
  }
  if (value.schema_version !== "incidentseal-runner-request/v1") {
    throw new Error("request schema is invalid");
  }
  if (typeof value.run_id !== "string" || !RUN_ID_RE.test(value.run_id)) {
    throw new Error("run_id is invalid");
  }
  if (value.payload === null || Array.isArray(value.payload) || typeof value.payload !== "object") {
    throw new Error("payload must be an object");
  }
  return value;
}


function pgError(payload) {
  const values = [];
  let position = 0;
  while (position < payload.length && payload[position] !== 0) {
    const code = String.fromCharCode(payload[position]);
    const end = payload.indexOf(0, position + 1);
    if (end < 0) break;
    if (["S", "C", "M"].includes(code)) values.push(payload.subarray(position + 1, end).toString("utf8"));
    position = end + 1;
  }
  return values.join(" | ") || "PostgreSQL returned an error";
}


class PgWire {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.waiters = [];
    this.failure = null;
    socket.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.flush();
    });
    socket.on("error", (error) => this.rejectAll(error));
    socket.on("close", () => this.rejectAll(new Error("PostgreSQL connection closed unexpectedly")));
  }

  rejectAll(error) {
    this.failure = error;
    while (this.waiters.length) this.waiters.shift().reject(error);
  }

  flush() {
    while (this.waiters.length && this.buffer.length >= 5) {
      const length = this.buffer.readUInt32BE(1);
      if (length < 4 || length > 16 * 1024 * 1024) {
        this.rejectAll(new Error("PostgreSQL message length is invalid"));
        return;
      }
      if (this.buffer.length < length + 1) return;
      const message = {
        type: String.fromCharCode(this.buffer[0]),
        payload: this.buffer.subarray(5, length + 1),
      };
      this.buffer = this.buffer.subarray(length + 1);
      this.waiters.shift().resolve(message);
    }
  }

  next() {
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
      this.flush();
    });
  }
}


async function connectPostgres() {
  const host = process.env.PGHOST || "database";
  const port = Number.parseInt(process.env.PGPORT || "5432", 10);
  const user = process.env.PGUSER || "incidentseal";
  const database = process.env.PGDATABASE || "incidentseal";
  const socket = net.createConnection({ host, port });
  socket.setTimeout(10000, () => socket.destroy(new Error("PostgreSQL connection timed out")));
  await new Promise((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  const wire = new PgWire(socket);
  const parameterBytes = Buffer.from(
    `user\0${user}\0database\0${database}\0client_encoding\0UTF8\0application_name\0incidentseal-node\0\0`,
    "utf8",
  );
  const body = Buffer.alloc(4 + parameterBytes.length);
  body.writeUInt32BE(196608, 0);
  parameterBytes.copy(body, 4);
  const startup = Buffer.alloc(4 + body.length);
  startup.writeUInt32BE(startup.length, 0);
  body.copy(startup, 4);
  socket.write(startup);
  let authenticated = false;
  while (true) {
    const message = await wire.next();
    if (message.type === "R") {
      const method = message.payload.readUInt32BE(0);
      if (method !== 0) throw new Error(`unsupported PostgreSQL authentication method ${method}`);
      authenticated = true;
    } else if (message.type === "E") {
      throw new Error(pgError(message.payload));
    } else if (message.type === "Z") {
      if (!authenticated) throw new Error("PostgreSQL became ready without AuthenticationOk");
      return { socket, wire };
    }
  }
}


function quoteSql(value) {
  if (value.includes("\0") || value.length > 256) throw new Error("SQL value is outside the bounded domain");
  return `'${value.replaceAll("'", "''")}'`;
}


function decodeDataRow(payload) {
  const count = payload.readUInt16BE(0);
  const values = [];
  let position = 2;
  for (let index = 0; index < count; index += 1) {
    const length = payload.readInt32BE(position);
    position += 4;
    if (length < 0) throw new Error("unexpected PostgreSQL NULL");
    values.push(payload.subarray(position, position + length).toString("utf8"));
    position += length;
  }
  return values;
}


async function writeDatabaseResult(runId, inputDigest, resultDigest) {
  const values = [runId, "node", inputDigest, resultDigest].map(quoteSql).join(",");
  const query =
    "INSERT INTO verification_results (run_id,runner,input_digest,result_digest) VALUES (" +
    values +
    ") ON CONFLICT (run_id,runner) DO UPDATE SET input_digest=EXCLUDED.input_digest," +
    "result_digest=EXCLUDED.result_digest RETURNING run_id,runner,input_digest,result_digest;";
  const { socket, wire } = await connectPostgres();
  let row = null;
  try {
    const queryBytes = Buffer.from(`${query}\0`, "utf8");
    const message = Buffer.alloc(5 + queryBytes.length);
    message.write("Q", 0, "ascii");
    message.writeUInt32BE(queryBytes.length + 4, 1);
    queryBytes.copy(message, 5);
    socket.write(message);
    while (true) {
      const response = await wire.next();
      if (response.type === "D") row = decodeDataRow(response.payload);
      else if (response.type === "E") throw new Error(pgError(response.payload));
      else if (response.type === "Z") break;
    }
  } finally {
    socket.end();
  }
  const expected = [runId, "node", inputDigest, resultDigest];
  if (JSON.stringify(row) !== JSON.stringify(expected)) {
    throw new Error("PostgreSQL returned an unexpected result row");
  }
  return row;
}


async function buildResult(request, writeDatabase) {
  const inputDigest = `sha256:${createHash("sha256").update(canonicalText(request), "utf8").digest("hex")}`;
  const resultDigest = `sha256:${createHash("sha256").update(`${inputDigest}|node`, "utf8").digest("hex")}`;
  if (writeDatabase) await writeDatabaseResult(request.run_id, inputDigest, resultDigest);
  return {
    schema_version: "incidentseal-runner-result/v1",
    run_id: request.run_id,
    runner: "node",
    input_digest: inputDigest,
    result_digest: resultDigest,
    database_verified: writeDatabase,
  };
}


async function main() {
  if (process.argv.slice(2).length === 1 && process.argv[2] === "--self-test") {
    const request = validateRequest({ schema_version: "incidentseal-runner-request/v1", run_id: "isrun-0123456789abcdef", payload: { probe: "incidentseal" } });
    process.stdout.write(`${JSON.stringify(await buildResult(request, false))}\n`);
    return;
  }
  if (process.argv.slice(2).length) throw new Error("runner accepts no arguments");
  const inputRoot = process.env.INCIDENTSEAL_INPUT || "/incidentseal/input";
  const outputRoot = process.env.INCIDENTSEAL_OUTPUT || "/incidentseal/output";
  const request = validateRequest(JSON.parse(await readFile(`${inputRoot}/request.json`, "utf8")));
  const result = await buildResult(request, true);
  const temporary = `${outputRoot}/.result.json.tmp`;
  const final = `${outputRoot}/result.json`;
  await writeFile(temporary, `${JSON.stringify(result)}\n`, { encoding: "utf8", flag: "wx" });
  await rename(temporary, final);
}


main().catch((error) => {
  process.stderr.write(`IncidentSeal Node runner failed: ${error.message}\n`);
  process.exitCode = 1;
});
