# Host-owned backup and clean-restore implementation

- Unit: `IS4-U05`
- Command: `incidentseal topology backup-restore-probe --mode platform-validation --json`
- Authority: fixed synthetic platform validation only
- Status: implementation candidate

## Fixed surface

The command accepts no manifest, database, project, volume, archive, destination, path, or arbitrary operation. The host CLI owns Docker and creates exactly two disposable projects: `incidentseal-backup-source` and `incidentseal-restore-target`. Their networks and volumes are fixed, labeled, absent before the probe, and deleted after verified teardown. The three protected evidence volumes are identity-hashed before and after and are never mounted.

Both PostgreSQL databases and every migration, write-fence, dump, TOC-inspection, and restore actor use exact runtime-lock image IDs, numeric user `70:70`, read-only roots, no-new-privileges, all capabilities dropped, no published ports, no sensitive environment name, no Docker endpoint, and either one internal-only network or `network=none`. The only host mount is a narrow temporary backup directory outside the repository and OneDrive. Dump access is read/write; TOC inspection and restore access are read-only. It contains only fixed synthetic, non-sensitive evidence and is removed after the probe.

## Evidence sequence

The source is freshly migrated, seeded with two verification rows and all seven frozen journal records across three runs, then measured. A live relation-level `SHARE` lock fences writes while allowing the consistent `pg_dump` snapshot. A bounded runner write must time out behind that fence before the host accepts `source_writes_blocked=true`.

The migration image executes the contract's exact custom-format, uncompressed, no-owner, no-privilege dump command. The host fsyncs and hashes the exact archive bytes. A separate no-network actor lists the archive; the host normalizes whitespace, excludes variable comment headers, rejects ACL, global, database, role, or tablespace entries, requires core IncidentSeal objects, and hashes the normalized TOC. The archive digest is rechecked immediately before restore. Dump and restore stderr must be empty; an idempotent migration may emit only the exact locked-path `NOTICE: relation "..." already exists, skipping` form for the four expected tables, which is counted and retained in the runtime inspection.

The target begins with a different clean volume and no public tables. `pg_restore` runs with exact error-stopping, single-transaction, no-owner, and no-privilege arguments. The locked migration then recreates and hardens cluster-global roles. PASS requires exact schema, ordered journal bytes, verification rows, and two-role equivalence; denied runner schema creation, DDL, migration-ledger reads, journal reads, and recovery-fence reads; byte-identical state after PostgreSQL restart; unchanged protected-volume identities; removed archive custody; and complete source/target container, network, and volume teardown.

## Non-claims

This fixed `platform-validation` probe does not back up a repository workflow, user database, protected volume, production system, or arbitrary archive. It does not approve a manifest, execute workflow input, retain an archive, expose a general disaster-recovery command, or prove integrated recovery, dashboard, packaging, registry, redistribution, or release behavior.
