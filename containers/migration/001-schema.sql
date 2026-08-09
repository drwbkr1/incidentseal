BEGIN;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE incidentseal FROM PUBLIC;

DO $incidentseal$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'incidentseal_runner') THEN
        CREATE ROLE incidentseal_runner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE incidentseal_runner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$incidentseal$;

GRANT CONNECT ON DATABASE incidentseal TO incidentseal_runner;
GRANT USAGE ON SCHEMA public TO incidentseal_runner;

CREATE TABLE IF NOT EXISTS verification_results (
    run_id text NOT NULL,
    runner text NOT NULL CHECK (runner IN ('python', 'node')),
    input_digest text NOT NULL CHECK (input_digest ~ '^sha256:[0-9a-f]{64}$'),
    result_digest text NOT NULL CHECK (result_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (run_id, runner)
);

CREATE TABLE IF NOT EXISTS incidentseal_schema_migrations (
    migration_id text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO incidentseal_schema_migrations (migration_id)
VALUES ('001-schema-v2')
ON CONFLICT (migration_id) DO NOTHING;

REVOKE ALL ON TABLE verification_results FROM PUBLIC;
REVOKE ALL ON TABLE incidentseal_schema_migrations FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE verification_results TO incidentseal_runner;

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;

COMMIT;
