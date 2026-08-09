BEGIN;

CREATE TABLE IF NOT EXISTS verification_results (
    run_id text NOT NULL,
    runner text NOT NULL CHECK (runner IN ('python', 'node')),
    input_digest text NOT NULL CHECK (input_digest ~ '^sha256:[0-9a-f]{64}$'),
    result_digest text NOT NULL CHECK (result_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (run_id, runner)
);

COMMIT;
