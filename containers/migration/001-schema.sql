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

CREATE TABLE IF NOT EXISTS incidentseal_run_events (
    run_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence BETWEEN 0 AND 9007199254740991),
    event_id uuid NOT NULL,
    occurred_at_utc timestamptz NOT NULL,
    event_type text NOT NULL CHECK (event_type IN (
        'run.queued', 'run.started', 'policy.checked', 'step.started', 'step.completed',
        'step.failed', 'evidence.recorded', 'run.completed', 'run.cancelled', 'run.failed',
        'run.stale', 'run.superseded'
    )),
    lifecycle text NOT NULL CHECK (lifecycle IN (
        'queued', 'running', 'completed', 'cancelled', 'failed', 'stale', 'superseded'
    )),
    verdict text CHECK (verdict IN ('PASS', 'FAIL', 'INCONCLUSIVE', 'INVALID')),
    terminal boolean NOT NULL,
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    approval_digest text NOT NULL CHECK (approval_digest ~ '^sha256:[0-9a-f]{64}$'),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^sha256:[0-9a-f]{64}$'),
    event_digest text NOT NULL CHECK (event_digest ~ '^sha256:[0-9a-f]{64}$'),
    previous_link_digest text NOT NULL CHECK (previous_link_digest ~ '^sha256:[0-9a-f]{64}$'),
    link_digest text NOT NULL CHECK (link_digest ~ '^sha256:[0-9a-f]{64}$'),
    event_bytes bytea NOT NULL CHECK (octet_length(event_bytes) BETWEEN 2 AND 1048576),
    record_bytes bytea NOT NULL CHECK (octet_length(record_bytes) BETWEEN 2 AND 2097152),
    PRIMARY KEY (run_id, sequence),
    UNIQUE (event_id),
    UNIQUE (idempotency_key),
    CHECK (manifest_digest = approval_digest),
    CHECK (terminal = (lifecycle IN ('completed', 'cancelled', 'failed', 'stale', 'superseded'))),
    CHECK ((lifecycle = 'completed' AND verdict IS NOT NULL) OR (lifecycle <> 'completed' AND verdict IS NULL))
);

CREATE TABLE IF NOT EXISTS incidentseal_recovery_fences (
    run_id uuid PRIMARY KEY,
    workflow_holder_id uuid NOT NULL,
    workflow_fence_token bigint NOT NULL CHECK (workflow_fence_token BETWEEN 0 AND 9007199254740991),
    workflow_expires_at timestamptz NOT NULL,
    recovery_holder_id uuid,
    recovery_fence_token bigint NOT NULL DEFAULT 0 CHECK (recovery_fence_token BETWEEN 0 AND 9007199254740991),
    recovery_expires_at timestamptz,
    CHECK ((recovery_holder_id IS NULL) = (recovery_expires_at IS NULL))
);

CREATE OR REPLACE FUNCTION public.incidentseal_deny_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $incidentseal$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_IMMUTABLE: retained events cannot be changed or removed';
END
$incidentseal$;

DO $incidentseal$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'incidentseal_run_events_no_update_delete') THEN
        CREATE TRIGGER incidentseal_run_events_no_update_delete
        BEFORE UPDATE OR DELETE ON public.incidentseal_run_events
        FOR EACH ROW EXECUTE FUNCTION public.incidentseal_deny_event_mutation();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'incidentseal_run_events_no_truncate') THEN
        CREATE TRIGGER incidentseal_run_events_no_truncate
        BEFORE TRUNCATE ON public.incidentseal_run_events
        FOR EACH STATEMENT EXECUTE FUNCTION public.incidentseal_deny_event_mutation();
    END IF;
END
$incidentseal$;

CREATE OR REPLACE FUNCTION public.incidentseal_append_event(p_record_bytes bytea, p_event_bytes bytea)
RETURNS TABLE (
    disposition text,
    run_id uuid,
    sequence bigint,
    idempotency_key text,
    event_digest text,
    link_digest text,
    event_count bigint,
    root_digest text,
    lifecycle text,
    verdict text,
    terminal boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $incidentseal$
DECLARE
    v_record jsonb;
    v_event jsonb;
    v_record_keys text[];
    v_event_keys text[];
    v_payload_keys text[];
    v_run_id uuid;
    v_sequence bigint;
    v_event_id uuid;
    v_occurred_at timestamptz;
    v_event_type text;
    v_lifecycle text;
    v_verdict text;
    v_terminal boolean;
    v_manifest text;
    v_approval text;
    v_idempotency text;
    v_event_digest text;
    v_previous text;
    v_link text;
    v_existing public.incidentseal_run_events%ROWTYPE;
    v_prior public.incidentseal_run_events%ROWTYPE;
BEGIN
    IF p_record_bytes IS NULL OR p_event_bytes IS NULL
       OR octet_length(p_record_bytes) NOT BETWEEN 2 AND 2097152
       OR octet_length(p_event_bytes) NOT BETWEEN 2 AND 1048576 THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_SCHEMA: journal byte bounds differ';
    END IF;
    BEGIN
        v_record := convert_from(p_record_bytes, 'UTF8')::jsonb;
        v_event := convert_from(p_event_bytes, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_SCHEMA: journal bytes are not UTF-8 JSON';
    END;
    IF jsonb_typeof(v_record) <> 'object' OR jsonb_typeof(v_event) <> 'object' OR v_record->'event' <> v_event THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_SCHEMA: record and event bytes differ';
    END IF;
    SELECT array_agg(key ORDER BY key) INTO v_record_keys FROM jsonb_object_keys(v_record) AS keys(key);
    SELECT array_agg(key ORDER BY key) INTO v_event_keys FROM jsonb_object_keys(v_event) AS keys(key);
    IF v_record_keys <> ARRAY['event','event_digest','idempotency_key','link_digest','previous_link_digest','schema_version']::text[]
       OR v_event_keys <> ARRAY['approval_digest','error','event_id','event_type','lifecycle','manifest_digest','occurred_at_utc','payload','run_id','schema_version','sequence','terminal','verdict']::text[]
       OR v_record->>'schema_version' <> 'incidentseal-event-journal-record/v1'
       OR v_event->>'schema_version' <> 'incidentseal-run-event/v1' THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_SCHEMA: journal object fields differ';
    END IF;
    BEGIN
        v_run_id := (v_event->>'run_id')::uuid;
        v_sequence := (v_event->>'sequence')::bigint;
        v_event_id := (v_event->>'event_id')::uuid;
        v_occurred_at := (v_event->>'occurred_at_utc')::timestamptz;
        v_terminal := (v_event->>'terminal')::boolean;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_SCHEMA: event scalar fields are invalid';
    END;
    v_event_type := v_event->>'event_type';
    v_lifecycle := v_event->>'lifecycle';
    v_verdict := v_event->>'verdict';
    v_manifest := v_event->>'manifest_digest';
    v_approval := v_event->>'approval_digest';
    v_idempotency := v_record->>'idempotency_key';
    v_event_digest := v_record->>'event_digest';
    v_previous := v_record->>'previous_link_digest';
    v_link := v_record->>'link_digest';
    IF v_sequence NOT BETWEEN 0 AND 9007199254740991
       OR v_event->>'occurred_at_utc' !~ '^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$'
       OR v_idempotency !~ '^sha256:[0-9a-f]{64}$'
       OR v_event_digest !~ '^sha256:[0-9a-f]{64}$'
       OR v_previous !~ '^sha256:[0-9a-f]{64}$'
       OR v_link !~ '^sha256:[0-9a-f]{64}$'
       OR v_manifest !~ '^sha256:[0-9a-f]{64}$'
       OR v_approval !~ '^sha256:[0-9a-f]{64}$'
       OR v_manifest <> v_approval
       OR jsonb_typeof(v_event->'payload') <> 'object' THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_SCHEMA: event identity fields are invalid';
    END IF;
    IF NOT (
        (v_lifecycle = 'queued' AND v_event_type = 'run.queued')
        OR (v_lifecycle = 'running' AND v_event_type IN ('run.started','policy.checked','step.started','step.completed','step.failed','evidence.recorded'))
        OR (v_lifecycle = 'completed' AND v_event_type = 'run.completed')
        OR (v_lifecycle = 'cancelled' AND v_event_type = 'run.cancelled')
        OR (v_lifecycle = 'failed' AND v_event_type = 'run.failed')
        OR (v_lifecycle = 'stale' AND v_event_type = 'run.stale')
        OR (v_lifecycle = 'superseded' AND v_event_type = 'run.superseded')
    ) OR v_terminal <> (v_lifecycle IN ('completed','cancelled','failed','stale','superseded'))
      OR (v_lifecycle = 'completed' AND v_verdict NOT IN ('PASS','FAIL','INCONCLUSIVE','INVALID'))
      OR (v_lifecycle <> 'completed' AND v_verdict IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_STATE: lifecycle, event type, terminal, or verdict differs';
    END IF;
    IF v_lifecycle = 'stale' THEN
        SELECT array_agg(key ORDER BY key) INTO v_payload_keys FROM jsonb_object_keys(v_event->'payload') AS keys(key);
        IF v_payload_keys <> ARRAY['expected_authority_digest','observed_authority_digest','reason']::text[]
           OR v_event->'payload'->>'expected_authority_digest' <> v_manifest
           OR v_event->'payload'->>'observed_authority_digest' !~ '^sha256:[0-9a-f]{64}$'
           OR v_event->'payload'->>'observed_authority_digest' = v_manifest
           OR coalesce(v_event->'payload'->>'reason','') = '' THEN
            RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_STATE: stale evidence differs';
        END IF;
    ELSIF v_lifecycle = 'superseded' THEN
        SELECT array_agg(key ORDER BY key) INTO v_payload_keys FROM jsonb_object_keys(v_event->'payload') AS keys(key);
        BEGIN
            IF v_payload_keys <> ARRAY['reason','superseded_by_run_id']::text[]
               OR (v_event->'payload'->>'superseded_by_run_id')::uuid = v_run_id
               OR coalesce(v_event->'payload'->>'reason','') = '' THEN
                RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_STATE: supersession evidence differs';
            END IF;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_STATE: supersession evidence differs';
        END;
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_run_id::text, 0));

    SELECT j.* INTO v_existing FROM public.incidentseal_run_events AS j WHERE j.idempotency_key = v_idempotency;
    IF FOUND THEN
        IF v_existing.record_bytes <> p_record_bytes OR v_existing.event_bytes <> p_event_bytes THEN
            RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_CONFLICT: idempotency key is retained for different bytes';
        END IF;
        RETURN QUERY SELECT
            'replayed'::text, v_existing.run_id, v_existing.sequence, v_existing.idempotency_key,
            v_existing.event_digest, v_existing.link_digest,
            (SELECT count(*)::bigint FROM public.incidentseal_run_events AS c WHERE c.run_id = v_existing.run_id),
            v_existing.link_digest, v_existing.lifecycle, v_existing.verdict, v_existing.terminal;
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM public.incidentseal_run_events AS j WHERE j.event_id = v_event_id)
       OR EXISTS (SELECT 1 FROM public.incidentseal_run_events AS j WHERE j.run_id = v_run_id AND j.sequence = v_sequence) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_CONFLICT: event ID or run sequence is already retained';
    END IF;

    SELECT j.* INTO v_prior
    FROM public.incidentseal_run_events AS j
    WHERE j.run_id = v_run_id
    ORDER BY j.sequence DESC
    LIMIT 1;
    IF NOT FOUND THEN
        IF v_sequence <> 0 OR v_lifecycle <> 'queued' OR v_previous <> 'sha256:0000000000000000000000000000000000000000000000000000000000000000' THEN
            RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_SEQUENCE: first event is not queued at genesis sequence zero';
        END IF;
    ELSE
        IF v_prior.terminal THEN
            RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_TERMINAL: terminal run cannot accept another event';
        END IF;
        IF v_sequence <> v_prior.sequence + 1 OR v_previous <> v_prior.link_digest THEN
            RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_SEQUENCE: sequence or predecessor is not contiguous';
        END IF;
        IF v_manifest <> v_prior.manifest_digest OR v_approval <> v_prior.approval_digest THEN
            RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_AUTHORITY: run authority changed within the journal';
        END IF;
        IF (v_prior.lifecycle = 'queued' AND v_lifecycle NOT IN ('running','cancelled','failed','stale','superseded'))
           OR (v_prior.lifecycle = 'running' AND v_lifecycle NOT IN ('running','completed','cancelled','failed','stale','superseded'))
           OR v_prior.lifecycle NOT IN ('queued','running') THEN
            RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_STATE: lifecycle transition is invalid';
        END IF;
    END IF;

    INSERT INTO public.incidentseal_run_events (
        run_id, sequence, event_id, occurred_at_utc, event_type, lifecycle, verdict, terminal,
        manifest_digest, approval_digest, idempotency_key, event_digest, previous_link_digest,
        link_digest, event_bytes, record_bytes
    ) VALUES (
        v_run_id, v_sequence, v_event_id, v_occurred_at, v_event_type, v_lifecycle, v_verdict, v_terminal,
        v_manifest, v_approval, v_idempotency, v_event_digest, v_previous, v_link, p_event_bytes, p_record_bytes
    );
    RETURN QUERY SELECT
        'inserted'::text, v_run_id, v_sequence, v_idempotency, v_event_digest, v_link,
        v_sequence + 1, v_link, v_lifecycle, v_verdict, v_terminal;
EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_JOURNAL_CONFLICT: concurrent journal identity conflict';
END
$incidentseal$;

CREATE OR REPLACE FUNCTION public.incidentseal_acquire_recovery_fence(
    p_run_id uuid,
    p_workflow_fence_token bigint,
    p_recovery_holder_id uuid,
    p_recovery_expires_at timestamptz
)
RETURNS TABLE (
    workflow_holder_id uuid,
    workflow_fence_token bigint,
    workflow_expires_at timestamptz,
    recovery_holder_id uuid,
    recovery_fence_token bigint,
    recovery_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $incidentseal$
DECLARE
    v_fence public.incidentseal_recovery_fences%ROWTYPE;
BEGIN
    IF p_workflow_fence_token NOT BETWEEN 0 AND 9007199254740991
       OR p_recovery_expires_at <= CURRENT_TIMESTAMP
       OR p_recovery_expires_at > CURRENT_TIMESTAMP + interval '5 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_RECOVERY_FENCE: recovery fence request is invalid';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_run_id::text, 1));
    SELECT f.* INTO v_fence
    FROM public.incidentseal_recovery_fences AS f
    WHERE f.run_id = p_run_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_RECOVERY_LEASE_UNAVAILABLE: workflow lease is missing';
    END IF;
    IF v_fence.workflow_fence_token <> p_workflow_fence_token THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_RECOVERY_FENCE: workflow fence token changed';
    END IF;
    IF v_fence.workflow_expires_at > CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_RECOVERY_ACTIVE_OWNER: workflow lease is active';
    END IF;
    IF v_fence.recovery_expires_at > CURRENT_TIMESTAMP THEN
        IF v_fence.recovery_holder_id <> p_recovery_holder_id THEN
            RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_RECOVERY_ACTIVE_OWNER: another recovery holder is active';
        END IF;
    ELSE
        UPDATE public.incidentseal_recovery_fences AS f
        SET recovery_holder_id = p_recovery_holder_id,
            recovery_fence_token = f.recovery_fence_token + 1,
            recovery_expires_at = p_recovery_expires_at
        WHERE f.run_id = p_run_id
        RETURNING f.* INTO v_fence;
    END IF;
    RETURN QUERY SELECT
        v_fence.workflow_holder_id,
        v_fence.workflow_fence_token,
        v_fence.workflow_expires_at,
        v_fence.recovery_holder_id,
        v_fence.recovery_fence_token,
        v_fence.recovery_expires_at;
END
$incidentseal$;

CREATE OR REPLACE FUNCTION public.incidentseal_release_recovery_fence(
    p_run_id uuid,
    p_recovery_holder_id uuid,
    p_recovery_fence_token bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $incidentseal$
DECLARE
    v_updated bigint;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_run_id::text, 1));
    UPDATE public.incidentseal_recovery_fences AS f
    SET recovery_expires_at = CURRENT_TIMESTAMP
    WHERE f.run_id = p_run_id
      AND f.recovery_holder_id = p_recovery_holder_id
      AND f.recovery_fence_token = p_recovery_fence_token
      AND f.recovery_expires_at > CURRENT_TIMESTAMP;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    IF v_updated <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'IS_RECOVERY_FENCE: recovery fence release did not match the active holder';
    END IF;
    RETURN true;
END
$incidentseal$;

REVOKE ALL ON TABLE verification_results FROM PUBLIC;
REVOKE ALL ON TABLE incidentseal_schema_migrations FROM PUBLIC;
REVOKE ALL ON TABLE incidentseal_run_events FROM PUBLIC;
REVOKE ALL ON TABLE incidentseal_recovery_fences FROM PUBLIC;
REVOKE ALL ON FUNCTION public.incidentseal_append_event(bytea, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.incidentseal_deny_event_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.incidentseal_acquire_recovery_fence(uuid, bigint, uuid, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.incidentseal_release_recovery_fence(uuid, uuid, bigint) FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE verification_results TO incidentseal_runner;

INSERT INTO incidentseal_schema_migrations (migration_id)
VALUES ('001-schema-v2'), ('002-event-journal-v1'), ('003-recovery-fence-v1')
ON CONFLICT (migration_id) DO NOTHING;

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

COMMIT;
