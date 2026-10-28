"""Pager worker: cases from alerts, the page outbox, heartbeat counters.

Revision ID: 0002
Revises: 0001

The worker (a later PR) is one more service that talks to the database, so it gets
the same shape of access as ingest: a login role (soc_worker) with no table
privileges at all, whose only way in is EXECUTE on a handful of SECURITY DEFINER
functions. The functions run as soc_worker_writer (NOLOGIN, owns no tables), so
row-level security still applies to them and the policies below are what let them
in. The worker is cross-tenant by design, which is why it is not soc_app.

  assign_cases     alerts without a case -> an open case with the same client,
                   rule and host seen less than 60 minutes earlier, or a new case
                   (plus its page, when the policy says to page)
  claim_pages      due, pending pages -> only what a push needs; takes a lease
  finish_page      records the outcome; schedules the retry or gives up
  heartbeat_counts counters for the weekly OK push and the STALE checks
  worker_state_*   a tiny key/value table so a restart does not repeat a push

No function returns the raw payload, and none takes a client id from the caller.
Roles are created NOLOGIN; deploy gives soc_worker its login (soc_api.db logins).
"""

from alembic import op

revision = "0002"
down_revision = "0001"

UNASSIGNED = "00000000-0000-4000-8000-000000000001"

FUNCTIONS = [
    "assign_cases(integer, jsonb)",
    "claim_pages(integer)",
    "finish_page(uuid, text, text)",
    "heartbeat_counts(timestamptz)",
    "worker_state_get(text)",
    "worker_state_set(text, text)",
]


def upgrade() -> None:
    # Same rule as 0001: a pre-existing role with extra privileges stops the migration.
    op.execute(
        """
        DO $$
        DECLARE
            r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY['soc_worker', 'soc_worker_writer'] LOOP
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS '
                                   'NOCREATEDB NOCREATEROLE', r);
                ELSIF EXISTS (
                    SELECT FROM pg_roles WHERE rolname = r
                    AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole
                         OR (r = 'soc_worker_writer' AND rolcanlogin))
                ) THEN
                    RAISE EXCEPTION 'role % has privileges it must not have', r;
                END IF;
            END LOOP;
        END $$
        """
    )

    # ---- the outbox ----
    # One row per page. priority is the ntfy priority (1-5); a page with priority 0
    # is never queued (console only). status moves pending -> sent | failed.
    # next_attempt_at is both the retry time and the lease taken by claim_pages.
    op.execute(
        """
        ALTER TABLE notification
            ADD COLUMN priority smallint NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5),
            ADD COLUMN status text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'sent', 'failed', 'skipped')),
            ADD COLUMN next_attempt_at timestamptz NOT NULL DEFAULT now(),
            ADD COLUMN last_error text CHECK (char_length(last_error) <= 40),
            ADD COLUMN created_at timestamptz NOT NULL DEFAULT now()
        """
    )
    op.execute(
        "CREATE INDEX notification_due ON notification (next_attempt_at) WHERE status = 'pending'"
    )
    op.execute("CREATE INDEX alert_unassigned ON alert (received_at) WHERE case_id IS NULL")
    op.execute(
        "CREATE INDEX alert_case_group ON alert "
        "(client_id, rule, ((raw -> 'routing') ->> 'hostname'), received_at DESC) "
        "WHERE case_id IS NOT NULL"
    )

    op.execute(
        """
        CREATE TABLE worker_state (
            key text PRIMARY KEY CHECK (key ~ '^[a-z0-9_.:-]{1,64}$'),
            value text NOT NULL CHECK (char_length(value) <= 1000),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )

    # ---- what soc_worker_writer may touch (RLS is on, so policies too) ----
    op.execute("GRANT SELECT ON client TO soc_worker_writer")
    op.execute("GRANT SELECT ON alert TO soc_worker_writer")
    op.execute("GRANT UPDATE (case_id) ON alert TO soc_worker_writer")
    op.execute("GRANT SELECT, INSERT ON soc_case TO soc_worker_writer")
    op.execute("GRANT INSERT ON case_event TO soc_worker_writer")
    op.execute("GRANT SELECT, INSERT, UPDATE ON notification TO soc_worker_writer")
    op.execute("GRANT SELECT, INSERT, UPDATE ON worker_state TO soc_worker_writer")
    op.execute("ALTER TABLE worker_state ENABLE ROW LEVEL SECURITY")
    for table, commands in [
        ("client", "SELECT"),
        ("alert", "SELECT"),
        ("alert", "UPDATE"),
        ("soc_case", "SELECT"),
        ("soc_case", "INSERT"),
        ("case_event", "INSERT"),
        ("notification", "SELECT"),
        ("notification", "INSERT"),
        ("notification", "UPDATE"),
        ("worker_state", "SELECT"),
        ("worker_state", "INSERT"),
        ("worker_state", "UPDATE"),
    ]:
        clause = "WITH CHECK (true)" if commands == "INSERT" else "USING (true)"
        if commands == "UPDATE":
            clause = "USING (true) WITH CHECK (true)"
        op.execute(
            f"CREATE POLICY worker_{commands.lower()} ON {table} "
            f"FOR {commands} TO soc_worker_writer {clause}"
        )

    # ---- alert -> case (+ page) ----
    # p_policy maps a detection category (raw->>'cat') to an ntfy priority 0-5; 0
    # means "case, but no push". Anything else (missing, not a whole number 0-5) falls
    # back to the case severity. Unassigned always pages at 4 or more.
    # One caller at a time (advisory lock): two callers could otherwise each open a
    # case for the same group. Grouping compares alert times with each other, not with
    # now(), so a backlog after downtime groups the same way live traffic would.
    op.execute(
        f"""
        CREATE FUNCTION assign_cases(p_batch integer, p_policy jsonb DEFAULT '{{}}')
        RETURNS TABLE (alerts_assigned integer, cases_opened integer, pages_queued integer)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            a record;
            target uuid;
            sev text;
            prio integer;
            raw_prio jsonb;
            n_alerts integer := 0;
            n_cases integer := 0;
            n_pages integer := 0;
        BEGIN
            IF p_batch IS NULL OR p_batch < 1 OR p_batch > 1000 THEN
                RAISE EXCEPTION 'batch must be between 1 and 1000';
            END IF;
            IF p_policy IS NULL OR jsonb_typeof(p_policy) <> 'object' THEN
                p_policy := '{{}}'::jsonb;
            END IF;
            PERFORM pg_advisory_xact_lock(hashtext('soc_assign_cases'));
            FOR a IN
                SELECT id, client_id, rule, severity, received_at,
                       (raw -> 'routing') ->> 'hostname' AS host,
                       raw ->> 'cat' AS cat
                FROM alert WHERE case_id IS NULL
                ORDER BY received_at, id LIMIT p_batch
            LOOP
                SELECT x.case_id INTO target
                FROM alert x JOIN soc_case c ON c.client_id = x.client_id AND c.id = x.case_id
                WHERE x.client_id = a.client_id
                  AND x.rule IS NOT DISTINCT FROM a.rule
                  AND (x.raw -> 'routing') ->> 'hostname' IS NOT DISTINCT FROM a.host
                  AND c.status = 'open'
                  AND x.received_at >= a.received_at - interval '60 minutes'
                ORDER BY x.received_at DESC LIMIT 1;
                IF target IS NOT NULL THEN
                    UPDATE alert SET case_id = target WHERE id = a.id;
                    INSERT INTO case_event (client_id, case_id, actor, kind, body)
                    VALUES (a.client_id, target, 'system', 'alert_attached', a.id::text);
                ELSE
                    sev := a.severity;
                    IF a.client_id = '{UNASSIGNED}'::uuid
                       AND sev IN ('info', 'low') THEN
                        sev := 'medium';
                    END IF;
                    INSERT INTO soc_case (client_id, severity) VALUES (a.client_id, sev)
                    RETURNING id INTO target;
                    UPDATE alert SET case_id = target WHERE id = a.id;
                    INSERT INTO case_event (client_id, case_id, actor, kind, body)
                    VALUES (a.client_id, target, 'system', 'opened', a.id::text);
                    n_cases := n_cases + 1;
                    raw_prio := p_policy -> a.cat;
                    IF raw_prio IS NOT NULL AND jsonb_typeof(raw_prio) = 'number'
                       AND (raw_prio #>> '{{}}') ~ '^[0-5]$' THEN
                        prio := (raw_prio #>> '{{}}')::integer;
                    ELSE
                        prio := CASE sev WHEN 'info' THEN 0 WHEN 'low' THEN 3
                                         WHEN 'medium' THEN 4 ELSE 5 END;
                    END IF;
                    IF a.client_id = '{UNASSIGNED}'::uuid THEN
                        prio := greatest(prio, 4);
                    END IF;
                    IF prio > 0 THEN
                        INSERT INTO notification (client_id, case_id, channel, priority)
                        VALUES (a.client_id, target, 'ntfy', prio);
                        n_pages := n_pages + 1;
                    END IF;
                END IF;
                n_alerts := n_alerts + 1;
            END LOOP;
            RETURN QUERY SELECT n_alerts, n_cases, n_pages;
        END
        $$
        """
    )

    # ---- claim due pages: the push fields and nothing else ----
    # Taking the lease (attempts + 1, next_attempt_at two minutes out) inside the same
    # statement is what keeps two workers from sending one page twice; a worker that
    # dies after claiming leaves a row that becomes due again once the lease ends.
    op.execute(
        """
        CREATE FUNCTION claim_pages(p_batch integer)
        RETURNS TABLE (
            id uuid, priority smallint, attempts integer, client_slug text, rule text,
            host text, link text, case_short text, detected_at timestamptz
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        #variable_conflict use_column
        BEGIN
            IF p_batch IS NULL OR p_batch < 1 OR p_batch > 100 THEN
                RAISE EXCEPTION 'batch must be between 1 and 100';
            END IF;
            RETURN QUERY
            WITH due AS (
                SELECT n.id FROM notification n
                WHERE n.status = 'pending' AND n.next_attempt_at <= now()
                ORDER BY n.priority DESC, n.created_at, n.id
                LIMIT p_batch FOR UPDATE SKIP LOCKED
            ), taken AS (
                UPDATE notification n
                SET attempts = n.attempts + 1,
                    next_attempt_at = now() + interval '2 minutes'
                FROM due WHERE n.id = due.id
                RETURNING n.id, n.priority, n.attempts, n.client_id, n.case_id
            )
            SELECT t.id, t.priority, t.attempts, cl.slug, fa.rule,
                   left((fa.raw -> 'routing') ->> 'hostname', 64),
                   CASE WHEN fa.raw ->> 'link' LIKE 'https://app.limacharlie.io/%'
                        THEN left(fa.raw ->> 'link', 512) END,
                   left(t.case_id::text, 8), fa.detected_at
            FROM taken t
            JOIN client cl ON cl.id = t.client_id
            JOIN LATERAL (
                SELECT x.rule, x.raw, x.detected_at FROM alert x
                WHERE x.client_id = t.client_id AND x.case_id = t.case_id
                ORDER BY x.received_at, x.id LIMIT 1
            ) fa ON true
            ORDER BY t.priority DESC, t.id;
        END
        $$
        """
    )

    # ---- record what happened ----
    # 'sent'; 'retry' (network error, 5xx, 429): back off 10 s, 30 s, 2 m, 5 m, then
    # every 15 m, and give up once the page is a day old; 'fail' (any other 4xx): stop.
    # last_error is a short code only, never a response body.
    op.execute(
        """
        CREATE FUNCTION finish_page(p_id uuid, p_outcome text, p_error text DEFAULT NULL)
        RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            n record;
            code text;
            delay interval;
        BEGIN
            IF p_outcome NOT IN ('sent', 'retry', 'fail') THEN
                RAISE EXCEPTION 'unknown outcome';
            END IF;
            code := CASE WHEN p_error ~ '^[a-z0-9_]{1,40}$' THEN p_error
                         WHEN p_error IS NULL THEN NULL ELSE 'error' END;
            SELECT id, attempts, created_at INTO n
            FROM notification WHERE id = p_id AND status = 'pending' FOR UPDATE;
            IF NOT FOUND THEN
                RETURN 'not_pending';
            END IF;
            IF p_outcome = 'sent' THEN
                UPDATE notification SET status = 'sent', sent_at = now(), last_error = NULL
                WHERE id = p_id;
                RETURN 'sent';
            END IF;
            IF p_outcome = 'fail' THEN
                UPDATE notification SET status = 'failed', last_error = coalesce(code, 'error')
                WHERE id = p_id;
                RETURN 'failed';
            END IF;
            IF now() >= n.created_at + interval '24 hours' THEN
                UPDATE notification SET status = 'failed', last_error = 'gave_up'
                WHERE id = p_id;
                RETURN 'failed';
            END IF;
            delay := CASE greatest(n.attempts, 1)
                         WHEN 1 THEN interval '10 seconds'
                         WHEN 2 THEN interval '30 seconds'
                         WHEN 3 THEN interval '2 minutes'
                         WHEN 4 THEN interval '5 minutes'
                         ELSE interval '15 minutes' END;
            UPDATE notification
            SET next_attempt_at = now() + delay, last_error = coalesce(code, 'error')
            WHERE id = p_id;
            RETURN 'retry';
        END
        $$
        """
    )

    # ---- counters for the heartbeat ----
    op.execute(
        """
        CREATE FUNCTION heartbeat_counts(p_since timestamptz)
        RETURNS TABLE (
            alerts_received bigint, cases_opened bigint, pages_sent bigint,
            pages_failed bigint, failed_last_24h bigint,
            oldest_pending_page_s bigint, oldest_unassigned_alert_s bigint
        )
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT
                (SELECT count(*) FROM alert WHERE received_at >= p_since),
                (SELECT count(*) FROM soc_case WHERE opened_at >= p_since),
                (SELECT count(*) FROM notification
                  WHERE status = 'sent' AND sent_at >= p_since),
                (SELECT count(*) FROM notification
                  WHERE status = 'failed' AND created_at >= p_since),
                (SELECT count(*) FROM notification
                  WHERE status = 'failed' AND created_at >= now() - interval '24 hours'),
                (SELECT floor(extract(epoch FROM now() - min(created_at)))::bigint
                  FROM notification WHERE status = 'pending'),
                (SELECT floor(extract(epoch FROM now() - min(received_at)))::bigint
                  FROM alert WHERE case_id IS NULL)
        $$
        """
    )

    # ---- tiny state store ----
    op.execute(
        """
        CREATE FUNCTION worker_state_get(p_key text) RETURNS text
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$ SELECT value FROM worker_state WHERE key = p_key $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION worker_state_set(p_key text, p_value text) RETURNS void
        LANGUAGE sql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            INSERT INTO worker_state (key, value) VALUES (p_key, p_value)
            ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()
        $$
        """
    )

    # ---- hand the functions to the writer role; only soc_worker may call them ----
    op.execute("GRANT soc_worker_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_worker_writer")
    for function in FUNCTIONS:
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"ALTER FUNCTION {function} OWNER TO soc_worker_writer")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO soc_worker")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_worker_writer")


def downgrade() -> None:
    for function in FUNCTIONS:
        op.execute(f"DROP FUNCTION {function}")
    for table, commands in [
        ("client", "SELECT"),
        ("alert", "SELECT"),
        ("alert", "UPDATE"),
        ("soc_case", "SELECT"),
        ("soc_case", "INSERT"),
        ("case_event", "INSERT"),
        ("notification", "SELECT"),
        ("notification", "INSERT"),
        ("notification", "UPDATE"),
    ]:
        op.execute(f"DROP POLICY worker_{commands.lower()} ON {table}")
    op.execute("DROP TABLE worker_state")
    op.execute("DROP INDEX alert_case_group")
    op.execute("DROP INDEX alert_unassigned")
    op.execute("DROP INDEX notification_due")
    op.execute(
        "ALTER TABLE notification DROP COLUMN priority, DROP COLUMN status, "
        "DROP COLUMN next_attempt_at, DROP COLUMN last_error, DROP COLUMN created_at"
    )
    op.execute(
        "REVOKE ALL ON client, alert, soc_case, case_event, notification FROM soc_worker_writer"
    )
