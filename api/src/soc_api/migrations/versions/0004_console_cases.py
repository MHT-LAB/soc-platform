"""Console database access: case queue, case detail, Ack and Close.

Revision ID: 0004
Revises: 0003

The console (a later PR) becomes the third service with a database login, in the same
shape as ingest and the worker: a login role (soc_console) with no table privileges
whose only way in is EXECUTE on four SECURITY DEFINER functions, owned by
soc_console_writer (NOLOGIN, owns no tables, reaches tables through RLS policies written
for it and column grants). The console is a staff view across clients; per-client roles
come with sign-in in a later sprint.

  list_cases   the queue (open and acknowledged by default), newest first
  get_case     one case: its alerts (the raw payload as TEXT, cut), its events
  ack_case     open -> acknowledged, marks the case's pages acknowledged, one audit event
  close_case   -> closed, a note is required, one audit event

Cases gain two states, acknowledged and closed, and the table now checks them (a closed
case has a close time and the reverse). assign_cases keeps attaching alerts to an
acknowledged case (so acknowledging stops the buzzing, not the record) and only a
closed case stops collecting. Nothing here removes or renames anything: the previous
release's code, which only writes `open`, keeps working.
"""

from alembic import op

revision = "0004"
down_revision = "0003"

UNASSIGNED = "00000000-0000-4000-8000-000000000001"

FUNCTIONS = [
    "list_cases(text, integer)",
    "get_case(uuid)",
    "ack_case(uuid, text)",
    "close_case(uuid, text, text)",
]

# The tables the console's writer role touches, and what it may do to them.
POLICIES = [
    ("client", "SELECT"),
    ("alert", "SELECT"),
    ("soc_case", "SELECT"),
    ("soc_case", "UPDATE"),
    ("case_event", "SELECT"),
    ("case_event", "INSERT"),
    ("notification", "SELECT"),
    ("notification", "UPDATE"),
]

# assign_cases as 0002 wrote it, with the one thing that changes (which cases an alert
# may join) left as a token.
ASSIGN_CASES = r"""
CREATE OR REPLACE FUNCTION assign_cases(p_batch integer, p_policy jsonb DEFAULT '{}')
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
                p_policy := '{}'::jsonb;
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
                  AND __MATCH__
                  AND x.received_at >= a.received_at - interval '60 minutes'
                ORDER BY x.received_at DESC LIMIT 1;
                IF target IS NOT NULL THEN
                    UPDATE alert SET case_id = target WHERE id = a.id;
                    INSERT INTO case_event (__AT_COLS__client_id, case_id, actor, kind, body)
                    VALUES (__AT_VAL__a.client_id, target, 'system', 'alert_attached', a.id::text);
                ELSE
                    sev := a.severity;
                    IF a.client_id = '__UNASSIGNED__'::uuid
                       AND sev IN ('info', 'low') THEN
                        sev := 'medium';
                    END IF;
                    INSERT INTO soc_case (client_id, severity) VALUES (a.client_id, sev)
                    RETURNING id INTO target;
                    UPDATE alert SET case_id = target WHERE id = a.id;
                    INSERT INTO case_event (__AT_COLS__client_id, case_id, actor, kind, body)
                    VALUES (__AT_VAL__a.client_id, target, 'system', 'opened', a.id::text);
                    n_cases := n_cases + 1;
                    raw_prio := p_policy -> a.cat;
                    IF raw_prio IS NOT NULL AND jsonb_typeof(raw_prio) = 'number'
                       AND (raw_prio #>> '{}') ~ '^[0-5]$' THEN
                        prio := (raw_prio #>> '{}')::integer;
                    ELSE
                        prio := CASE sev WHEN 'info' THEN 0 WHEN 'low' THEN 3
                                         WHEN 'medium' THEN 4 ELSE 5 END;
                    END IF;
                    IF a.client_id = '__UNASSIGNED__'::uuid THEN
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

# A sign-in name as the tailnet gives it: local part, @, domain. Doubled quote because it
# sits inside an SQL string.
LOGIN = r"^[A-Za-z0-9._%+''-]{1,64}@[A-Za-z0-9.-]{1,189}$"


def assign_cases(match: str, *, own_clock: bool) -> str:
    """own_clock: stamp each event with its own reading of the clock. Within one
    transaction now() is constant, so a case's first events would tie and the history
    could list them in any order."""
    return (
        ASSIGN_CASES.replace("__UNASSIGNED__", UNASSIGNED)
        .replace("__MATCH__", match)
        .replace("__AT_COLS__", "at, " if own_clock else "")
        .replace("__AT_VAL__", "clock_timestamp(), " if own_clock else "")
    )


def upgrade() -> None:
    # Same rule as 0002: a pre-existing role with extra privileges stops the migration.
    op.execute(
        """
        DO $$
        DECLARE
            r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY['soc_console', 'soc_console_writer'] LOOP
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS '
                                   'NOCREATEDB NOCREATEROLE', r);
                ELSIF EXISTS (
                    SELECT FROM pg_roles WHERE rolname = r
                    AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole
                         OR (r = 'soc_console_writer' AND rolcanlogin))
                ) THEN
                    RAISE EXCEPTION 'role % has privileges it must not have', r;
                END IF;
            END LOOP;
        END $$
        """
    )

    # ---- case states ----
    op.execute(
        "ALTER TABLE soc_case ADD CONSTRAINT soc_case_status_check "
        "CHECK (status IN ('open', 'acknowledged', 'closed')), "
        "ADD CONSTRAINT soc_case_closed_check CHECK ((status = 'closed') = (closed_at IS NOT NULL))"
    )
    op.execute(
        "CREATE INDEX soc_case_queue ON soc_case (opened_at DESC) "
        "WHERE status IN ('open', 'acknowledged')"
    )
    op.execute(assign_cases("c.status IN ('open', 'acknowledged')", own_clock=True))

    # ---- what soc_console_writer may touch ----
    op.execute(
        "GRANT SELECT ON client, alert, soc_case, case_event, notification TO soc_console_writer"
    )
    op.execute("GRANT UPDATE (status, closed_at, closing_note) ON soc_case TO soc_console_writer")
    op.execute("GRANT INSERT ON case_event TO soc_console_writer")
    op.execute("GRANT UPDATE (acked_at) ON notification TO soc_console_writer")
    for table, command in POLICIES:
        clause = "USING (true)"
        if command == "INSERT":
            clause = "WITH CHECK (true)"
        elif command == "UPDATE":
            clause = "USING (true) WITH CHECK (true)"
        op.execute(
            f"CREATE POLICY console_{command.lower()} ON {table} "
            f"FOR {command} TO soc_console_writer {clause}"
        )

    # ---- the queue ----
    # p_status: active (open + acknowledged, the default), open, acknowledged, closed, all.
    op.execute(
        """
        CREATE FUNCTION list_cases(p_status text DEFAULT 'active', p_limit integer DEFAULT 100)
        RETURNS TABLE (
            id uuid, client_slug text, severity text, status text, opened_at timestamptz,
            alert_count bigint, last_alert_at timestamptz, rule text, host text,
            acked_by text, acked_at timestamptz, closed_at timestamptz
        )
        LANGUAGE plpgsql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        #variable_conflict use_column
        BEGIN
            IF p_status IS NULL OR p_status NOT IN
               ('active', 'open', 'acknowledged', 'closed', 'all') THEN
                RAISE EXCEPTION 'unknown status filter';
            END IF;
            IF p_limit IS NULL OR p_limit < 1 OR p_limit > 500 THEN
                RAISE EXCEPTION 'limit must be between 1 and 500';
            END IF;
            RETURN QUERY
            SELECT c.id, cl.slug, c.severity, c.status, c.opened_at,
                   (SELECT count(*) FROM alert a WHERE a.client_id = c.client_id
                                                   AND a.case_id = c.id),
                   (SELECT max(a.received_at) FROM alert a WHERE a.client_id = c.client_id
                                                              AND a.case_id = c.id),
                   fa.rule,
                   left((fa.raw -> 'routing') ->> 'hostname', 64),
                   ev.actor, ev.at, c.closed_at
            FROM soc_case c
            JOIN client cl ON cl.id = c.client_id
            LEFT JOIN LATERAL (
                SELECT a.rule, a.raw FROM alert a
                WHERE a.client_id = c.client_id AND a.case_id = c.id
                ORDER BY a.received_at, a.id LIMIT 1
            ) fa ON true
            LEFT JOIN LATERAL (
                SELECT e.actor, e.at FROM case_event e
                WHERE e.client_id = c.client_id AND e.case_id = c.id AND e.kind = 'acked'
                ORDER BY e.at DESC LIMIT 1
            ) ev ON true
            WHERE CASE p_status
                      WHEN 'all' THEN true
                      WHEN 'active' THEN c.status IN ('open', 'acknowledged')
                      ELSE c.status = p_status END
            ORDER BY c.opened_at DESC, c.id
            LIMIT p_limit;
        END
        $$
        """
    )

    # ---- one case ----
    # A single json document: the case, up to 100 alerts (newest first) with the raw
    # payload as TEXT cut at 20000 characters, and up to 200 events. The page escapes
    # every string and runs no script, so a hostile payload is shown, never executed.
    op.execute(
        """
        CREATE FUNCTION get_case(p_id uuid) RETURNS jsonb
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT jsonb_build_object(
                'case', jsonb_build_object(
                    'id', c.id, 'client_slug', cl.slug, 'severity', c.severity,
                    'status', c.status, 'opened_at', c.opened_at, 'closed_at', c.closed_at,
                    'closing_note', c.closing_note,
                    'alert_count', (SELECT count(*) FROM alert a
                                    WHERE a.client_id = c.client_id AND a.case_id = c.id)),
                'alerts', coalesce((
                    SELECT jsonb_agg(x ORDER BY x.received_at DESC) FROM (
                        SELECT a.id, a.rule, a.severity, a.summary, a.actor, a.detected_at,
                               a.received_at,
                               (a.raw -> 'routing') ->> 'hostname' AS host,
                               a.raw ->> 'link' AS link,
                               left(a.raw::text, 20000) AS raw,
                               char_length(a.raw::text) > 20000 AS raw_truncated
                        FROM alert a WHERE a.client_id = c.client_id AND a.case_id = c.id
                        ORDER BY a.received_at DESC, a.id LIMIT 100) x), '[]'::jsonb),
                'events', coalesce((
                    SELECT jsonb_agg(y ORDER BY y.at) FROM (
                        SELECT e.at, e.actor, e.kind, e.body FROM case_event e
                        WHERE e.client_id = c.client_id AND e.case_id = c.id
                        ORDER BY e.at DESC, e.id LIMIT 200) y), '[]'::jsonb))
            FROM soc_case c JOIN client cl ON cl.id = c.client_id
            WHERE c.id = p_id
        $$
        """
    )

    # ---- acknowledge ----
    # Idempotent. Returns acked | already | closed | not_found | invalid_login. The login
    # is checked here too: whatever the page passes, only something shaped like a login
    # reaches the audit trail.
    op.execute(
        f"""
        CREATE FUNCTION ack_case(p_id uuid, p_login text) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            c record;
        BEGIN
            IF p_login IS NULL OR char_length(p_login) > 254
               OR p_login !~ '{LOGIN}' THEN
                RETURN 'invalid_login';
            END IF;
            SELECT id, client_id, status INTO c FROM soc_case WHERE id = p_id FOR UPDATE;
            IF NOT FOUND THEN
                RETURN 'not_found';
            END IF;
            IF c.status = 'closed' THEN
                RETURN 'closed';
            END IF;
            IF c.status = 'acknowledged' THEN
                RETURN 'already';
            END IF;
            UPDATE soc_case SET status = 'acknowledged' WHERE id = c.id;
            UPDATE notification SET acked_at = now()
            WHERE client_id = c.client_id AND case_id = c.id AND acked_at IS NULL;
            INSERT INTO case_event (at, client_id, case_id, actor, kind)
            VALUES (clock_timestamp(), c.client_id, c.id, lower(p_login), 'acked');
            RETURN 'acked';
        END
        $$
        """
    )

    # ---- close ----
    # Returns closed | already | not_found | invalid_login | note_required | note_too_long.
    # Closing also marks the case's pages acknowledged, so nothing is re-sent for it.
    op.execute(
        f"""
        CREATE FUNCTION close_case(p_id uuid, p_login text, p_note text) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            c record;
            note text := btrim(coalesce(p_note, ''), ' ' || chr(9) || chr(10) || chr(13));
        BEGIN
            IF p_login IS NULL OR char_length(p_login) > 254
               OR p_login !~ '{LOGIN}' THEN
                RETURN 'invalid_login';
            END IF;
            IF note = '' THEN  -- a NUL byte cannot reach here: text cannot hold one
                RETURN 'note_required';
            END IF;
            IF char_length(note) > 2000 THEN
                RETURN 'note_too_long';
            END IF;
            SELECT id, client_id, status INTO c FROM soc_case WHERE id = p_id FOR UPDATE;
            IF NOT FOUND THEN
                RETURN 'not_found';
            END IF;
            IF c.status = 'closed' THEN
                RETURN 'already';
            END IF;
            UPDATE soc_case SET status = 'closed', closed_at = now(), closing_note = note
            WHERE id = c.id;
            UPDATE notification SET acked_at = now()
            WHERE client_id = c.client_id AND case_id = c.id AND acked_at IS NULL;
            INSERT INTO case_event (at, client_id, case_id, actor, kind, body)
            VALUES (clock_timestamp(), c.client_id, c.id, lower(p_login), 'closed', note);
            RETURN 'closed';
        END
        $$
        """
    )

    # ---- hand the functions to the writer role; only soc_console may call them ----
    op.execute("GRANT soc_console_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_console_writer")
    for function in FUNCTIONS:
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"ALTER FUNCTION {function} OWNER TO soc_console_writer")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO soc_console")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_console_writer")


def downgrade() -> None:
    for function in FUNCTIONS:
        op.execute(f"DROP FUNCTION {function}")
    for table, command in POLICIES:
        op.execute(f"DROP POLICY console_{command.lower()} ON {table}")
    op.execute(assign_cases("c.status = 'open'", own_clock=False))
    op.execute("DROP INDEX soc_case_queue")
    op.execute(
        "ALTER TABLE soc_case DROP CONSTRAINT soc_case_closed_check, "
        "DROP CONSTRAINT soc_case_status_check"
    )
    op.execute(
        "REVOKE ALL ON client, alert, soc_case, case_event, notification FROM soc_console_writer"
    )
