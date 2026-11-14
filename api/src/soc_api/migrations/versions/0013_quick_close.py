"""Quick close: close a case with a verdict, and show the verdict.

Revision ID: 0013
Revises: 0012

The case page gets four one-tap buttons (our test, our admin work, false positive,
duplicate). Each closes the case with a verdict kept in soc_case.verdict (a column since
0001, never written until now). The verdicts are a fixed set, checked in the function:

  test                 our own test
  authorized_activity  our own administrative work
  false_positive       the detection fired wrongly
  duplicate            the same event as another case

They are kept apart so tuning can count real false positives per rule without our own
tests and admin work mixed in.

  close_case_with_verdict(id, login, verdict, note)
      closes the case with the verdict and an optional note (up to 2000 characters), marks
      its pages acknowledged and writes one `closed` event whose actor is the login and
      whose detail is the verdict, then the note when there is one. Returns closed |
      already | not_found | invalid_login | invalid_verdict | note_too_long. close_case
      (a note is required, no verdict) is unchanged.

list_cases gains a trailing `verdict` column (a function's result columns cannot change in
place, so it is dropped and created again) and get_case's case object gains `verdict`. The
previous release's console reads columns and keys by name and ignores the new ones.
Downgrade restores 0004's definitions exactly and removes the new function and grant.
"""

from alembic import op

revision = "0013"
down_revision = "0012"

NEW = "close_case_with_verdict(uuid, text, text, text)"

# A sign-in name as the tailnet gives it (same pattern as 0004; doubled quote because it
# sits inside an SQL string).
LOGIN = r"^[A-Za-z0-9._%+''-]{1,64}@[A-Za-z0-9.-]{1,189}$"

LIST_CASES = """
        CREATE FUNCTION list_cases(p_status text DEFAULT 'active', p_limit integer DEFAULT 100)
        RETURNS TABLE (
            id uuid, client_slug text, severity text, status text, opened_at timestamptz,
            alert_count bigint, last_alert_at timestamptz, rule text, host text,
            acked_by text, acked_at timestamptz, closed_at timestamptz__VERDICT_COLUMN__
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
                   ev.actor, ev.at, c.closed_at__VERDICT_SELECT__
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

GET_CASE = """
        CREATE OR REPLACE FUNCTION get_case(p_id uuid) RETURNS jsonb
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT jsonb_build_object(
                'case', jsonb_build_object(
                    'id', c.id, 'client_slug', cl.slug, 'severity', c.severity,
                    'status', c.status, 'opened_at', c.opened_at, 'closed_at', c.closed_at,
                    'closing_note', c.closing_note,__VERDICT_KEY__
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


def list_cases(*, verdict: bool) -> str:
    return LIST_CASES.replace(
        "__VERDICT_COLUMN__", ",\n            verdict text" if verdict else ""
    ).replace("__VERDICT_SELECT__", ",\n                   c.verdict" if verdict else "")


def get_case(*, verdict: bool) -> str:
    return GET_CASE.replace(
        "__VERDICT_KEY__", "\n                    'verdict', c.verdict," if verdict else ""
    )


def hand_over(functions: list[str]) -> None:
    """Own and grant the way 0004 does: the writer role owns, only soc_console may call."""
    op.execute("GRANT soc_console_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_console_writer")
    for function in functions:
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"ALTER FUNCTION {function} OWNER TO soc_console_writer")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO soc_console")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_console_writer")


def upgrade() -> None:
    op.execute("GRANT UPDATE (verdict) ON soc_case TO soc_console_writer")

    op.execute("DROP FUNCTION list_cases(text, integer)")
    op.execute(list_cases(verdict=True))
    op.execute(get_case(verdict=True))

    # Returns closed | already | not_found | invalid_login | invalid_verdict | note_too_long.
    # The note may be empty here; the reason is then the verdict alone.
    op.execute(
        f"""
        CREATE FUNCTION close_case_with_verdict(
            p_id uuid, p_login text, p_verdict text, p_note text) RETURNS text
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
            IF p_verdict IS NULL OR p_verdict NOT IN
               ('test', 'authorized_activity', 'false_positive', 'duplicate') THEN
                RETURN 'invalid_verdict';
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
            UPDATE soc_case
            SET status = 'closed', closed_at = now(), verdict = p_verdict,
                closing_note = nullif(note, '')
            WHERE id = c.id;
            UPDATE notification SET acked_at = now()
            WHERE client_id = c.client_id AND case_id = c.id AND acked_at IS NULL;
            INSERT INTO case_event (at, client_id, case_id, actor, kind, body)
            VALUES (clock_timestamp(), c.client_id, c.id, lower(p_login), 'closed',
                    p_verdict || CASE WHEN note = '' THEN '' ELSE ': ' || note END);
            RETURN 'closed';
        END
        $$
        """
    )
    hand_over(["list_cases(text, integer)", NEW])


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {NEW}")
    op.execute("DROP FUNCTION list_cases(text, integer)")
    op.execute(list_cases(verdict=False))
    op.execute(get_case(verdict=False))
    hand_over(["list_cases(text, integer)"])
    op.execute("REVOKE UPDATE (verdict) ON soc_case FROM soc_console_writer")
