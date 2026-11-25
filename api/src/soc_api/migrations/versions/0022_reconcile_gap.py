"""A stretch of detections the catch-up worker never fetched is remembered, and pages.

Revision ID: 0022
Revises: 0021

The catch-up worker fetches at most the last 24 hours. After a longer outage (the SOC host down
for two days, or a restore from an older backup) the middle is never fetched, and until now that
was one log line. It is now recorded on the cursor and the pager raises a STALE reason for it
until a person runs the backfill command.

  reconcile_cursor.gap_from, gap_to
                       the span that was skipped (both NULL when nothing is missing). A second
                       gap widens the span, never narrows it.
  reconcile_gap_note(source, from, to)
                       soc_reconcile only: the catch-up worker records what it is about to skip
  reconcile_gap_get(source)
                       soc_reconcile only: where the recorded gap starts (NULL for none), so the
                       backfill command can default to it
  reconcile_gap_clear(source, since)
                       soc_reconcile only: the backfill command says it fetched everything from
                       `since`; the gap is cleared only when `since` is at or before its start
                       (a backfill that starts later leaves the hole open). Returns whether it
                       cleared.
  reconcile_gap_health()
                       soc_worker only: the longest skipped span in seconds, 0 for none. No
                       source name, no times, no client data.

Additive. Downgrade removes the four functions, the grant and the two columns.
"""

from alembic import op

revision = "0022"
down_revision = "0021"

RECONCILE_FUNCTIONS = (
    "reconcile_gap_note(text, timestamptz, timestamptz)",
    "reconcile_gap_get(text)",
    "reconcile_gap_clear(text, timestamptz)",
)
WORKER_FUNCTIONS = ("reconcile_gap_health()",)


def upgrade() -> None:
    op.execute(
        "ALTER TABLE reconcile_cursor ADD COLUMN gap_from timestamptz, "
        "ADD COLUMN gap_to timestamptz, "
        "ADD CONSTRAINT reconcile_cursor_gap_pair CHECK "
        "((gap_from IS NULL) = (gap_to IS NULL) AND (gap_from IS NULL OR gap_from < gap_to))"
    )
    # The pager's writer already reads two columns of the cursor through a policy.
    op.execute("GRANT SELECT (gap_from, gap_to) ON reconcile_cursor TO soc_worker_writer")
    op.execute(
        """
        CREATE FUNCTION reconcile_gap_note(p_source text, p_from timestamptz, p_to timestamptz)
        RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            sid uuid;
        BEGIN
            IF p_from IS NULL OR p_to IS NULL OR p_from >= p_to
               OR p_to - p_from > interval '3650 days' THEN
                RAISE EXCEPTION 'bad gap';
            END IF;
            SELECT id INTO sid FROM source WHERE slug = p_source AND enabled;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown source';
            END IF;
            UPDATE reconcile_cursor
            SET gap_from = LEAST(coalesce(gap_from, p_from), p_from),
                gap_to = GREATEST(coalesce(gap_to, p_to), p_to),
                updated_at = now()
            WHERE source_id = sid;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'no cursor';
            END IF;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION reconcile_gap_get(p_source text) RETURNS timestamptz
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT c.gap_from
            FROM reconcile_cursor c JOIN source s ON s.id = c.source_id
            WHERE s.slug = p_source AND s.enabled
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION reconcile_gap_clear(p_source text, p_since timestamptz)
        RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            sid uuid;
            cleared integer;
        BEGIN
            IF p_since IS NULL THEN
                RAISE EXCEPTION 'bad time';
            END IF;
            SELECT id INTO sid FROM source WHERE slug = p_source AND enabled;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown source';
            END IF;
            UPDATE reconcile_cursor
            SET gap_from = NULL, gap_to = NULL, updated_at = now()
            WHERE source_id = sid AND gap_from IS NOT NULL AND p_since <= gap_from;
            GET DIAGNOSTICS cleared = ROW_COUNT;
            RETURN cleared > 0;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION reconcile_gap_health() RETURNS integer
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT coalesce(max(extract(epoch FROM gap_to - gap_from)), 0)::integer
            FROM reconcile_cursor WHERE gap_from IS NOT NULL
        $$
        """
    )
    for role, functions, login in (
        ("soc_reconcile_writer", RECONCILE_FUNCTIONS, "soc_reconcile"),
        ("soc_worker_writer", WORKER_FUNCTIONS, "soc_worker"),
    ):
        op.execute(f"GRANT {role} TO current_user")
        op.execute(f"GRANT CREATE ON SCHEMA public TO {role}")
        for function in functions:
            op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
            op.execute(f"ALTER FUNCTION {function} OWNER TO {role}")
            op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO {login}")
        op.execute(f"REVOKE CREATE ON SCHEMA public FROM {role}")


def downgrade() -> None:
    for function in (*RECONCILE_FUNCTIONS, *WORKER_FUNCTIONS):
        op.execute(f"DROP FUNCTION {function}")
    op.execute("REVOKE SELECT (gap_from, gap_to) ON reconcile_cursor FROM soc_worker_writer")
    op.execute(
        "ALTER TABLE reconcile_cursor DROP CONSTRAINT reconcile_cursor_gap_pair, "
        "DROP COLUMN gap_from, DROP COLUMN gap_to"
    )
