"""Pipeline health for the console's degraded banner.

Revision ID: 0010
Revises: 0009

The pager worker already decides when the pipeline is STALE (pages stuck, new alerts not
becoming cases, a failed page, the catch-up worker quiet, the last backup old). The console
shows the same conditions as a banner, so it needs the same numbers. One function, in the
shape of the other console functions:

  console_health()   SECURITY DEFINER, owned by soc_console_writer, EXECUTE for soc_console
                     only. One row of plain numbers, the same expressions the worker's
                     heartbeat_counts(), reconcile_health() and backup_health() use:
                       oldest_pending_page_s     age of the oldest page still waiting (NULL: none)
                       failed_last_24h           pages that failed in the last 24 hours
                       oldest_unassigned_alert_s age of the oldest alert without a case (NULL: none)
                       reconcile_sources         sources that have a catch-up cursor
                       reconcile_quiet_s         longest time since any of them last ran well
                       backup_age_s              time since the last good dump (or since the
                                                 backup state began when there has been none)
                     No names, no text, no ids.

The console's writer role gets column-only read access to two more tables, behind policies for
it, as the worker's writer has: backup_state (started_at, last_ok_at) and reconcile_cursor
(last_success, started_at). Additive; downgrade removes the function, policies and grants.

"""

from alembic import op

revision = "0010"
down_revision = "0009"


def upgrade() -> None:
    op.execute("GRANT SELECT (started_at, last_ok_at) ON backup_state TO soc_console_writer")
    op.execute(
        "CREATE POLICY console_health_read ON backup_state FOR SELECT "
        "TO soc_console_writer USING (true)"
    )
    op.execute("GRANT SELECT (last_success, started_at) ON reconcile_cursor TO soc_console_writer")
    op.execute(
        "CREATE POLICY console_health_read ON reconcile_cursor FOR SELECT "
        "TO soc_console_writer USING (true)"
    )
    op.execute(
        """
        CREATE FUNCTION console_health()
        RETURNS TABLE (
            oldest_pending_page_s bigint, failed_last_24h bigint,
            oldest_unassigned_alert_s bigint, reconcile_sources integer,
            reconcile_quiet_s double precision, backup_age_s double precision
        )
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT
                (SELECT floor(extract(epoch FROM now() - min(created_at)))::bigint
                  FROM notification WHERE status = 'pending'),
                (SELECT count(*) FROM notification
                  WHERE status = 'failed' AND created_at >= now() - interval '24 hours'),
                (SELECT floor(extract(epoch FROM now() - min(received_at)))::bigint
                  FROM alert WHERE case_id IS NULL),
                (SELECT count(*)::integer FROM reconcile_cursor),
                (SELECT max(extract(epoch FROM now() - coalesce(last_success, started_at)))
                        ::double precision FROM reconcile_cursor),
                (SELECT extract(epoch FROM now() - coalesce(last_ok_at, started_at))
                        ::double precision FROM backup_state)
        $$
        """
    )
    op.execute("GRANT soc_console_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_console_writer")
    op.execute("REVOKE ALL ON FUNCTION console_health() FROM PUBLIC")
    op.execute("ALTER FUNCTION console_health() OWNER TO soc_console_writer")
    op.execute("GRANT EXECUTE ON FUNCTION console_health() TO soc_console")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_console_writer")


def downgrade() -> None:
    op.execute("DROP FUNCTION console_health()")
    op.execute("DROP POLICY console_health_read ON reconcile_cursor")
    op.execute(
        "REVOKE SELECT (last_success, started_at) ON reconcile_cursor FROM soc_console_writer"
    )
    op.execute("DROP POLICY console_health_read ON backup_state")
    op.execute("REVOKE SELECT (started_at, last_ok_at) ON backup_state FROM soc_console_writer")
