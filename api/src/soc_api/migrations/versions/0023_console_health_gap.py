"""The console banner and System page know about rule drift and a skipped stretch.

Revision ID: 0023
Revises: 0022

The pager has two STALE reasons the console could not show: rules that differ from what the
deploy wrote (0018) and a stretch of detections the catch-up worker never fetched (0022). The
banner reads console_health() and the System page reads ops_overview(), so both gain the
numbers the pager already uses:

  console_health()   two more columns, the same numbers as the pager's two health functions:
                       rules_drift      how many rules are changed, unmanaged or missing (or the
                                        manifest is wrong); 0 when drift is not being checked
                       reconcile_gap_s  the longest skipped span in seconds, 0 for none
                     A function's result columns cannot change in place, so it is dropped and
                     created again (as in 0011); the previous release's console reads columns
                     by name and ignores the new ones. soc_console_writer gets column SELECT on
                     the two gap columns (the cursor policy from 0010 already lets it read rows).
  ops_overview()     health.reconcile_gap_s, one more key, by an exact-once text swap (the
                     migration refuses to run if the anchor is not there exactly once).

No source name, no time and no rule name is added: seconds and a count.

Downgrade restores 0011's console_health() and the previous ops_overview() exactly.
"""

from alembic import op
from sqlalchemy import text

revision = "0023"
down_revision = "0022"

# The pager's count (0018, with 0019's `stale` manifest): a test holds it equal to
# rules_drift_health() in every manifest state.
WRONG_COUNT = """(SELECT (SELECT count(*) FROM rule_inventory
                        WHERE drift IN ('changed', 'unmanaged'))
                   + coalesce((SELECT missing_count FROM rules_drift), 0)
                   + coalesce((SELECT (manifest IN ('bad', 'absent', 'stale'))::integer
                               FROM rules_drift), 0))"""

# 0011's definition, restored by the downgrade.
OLD_CONSOLE_HEALTH = """
        CREATE FUNCTION console_health()
        RETURNS TABLE (
            oldest_pending_page_s bigint, failed_last_24h bigint,
            oldest_unassigned_alert_s bigint, reconcile_sources integer,
            reconcile_quiet_s double precision, backup_age_s double precision,
            posture_runs integer, posture_quiet_s double precision
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
                        ::double precision FROM backup_state),
                (SELECT count(*)::integer FROM posture_run),
                (SELECT extract(epoch FROM now() - coalesce(
                            max(at) FILTER (WHERE ok), min(at)))::double precision
                  FROM posture_run)
        $$
"""

NEW_CONSOLE_HEALTH = (
    """
        CREATE FUNCTION console_health()
        RETURNS TABLE (
            oldest_pending_page_s bigint, failed_last_24h bigint,
            oldest_unassigned_alert_s bigint, reconcile_sources integer,
            reconcile_quiet_s double precision, backup_age_s double precision,
            posture_runs integer, posture_quiet_s double precision,
            rules_drift integer, reconcile_gap_s integer
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
                        ::double precision FROM backup_state),
                (SELECT count(*)::integer FROM posture_run),
                (SELECT extract(epoch FROM now() - coalesce(
                            max(at) FILTER (WHERE ok), min(at)))::double precision
                  FROM posture_run),
                -- 0 when drift is not being checked, which is never a reason to page
                (SELECT CASE WHEN EXISTS (SELECT 1 FROM rules_drift)
                             THEN """
    + WRONG_COUNT
    + """::integer ELSE 0 END),
                (SELECT coalesce(max(extract(epoch FROM gap_to - gap_from)), 0)::integer
                  FROM reconcile_cursor WHERE gap_from IS NOT NULL)
        $$
"""
)

# ---- ops_overview(): health gains the gap, next to the other pager numbers ----

OV_HEALTH_OLD = "'posture_quiet_s', h.posture_quiet_s,"
OV_HEALTH_NEW = """'posture_quiet_s', h.posture_quiet_s,
        'reconcile_gap_s', h.reconcile_gap_s,"""
OVERVIEW_SWAPS = [(OV_HEALTH_OLD, OV_HEALTH_NEW)]

DEFINITION = text("SELECT pg_get_functiondef(CAST(:signature AS regprocedure))")
GRANT_WRITER = text("GRANT soc_console_writer TO current_user")


def _swap(signature: str, swaps: list[tuple[str, str]], *, reverse: bool) -> None:
    conn = op.get_bind()
    definition = conn.execute(DEFINITION, {"signature": signature}).scalar_one()
    for old, new in swaps:
        a, b = (new, old) if reverse else (old, new)
        if definition.count(a) != 1:
            raise RuntimeError(f"{signature} is not the definition this migration expects")
        definition = definition.replace(a, b)
    conn.execute(GRANT_WRITER)
    conn.exec_driver_sql(definition)


def _recreate_console_health(definition: str) -> None:
    op.execute("DROP FUNCTION console_health()")
    op.execute(definition)
    op.execute("GRANT soc_console_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_console_writer")
    op.execute("REVOKE ALL ON FUNCTION console_health() FROM PUBLIC")
    op.execute("ALTER FUNCTION console_health() OWNER TO soc_console_writer")
    op.execute("GRANT EXECUTE ON FUNCTION console_health() TO soc_console")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_console_writer")


def upgrade() -> None:
    op.execute("GRANT SELECT (gap_from, gap_to) ON reconcile_cursor TO soc_console_writer")
    _recreate_console_health(NEW_CONSOLE_HEALTH)
    _swap("ops_overview(integer, text)", OVERVIEW_SWAPS, reverse=False)


def downgrade() -> None:
    _swap("ops_overview(integer, text)", OVERVIEW_SWAPS, reverse=True)
    _recreate_console_health(OLD_CONSOLE_HEALTH)
    op.execute("REVOKE SELECT (gap_from, gap_to) ON reconcile_cursor FROM soc_console_writer")
