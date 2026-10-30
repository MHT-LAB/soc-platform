"""Reconcile health for the pager, and how late an alert was.

Revision ID: 0007
Revises: 0006

Two things the pager worker needs before the catch-up worker exists.

  reconcile_health()   one row for the "SOC STALE" check: how many sources have a
                       cursor, and the longest any of them has gone without a good run
                       (since the last success, or since the cursor row was created when
                       there has been none). No source names, no errors, no client data;
                       executable by soc_worker only. A source without a cursor row is
                       not counted, so nothing is flagged before the catch-up worker has
                       ever run.
  claim_pages(batch)   also returns late_s: seconds between when the first alert of the
                       page's case was detected and when it was received here (NULL when
                       the detection time is unknown). The worker puts "LATE:" in the
                       title when it is large, whichever path (webhook or catch-up)
                       delivered the alert.

reconcile_cursor gets started_at so a source that has only ever failed still goes stale.
Additive: the previous release's worker reads the pages by column name and ignores
late_s. Downgrade restores the previous claim_pages.
"""

from alembic import op

revision = "0007"
down_revision = "0006"

# claim_pages as 0005 left it, with __RET__ and __SEL__ for the one new column and
# __LCOL__ for the lateral subquery's extra column.
CLAIM = r"""
CREATE FUNCTION claim_pages(p_batch integer)
        RETURNS TABLE (
            id uuid, priority smallint, attempts integer, client_slug text, rule text,
            host text, link text, case_short text, detected_at timestamptz,
            case_id uuid, kind text__RET__
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
                  AND (n.kind = 'page' OR EXISTS (
                      SELECT 1 FROM soc_case c
                      WHERE c.client_id = n.client_id AND c.id = n.case_id
                        AND c.status = 'open'))
                ORDER BY n.priority DESC, n.created_at, n.id
                LIMIT p_batch FOR UPDATE SKIP LOCKED
            ), taken AS (
                UPDATE notification n
                SET attempts = n.attempts + 1,
                    next_attempt_at = now() + interval '2 minutes'
                FROM due WHERE n.id = due.id
                RETURNING n.id, n.priority, n.attempts, n.client_id, n.case_id, n.kind
            )
            SELECT t.id, t.priority, t.attempts, cl.slug, fa.rule,
                   left((fa.raw -> 'routing') ->> 'hostname', 64),
                   CASE WHEN fa.raw ->> 'link' LIKE 'https://app.limacharlie.io/%'
                        THEN left(fa.raw ->> 'link', 512) END,
                   left(t.case_id::text, 8), fa.detected_at, t.case_id, t.kind__SEL__
            FROM taken t
            JOIN client cl ON cl.id = t.client_id
            JOIN LATERAL (
                SELECT x.rule, x.raw, x.detected_at__LCOL__ FROM alert x
                WHERE x.client_id = t.client_id AND x.case_id = t.case_id
                ORDER BY x.received_at, x.id LIMIT 1
            ) fa ON true
            ORDER BY t.priority DESC, t.id;
        END
        $$
"""


def claim_pages(*, new: bool) -> str:
    return (
        CLAIM.replace("__RET__", ",\n            late_s double precision" if new else "")
        .replace(
            "__SEL__",
            ",\n                   extract(epoch FROM fa.received_at - fa.detected_at)"
            "::double precision"
            if new
            else "",
        )
        .replace("__LCOL__", ", x.received_at" if new else "")
    )


def regrant() -> None:
    op.execute("REVOKE ALL ON FUNCTION claim_pages(integer) FROM PUBLIC")
    op.execute("GRANT soc_worker_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_worker_writer")
    op.execute("ALTER FUNCTION claim_pages(integer) OWNER TO soc_worker_writer")
    op.execute("GRANT EXECUTE ON FUNCTION claim_pages(integer) TO soc_worker")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_worker_writer")


def upgrade() -> None:
    op.execute(
        "ALTER TABLE reconcile_cursor ADD COLUMN started_at timestamptz NOT NULL DEFAULT now()"
    )
    # The worker's writer reads two columns of the cursor table, through an RLS policy.
    op.execute("GRANT SELECT (last_success, started_at) ON reconcile_cursor TO soc_worker_writer")
    op.execute(
        "CREATE POLICY worker_reconcile_read ON reconcile_cursor FOR SELECT "
        "TO soc_worker_writer USING (true)"
    )
    op.execute(
        """
        CREATE FUNCTION reconcile_health()
        RETURNS TABLE (sources integer, quiet_s double precision)
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT count(*)::integer,
                   max(extract(epoch FROM now() - coalesce(last_success, started_at)))
                       ::double precision
            FROM reconcile_cursor
        $$
        """
    )
    op.execute("GRANT soc_worker_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_worker_writer")
    op.execute("REVOKE ALL ON FUNCTION reconcile_health() FROM PUBLIC")
    op.execute("ALTER FUNCTION reconcile_health() OWNER TO soc_worker_writer")
    op.execute("GRANT EXECUTE ON FUNCTION reconcile_health() TO soc_worker")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_worker_writer")

    # a function's result columns cannot change in place
    op.execute("DROP FUNCTION claim_pages(integer)")
    op.execute(claim_pages(new=True))
    regrant()


def downgrade() -> None:
    op.execute("DROP FUNCTION claim_pages(integer)")
    op.execute(claim_pages(new=False))
    regrant()
    op.execute("DROP FUNCTION reconcile_health()")
    op.execute("DROP POLICY worker_reconcile_read ON reconcile_cursor")
    op.execute(
        "REVOKE SELECT (last_success, started_at) ON reconcile_cursor FROM soc_worker_writer"
    )
    op.execute("ALTER TABLE reconcile_cursor DROP COLUMN started_at")
