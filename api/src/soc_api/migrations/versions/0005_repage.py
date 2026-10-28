"""Re-paging: a second and third push for an urgent page nobody acknowledged.

Revision ID: 0005
Revises: 0004

An urgent (priority 5) page that was sent and whose case is still `open` (not
acknowledged, not closed) is sent again after the first interval and once more after
the second; the worker's settings say how long (15 and 60 minutes). Re-sends are
ordinary rows in `notification` with a `kind`, so they follow the same lease, retry and
give-up rules as any page and show up in the counters.

  queue_repages(first, second)   adds the due re-send rows (once each: a unique index on
                                 case and kind makes it idempotent and race-proof) and
                                 marks pending re-sends for cases that are no longer open
                                 `skipped`, so nothing is sent after an Ack or a Close
  claim_pages(batch)             now also returns the full case id and the kind, and never
                                 hands out a re-send whose case is no longer open

Additive: the previous release's code never reads `kind`, and inserts pages with the
default `page`. Downgrade restores the previous claim_pages.
"""

from alembic import op

revision = "0005"
down_revision = "0004"

CLAIM = r"""
CREATE FUNCTION claim_pages(p_batch integer)
        RETURNS TABLE (
            id uuid, priority smallint, attempts integer, client_slug text, rule text,
            host text, link text, case_short text, detected_at timestamptz__RET__
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
                WHERE n.status = 'pending' AND n.next_attempt_at <= now()__DUE__
                ORDER BY n.priority DESC, n.created_at, n.id
                LIMIT p_batch FOR UPDATE SKIP LOCKED
            ), taken AS (
                UPDATE notification n
                SET attempts = n.attempts + 1,
                    next_attempt_at = now() + interval '2 minutes'
                FROM due WHERE n.id = due.id
                RETURNING n.id, n.priority, n.attempts, n.client_id, n.case_id__TAKEN__
            )
            SELECT t.id, t.priority, t.attempts, cl.slug, fa.rule,
                   left((fa.raw -> 'routing') ->> 'hostname', 64),
                   CASE WHEN fa.raw ->> 'link' LIKE 'https://app.limacharlie.io/%'
                        THEN left(fa.raw ->> 'link', 512) END,
                   left(t.case_id::text, 8), fa.detected_at__SEL__
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

REPAGE_KINDS = "'repage1', 'repage2'"


def claim_pages(*, new: bool) -> str:
    return (
        CLAIM.replace("__RET__", ",\n            case_id uuid, kind text" if new else "")
        .replace(
            "__DUE__",
            """
                  AND (n.kind = 'page' OR EXISTS (
                      SELECT 1 FROM soc_case c
                      WHERE c.client_id = n.client_id AND c.id = n.case_id
                        AND c.status = 'open'))"""
            if new
            else "",
        )
        .replace("__TAKEN__", ", n.kind" if new else "")
        .replace("__SEL__", ", t.case_id, t.kind" if new else "")
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
        "ALTER TABLE notification ADD COLUMN kind text NOT NULL DEFAULT 'page' "
        "CHECK (kind IN ('page', 'repage1', 'repage2'))"
    )
    op.execute("CREATE UNIQUE INDEX notification_case_kind ON notification (case_id, kind)")

    op.execute(
        f"""
        CREATE FUNCTION queue_repages(p_first interval, p_second interval) RETURNS integer
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            n_first integer;
            n_second integer;
        BEGIN
            IF p_first IS NULL OR p_second IS NULL OR p_first < interval '1 second'
               OR p_second <= p_first OR p_second > interval '7 days' THEN
                RAISE EXCEPTION 'bad re-page intervals';
            END IF;
            -- nothing is sent after an Ack or a Close
            UPDATE notification n SET status = 'skipped'
            FROM soc_case c
            WHERE n.kind IN ({REPAGE_KINDS}) AND n.status = 'pending'
              AND c.client_id = n.client_id AND c.id = n.case_id AND c.status <> 'open';
            -- first re-send: the original urgent page went out long enough ago
            INSERT INTO notification (client_id, case_id, channel, priority, kind)
            SELECT o.client_id, o.case_id, o.channel, o.priority, 'repage1'
            FROM notification o
            JOIN soc_case c ON c.client_id = o.client_id AND c.id = o.case_id
            WHERE o.kind = 'page' AND o.priority = 5 AND o.status = 'sent'
              AND o.sent_at <= now() - p_first AND c.status = 'open'
            ON CONFLICT (case_id, kind) DO NOTHING;
            GET DIAGNOSTICS n_first = ROW_COUNT;
            -- second re-send: only after the first one has actually gone out
            INSERT INTO notification (client_id, case_id, channel, priority, kind)
            SELECT o.client_id, o.case_id, o.channel, o.priority, 'repage2'
            FROM notification o
            JOIN soc_case c ON c.client_id = o.client_id AND c.id = o.case_id
            JOIN notification r ON r.case_id = o.case_id AND r.kind = 'repage1'
                               AND r.status = 'sent'
            WHERE o.kind = 'page' AND o.priority = 5 AND o.status = 'sent'
              AND o.sent_at <= now() - p_second AND c.status = 'open'
            ON CONFLICT (case_id, kind) DO NOTHING;
            GET DIAGNOSTICS n_second = ROW_COUNT;
            RETURN n_first + n_second;
        END
        $$
        """
    )
    op.execute("GRANT soc_worker_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_worker_writer")
    op.execute("REVOKE ALL ON FUNCTION queue_repages(interval, interval) FROM PUBLIC")
    op.execute("ALTER FUNCTION queue_repages(interval, interval) OWNER TO soc_worker_writer")
    op.execute("GRANT EXECUTE ON FUNCTION queue_repages(interval, interval) TO soc_worker")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_worker_writer")

    # a function's result columns cannot change in place
    op.execute("DROP FUNCTION claim_pages(integer)")
    op.execute(claim_pages(new=True))
    regrant()


def downgrade() -> None:
    op.execute("DROP FUNCTION claim_pages(integer)")
    op.execute(claim_pages(new=False))
    regrant()
    op.execute("DROP FUNCTION queue_repages(interval, interval)")
    op.execute("DROP INDEX notification_case_kind")
    op.execute("ALTER TABLE notification DROP COLUMN kind")
