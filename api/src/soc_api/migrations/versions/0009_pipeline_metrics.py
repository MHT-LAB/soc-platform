"""Pipeline counters for the console's /metrics page, read from the database.

Revision ID: 0009
Revises: 0008

The API, the pager worker and the catch-up worker are separate containers, so counters kept
in a process would not add up. The numbers are therefore counted from the rows themselves,
by one function in the same shape as the other console functions:

  pipeline_metrics()  SECURITY DEFINER, owned by soc_console_writer, EXECUTE for soc_console
                      only. Returns rows (metric, label, value): a fixed list of metric
                      names, and a label that is either empty, a source slug, a page kind
                      from a fixed list, or a histogram bound from a fixed list. No client
                      names, hostnames, alert text or ids ever appear.

  alerts_ingested     per source slug (a slug is our own configuration, and a webhook for a
                      source we do not have is refused, so the set cannot be widened from
                      outside); sources with no alert yet report 0
  alerts_grouped      alerts that joined a case that already existed (the "de-duplicated"
                      count: a second delivery of the same event id is refused by the
                      database and not recorded, so that kind of duplicate cannot be counted
                      from rows)
  alerts_late         alerts stored more than 5 minutes after the detection time, which is
                      the pager's own LATE rule (the catch-up worker's finds)
  pages_sent          notifications sent, per kind (page, repage1, repage2)
  pages_failed        notifications that failed
  cases_acked         cases acknowledged by a person
  ack_latency_*       seconds from the first page that went out for a case to its
                      acknowledgement: cumulative buckets (label = upper bound in seconds),
                      a sum and a count, over all time so rate() works

The console writer gets column-only read access to source (id, slug) behind a policy, for
the per-source count. Additive; downgrade removes the function, the policy and the grant.
"""

from alembic import op

revision = "0009"
down_revision = "0008"

# Upper bounds, in seconds, of the acknowledge-latency histogram: 1, 5, 15 minutes, 1, 4 hours.
BUCKETS = (60, 300, 900, 3600, 14400)


def upgrade() -> None:
    op.execute("GRANT SELECT (id, slug) ON source TO soc_console_writer")
    op.execute(
        "CREATE POLICY console_select ON source FOR SELECT TO soc_console_writer USING (true)"
    )

    op.execute(
        f"""
        CREATE FUNCTION pipeline_metrics()
        RETURNS TABLE (metric text, label text, value double precision)
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            WITH acked AS (
                SELECT extract(epoch FROM e.at - p.first_sent)::double precision AS secs
                FROM case_event e
                JOIN LATERAL (
                    SELECT min(n.sent_at) AS first_sent FROM notification n
                    WHERE n.client_id = e.client_id AND n.case_id = e.case_id
                      AND n.sent_at IS NOT NULL
                ) p ON p.first_sent IS NOT NULL
                WHERE e.kind = 'acked'
            ),
            kinds(kind) AS (VALUES ('page'), ('repage1'), ('repage2')),
            bounds(le) AS (VALUES {", ".join(f"({b})" for b in BUCKETS)}),
            clean AS (SELECT greatest(secs, 0) AS secs FROM acked)
            SELECT 'alerts_ingested', s.slug,
                   (SELECT count(*) FROM alert a WHERE a.source_id = s.id)::double precision
            FROM source s
            UNION ALL SELECT 'alerts_grouped', '',
                   (SELECT count(*) FROM case_event WHERE kind = 'alert_attached')::double precision
            UNION ALL SELECT 'alerts_late', '',
                   (SELECT count(*) FROM alert
                    WHERE detected_at IS NOT NULL
                      AND received_at - detected_at > interval '300 seconds')::double precision
            UNION ALL SELECT 'pages_sent', k.kind,
                   (SELECT count(*) FROM notification n
                    WHERE n.status = 'sent' AND n.kind = k.kind)::double precision
            FROM kinds k
            UNION ALL SELECT 'pages_failed', '',
                   (SELECT count(*) FROM notification WHERE status = 'failed')::double precision
            UNION ALL SELECT 'cases_acked', '',
                   (SELECT count(*) FROM case_event WHERE kind = 'acked')::double precision
            UNION ALL SELECT 'ack_latency_bucket', b.le::text,
                   (SELECT count(*) FROM clean WHERE clean.secs <= b.le)::double precision
            FROM bounds b
            UNION ALL SELECT 'ack_latency_sum', '',
                   coalesce((SELECT sum(secs) FROM clean), 0)::double precision
            UNION ALL SELECT 'ack_latency_count', '',
                   (SELECT count(*) FROM clean)::double precision
        $$
        """
    )
    op.execute("GRANT soc_console_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_console_writer")
    op.execute("REVOKE ALL ON FUNCTION pipeline_metrics() FROM PUBLIC")
    op.execute("ALTER FUNCTION pipeline_metrics() OWNER TO soc_console_writer")
    op.execute("GRANT EXECUTE ON FUNCTION pipeline_metrics() TO soc_console")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_console_writer")


def downgrade() -> None:
    op.execute("DROP FUNCTION pipeline_metrics()")
    op.execute("DROP POLICY console_select ON source")
    op.execute("REVOKE SELECT (id, slug) ON source FROM soc_console_writer")
