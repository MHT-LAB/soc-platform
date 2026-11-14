"""Ops Overview: one read-only function for the console's overview pages, and deploy marks.

Revision ID: 0012
Revises: 0011

The Operations, Fleet, Sources and Rules pages of the console all read from one function, in
the shape of the other console functions:

  ops_overview(period_days, client_slug)
      SECURITY DEFINER, STABLE, owned by soc_console_writer, EXECUTE for soc_console only.
      Returns one jsonb document of plain numbers and cut text. period_days must be 1, 7 or 30
      and client_slug must be 'all' or an existing client's slug; anything else raises. The
      document holds: the counts for the page title, the signal-flow figures (newest alert,
      pages sent and failed, the pager's 95th-percentile created-to-sent time), the latest open
      cases, MITRE ATT&CK tactic counts (from alert.mitre_hint, written "Tactic / Txxxx"),
      the raw health numbers (console_health() plus sensors, sources and org errors), the
      detection timeline (hourly for 1 and 7 days, daily for 30, counted by SOURCE TYPE, with
      the deploy marks), the case funnel by lane and status, mean time to acknowledge and to
      close over 7 and 30 days, the sensor fleet, the sources and the noisiest rules.
      A source's slug is the secret part of the public webhook path: the function never
      reads it (the console role has no column grant for it) and never returns it.

  deploy_mark(sha)
      Records that a build was deployed. Not SECURITY DEFINER and with no EXECUTE for any
      service role, like backup_mark_ok (0008): deploy.sh calls it as the superuser over the
      database container's own socket. Anything but a full lower-case commit hash raises.

New table deploy_event (at, sha), with row level security and no right for any service
role except column-only SELECT for the console's writer. The writer also gets column-only
SELECT (and a policy) on the tables the overview reads that it could not read before: source
(id, client_id, type, enabled; not slug, external_id or secret_ref), sensor_state,
rule_inventory, and a few more columns of reconcile_cursor and posture_run. Additive;
downgrade removes the functions, the table, the policies and the grants.
"""

from alembic import op

revision = "0012"
down_revision = "0011"

SENSOR_COLUMNS = "sid, hostname, platform, version, online, isolated, last_seen, updated_at"

OPS_OVERVIEW = r"""
CREATE FUNCTION ops_overview(p_days integer, p_client text DEFAULT 'all') RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    cid uuid;
    since timestamptz;
    unit text;
    h record;
    d integer;
    v_totals jsonb;
    v_flow jsonb;
    v_queue jsonb;
    v_open jsonb;
    v_tactics jsonb;
    v_health jsonb;
    v_timeline jsonb;
    v_deploys jsonb;
    v_funnel jsonb;
    v_response jsonb := '{}'::jsonb;
    v_fleet jsonb;
    v_sources jsonb;
    v_rules jsonb;
    v_inventory jsonb;
    v_clients jsonb;
BEGIN
    IF p_days IS NULL OR p_days NOT IN (1, 7, 30) THEN
        RAISE EXCEPTION 'period must be 1, 7 or 30 days';
    END IF;
    IF p_client IS NULL THEN
        RAISE EXCEPTION 'unknown client';
    END IF;
    IF p_client <> 'all' THEN
        SELECT id INTO cid FROM client WHERE slug = p_client;
        IF cid IS NULL THEN
            RAISE EXCEPTION 'unknown client';
        END IF;
    END IF;
    since := now() - make_interval(days => p_days);
    unit := CASE WHEN p_days = 30 THEN 'day' ELSE 'hour' END;

    SELECT coalesce(jsonb_agg(slug ORDER BY slug), '[]') INTO v_clients FROM client;

    -- A case's lane: the one written on it wins; otherwise a case that has a page queued, sent
    -- or failed is 'paged' and any other is 'quiet' (logged, nobody paged).

    SELECT jsonb_build_object(
        'alerts_in', (SELECT count(*) FROM alert a
                       WHERE a.received_at >= since AND (cid IS NULL OR a.client_id = cid)),
        'pages', (SELECT count(*) FROM notification n
                   WHERE n.kind = 'page' AND n.status = 'sent' AND n.sent_at >= since
                     AND (cid IS NULL OR n.client_id = cid)),
        'cases', (SELECT count(*) FROM soc_case c
                   WHERE c.opened_at >= since AND (cid IS NULL OR c.client_id = cid))
    ) INTO v_totals;

    SELECT coalesce(jsonb_object_agg(severity, n), '{}') INTO v_open FROM (
        SELECT c.severity, count(*) AS n FROM soc_case c
        WHERE c.status IN ('open', 'acknowledged') AND (cid IS NULL OR c.client_id = cid)
        GROUP BY c.severity) s;

    SELECT jsonb_build_object(
        'last_alert_age_s', (SELECT floor(extract(epoch FROM now() - max(a.received_at)))
                              FROM alert a WHERE cid IS NULL OR a.client_id = cid),
        'sources_total', (SELECT count(*) FROM source s WHERE cid IS NULL OR s.client_id = cid),
        'sources_enabled', (SELECT count(*) FROM source s
                             WHERE s.enabled AND (cid IS NULL OR s.client_id = cid)),
        'pages_sent', (SELECT count(*) FROM notification n
                        WHERE n.status = 'sent' AND n.sent_at >= since
                          AND (cid IS NULL OR n.client_id = cid)),
        'pages_failed', (SELECT count(*) FROM notification n
                          WHERE n.status = 'failed' AND n.created_at >= since
                            AND (cid IS NULL OR n.client_id = cid)),
        'pager_p95_s', (SELECT percentile_cont(0.95) WITHIN GROUP (
                            ORDER BY extract(epoch FROM n.sent_at - n.created_at))
                        FROM notification n
                        WHERE n.kind = 'page' AND n.status = 'sent' AND n.sent_at >= since
                          AND (cid IS NULL OR n.client_id = cid)),
        'pager_n', (SELECT count(*) FROM notification n
                     WHERE n.kind = 'page' AND n.status = 'sent' AND n.sent_at >= since
                       AND (cid IS NULL OR n.client_id = cid)),
        'unacked_pages', (SELECT count(*) FROM soc_case c
                           WHERE c.status = 'open' AND (cid IS NULL OR c.client_id = cid)
                             AND EXISTS (SELECT 1 FROM notification n
                                         WHERE n.client_id = c.client_id AND n.case_id = c.id
                                           AND n.kind = 'page' AND n.status = 'sent')),
        'last_ack_age_s', (SELECT floor(extract(epoch FROM now() - max(e.at)))
                            FROM case_event e
                            WHERE e.kind = 'acked' AND (cid IS NULL OR e.client_id = cid))
    ) INTO v_flow;

    -- latest open cases
    SELECT coalesce(jsonb_agg(q ORDER BY (q ->> 'opened_s')::bigint DESC), '[]') INTO v_queue FROM (
        SELECT jsonb_build_object(
            'id', c.id,
            'severity', c.severity,
            'status', c.status,
            'rule', left(fa.rule, 200),
            'summary', left(coalesce(nullif(fa.summary, ''), fa.rule), 200),
            'host', left((fa.raw -> 'routing') ->> 'hostname', 64),
            'lane', left(coalesce(c.lane, CASE WHEN EXISTS (
                    SELECT 1 FROM notification n
                    WHERE n.client_id = c.client_id AND n.case_id = c.id AND n.kind = 'page'
                      AND n.status IN ('pending', 'sent', 'failed')) THEN 'paged' ELSE 'quiet' END),
                20),
            'verdict', left(c.verdict, 200),
            'age_s', floor(extract(epoch FROM now() - c.opened_at)),
            'opened_s', floor(extract(epoch FROM c.opened_at))
        ) AS q
        FROM soc_case c
        LEFT JOIN LATERAL (
            SELECT a.rule, a.summary, a.raw FROM alert a
            WHERE a.client_id = c.client_id AND a.case_id = c.id
            ORDER BY a.received_at, a.id LIMIT 1
        ) fa ON true
        WHERE c.status IN ('open', 'acknowledged') AND (cid IS NULL OR c.client_id = cid)
        ORDER BY c.opened_at DESC, c.id
        LIMIT 10
    ) x;

    -- tactics: mitre_hint is "Tactic" or "Tactic / T1234(.567)"; a technique is kept only when
    -- it looks like one
    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'tactic', tactic, 'technique', technique, 'n', n)), '[]')
    INTO v_tactics FROM (
        SELECT left(btrim(split_part(a.mitre_hint, '/', 1)), 60) AS tactic,
               CASE WHEN btrim(split_part(a.mitre_hint, '/', 2)) ~ '^T[0-9]{4}(\.[0-9]{3})?$'
                    THEN btrim(split_part(a.mitre_hint, '/', 2)) END AS technique,
               count(*) AS n
        FROM alert a
        WHERE a.received_at >= since AND (cid IS NULL OR a.client_id = cid)
          AND a.mitre_hint IS NOT NULL AND btrim(split_part(a.mitre_hint, '/', 1)) <> ''
        GROUP BY 1, 2
        ORDER BY n DESC
        LIMIT 200
    ) t;

    -- raw health numbers; the page decides colors with the pager's own limits
    SELECT * INTO h FROM console_health();
    SELECT jsonb_build_object(
        'oldest_pending_page_s', h.oldest_pending_page_s,
        'failed_last_24h', h.failed_last_24h,
        'oldest_unassigned_alert_s', h.oldest_unassigned_alert_s,
        'reconcile_sources', h.reconcile_sources,
        'reconcile_quiet_s', h.reconcile_quiet_s,
        'backup_age_s', h.backup_age_s,
        'posture_runs', h.posture_runs,
        'posture_quiet_s', h.posture_quiet_s,
        'reconcile_errors', (SELECT count(*) FROM reconcile_cursor WHERE last_error IS NOT NULL),
        'org_errors', (SELECT org_error_count FROM posture_run WHERE ok
                        ORDER BY at DESC LIMIT 1),
        'sensors_total', (SELECT count(*) FROM sensor_state),
        'sensors_online', (SELECT count(*) FROM sensor_state WHERE online),
        'sensors_updated_age_s', (SELECT floor(extract(epoch FROM now() - max(updated_at)))
                                   FROM sensor_state),
        'last_page_sent_age_s', (SELECT floor(extract(epoch FROM now() - max(sent_at)))
                                  FROM notification WHERE status = 'sent')
    ) INTO v_health;

    -- timeline: every bucket in the window, even the empty ones, counted by source type
    SELECT jsonb_build_object(
        'unit', unit,
        'rows', coalesce(jsonb_agg(jsonb_build_object('t', floor(extract(epoch FROM b.t)),
                                                      'c', coalesce(b.c, '{}')) ORDER BY b.t), '[]')
    ) INTO v_timeline FROM (
        SELECT g.t,
               (SELECT jsonb_object_agg(k.type, k.n) FROM (
                    SELECT left(s.type, 40) AS type, count(*) AS n
                    FROM alert a JOIN source s ON s.id = a.source_id
                    WHERE a.received_at >= g.t
                      AND a.received_at < g.t + (CASE WHEN unit = 'day' THEN interval '1 day'
                                                      ELSE interval '1 hour' END)
                      AND a.received_at >= since AND (cid IS NULL OR a.client_id = cid)
                    GROUP BY 1) k) AS c
        FROM generate_series(
                 date_trunc(unit, since),
                 date_trunc(unit, now()),
                 CASE WHEN unit = 'day' THEN interval '1 day' ELSE interval '1 hour' END) AS g(t)
    ) b;

    SELECT coalesce(jsonb_agg(jsonb_build_object('at', floor(extract(epoch FROM e.at)),
                                                 'sha', left(e.sha, 7)) ORDER BY e.at), '[]')
    INTO v_deploys FROM deploy_event e WHERE e.at >= since;

    -- funnel: cases opened in the period by lane and status
    SELECT coalesce(jsonb_agg(jsonb_build_object('lane', lane, 'status', status, 'n', n)), '[]')
    INTO v_funnel FROM (
        SELECT left(coalesce(c.lane, CASE WHEN EXISTS (
                    SELECT 1 FROM notification n
                    WHERE n.client_id = c.client_id AND n.case_id = c.id AND n.kind = 'page'
                      AND n.status IN ('pending', 'sent', 'failed')) THEN 'paged' ELSE 'quiet' END),
                20) AS lane,
               c.status, count(*) AS n
        FROM soc_case c
        WHERE c.opened_at >= since AND (cid IS NULL OR c.client_id = cid)
        GROUP BY 1, 2 ORDER BY 1, 2
    ) f;

    -- mean time to acknowledge (first page sent -> first acknowledgement) and to close
    -- (opened -> closed), for the last 7 and 30 days whatever the period is
    FOREACH d IN ARRAY ARRAY[7, 30] LOOP
        v_response := v_response || jsonb_build_object(d::text, jsonb_build_object(
            'mtta', (SELECT jsonb_build_object('n', count(*), 'avg_s', round(avg(secs))) FROM (
                SELECT greatest(extract(epoch FROM ack.at - pg.sent_at), 0) AS secs
                FROM soc_case c
                CROSS JOIN LATERAL (SELECT min(e.at) AS at FROM case_event e
                                    WHERE e.client_id = c.client_id AND e.case_id = c.id
                                      AND e.kind = 'acked') ack
                CROSS JOIN LATERAL (SELECT min(n.sent_at) AS sent_at FROM notification n
                                    WHERE n.client_id = c.client_id AND n.case_id = c.id
                                      AND n.kind = 'page' AND n.sent_at IS NOT NULL) pg
                WHERE ack.at >= now() - make_interval(days => d) AND pg.sent_at IS NOT NULL
                  AND (cid IS NULL OR c.client_id = cid)) m),
            'mttr', (SELECT jsonb_build_object('n', count(*), 'avg_s', round(avg(secs))) FROM (
                SELECT greatest(extract(epoch FROM c.closed_at - c.opened_at), 0) AS secs
                FROM soc_case c
                WHERE c.status = 'closed' AND c.closed_at >= now() - make_interval(days => d)
                  AND (cid IS NULL OR c.client_id = cid)) m)
        ));
    END LOOP;

    -- the sensor fleet is the organization's (posture knows no client): offline first
    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'hostname', left(s.hostname, 64), 'platform', left(s.platform, 40),
               'version', left(s.version, 40), 'online', s.online, 'isolated', s.isolated,
               'last_seen_age_s', floor(extract(epoch FROM now() - s.last_seen)),
               'updated_age_s', floor(extract(epoch FROM now() - s.updated_at))
           ) ORDER BY s.online, s.hostname), '[]') INTO v_fleet
    FROM (SELECT hostname, platform, version, online, isolated, last_seen, updated_at
          FROM sensor_state ORDER BY online, hostname LIMIT 500) s;

    -- sources: type, client, whether it is on, and when it was last heard from. No slug.
    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'type', left(s.type, 40), 'client', cl.slug, 'enabled', s.enabled,
               'alerts', (SELECT count(*) FROM alert a
                           WHERE a.source_id = s.id AND a.received_at >= since),
               'last_alert_age_s', (SELECT floor(extract(epoch FROM now() - max(a.received_at)))
                                    FROM alert a WHERE a.source_id = s.id),
               'has_cursor', rc.source_id IS NOT NULL,
               'catchup_age_s', floor(extract(epoch FROM
                                     now() - coalesce(rc.last_success, rc.started_at))),
               'catchup_error', rc.last_error
           ) ORDER BY s.type, s.id), '[]') INTO v_sources
    FROM (SELECT id, client_id, type, enabled FROM source
          WHERE cid IS NULL OR client_id = cid ORDER BY type, id LIMIT 100) s
    JOIN client cl ON cl.id = s.client_id
    LEFT JOIN reconcile_cursor rc ON rc.source_id = s.id;

    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'rule', r.rule, 'alerts', r.alerts, 'cases', r.cases, 'last_age_s', r.last_age_s,
               'worst', r.worst,
               'inventory', (SELECT CASE WHEN count(*) = 0 THEN NULL
                                          WHEN bool_or(i.enabled) THEN 'enabled'
                                          ELSE 'disabled' END
                              FROM rule_inventory i WHERE i.name = r.rule)
           ) ORDER BY r.alerts DESC, r.rule), '[]') INTO v_rules
    FROM (
        SELECT left(coalesce(a.rule, ''), 200) AS rule, count(*) AS alerts,
               count(DISTINCT a.case_id) AS cases,
               floor(extract(epoch FROM now() - max(a.received_at))) AS last_age_s,
               (ARRAY['critical', 'high', 'medium', 'low', 'info'])[
                   min(CASE a.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                                       WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END)] AS worst
        FROM alert a
        WHERE a.received_at >= since AND (cid IS NULL OR a.client_id = cid)
        GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT 25
    ) r;

    SELECT coalesce(jsonb_agg(jsonb_build_object('namespace', namespace, 'enabled', en,
                                                 'disabled', dis) ORDER BY namespace), '[]')
    INTO v_inventory FROM (
        SELECT namespace, count(*) FILTER (WHERE enabled) AS en,
               count(*) FILTER (WHERE NOT enabled) AS dis
        FROM rule_inventory GROUP BY namespace) i;

    RETURN jsonb_build_object(
        'generated_at', floor(extract(epoch FROM now())),
        'period_days', p_days,
        'client', p_client,
        'clients', v_clients,
        'totals', v_totals,
        'flow', v_flow,
        'open_by_severity', v_open,
        'queue', v_queue,
        'tactics', v_tactics,
        'health', v_health,
        'timeline', v_timeline,
        'deploys', v_deploys,
        'funnel', v_funnel,
        'response', v_response,
        'fleet', v_fleet,
        'sources', v_sources,
        'rules', v_rules,
        'rule_inventory', v_inventory
    );
END
$$
"""


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE deploy_event (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            at timestamptz NOT NULL DEFAULT now(),
            sha text NOT NULL CHECK (sha ~ '^[0-9a-f]{40}$')
        )
        """
    )
    op.execute("CREATE INDEX deploy_event_at ON deploy_event (at)")
    op.execute("ALTER TABLE deploy_event ENABLE ROW LEVEL SECURITY")
    op.execute("GRANT SELECT (at, sha) ON deploy_event TO soc_console_writer")
    op.execute(
        "CREATE POLICY console_overview_read ON deploy_event FOR SELECT "
        "TO soc_console_writer USING (true)"
    )
    op.execute(
        """
        CREATE FUNCTION deploy_mark(p_sha text) RETURNS void
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        BEGIN
            IF p_sha IS NULL OR p_sha !~ '^[0-9a-f]{40}$' THEN
                RAISE EXCEPTION 'a deploy is marked with a full commit hash';
            END IF;
            INSERT INTO deploy_event (sha) VALUES (p_sha);
            DELETE FROM deploy_event WHERE at < now() - interval '400 days';
        END
        $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION deploy_mark(text) FROM PUBLIC")

    # What the overview reads, column by column, behind policies for the console's writer.
    # The source table's slug, external_id and secret_ref are deliberately left out.
    op.execute("GRANT SELECT (id, client_id, type, enabled) ON source TO soc_console_writer")
    op.execute(
        "CREATE POLICY console_overview_read ON source FOR SELECT "
        "TO soc_console_writer USING (true)"
    )
    op.execute(f"GRANT SELECT ({SENSOR_COLUMNS}) ON sensor_state TO soc_console_writer")
    op.execute(
        "CREATE POLICY console_overview_read ON sensor_state FOR SELECT "
        "TO soc_console_writer USING (true)"
    )
    op.execute("GRANT SELECT (namespace, name, enabled) ON rule_inventory TO soc_console_writer")
    op.execute(
        "CREATE POLICY console_overview_read ON rule_inventory FOR SELECT "
        "TO soc_console_writer USING (true)"
    )
    op.execute("GRANT SELECT (source_id, last_error) ON reconcile_cursor TO soc_console_writer")
    op.execute("GRANT SELECT (org_error_count) ON posture_run TO soc_console_writer")

    op.execute(OPS_OVERVIEW)
    op.execute("GRANT soc_console_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_console_writer")
    op.execute("REVOKE ALL ON FUNCTION ops_overview(integer, text) FROM PUBLIC")
    op.execute("ALTER FUNCTION ops_overview(integer, text) OWNER TO soc_console_writer")
    op.execute("GRANT EXECUTE ON FUNCTION ops_overview(integer, text) TO soc_console")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_console_writer")


def downgrade() -> None:
    op.execute("DROP FUNCTION ops_overview(integer, text)")
    op.execute("DROP FUNCTION deploy_mark(text)")
    op.execute("DROP POLICY console_overview_read ON rule_inventory")
    op.execute("DROP POLICY console_overview_read ON sensor_state")
    op.execute("DROP POLICY console_overview_read ON source")
    op.execute("DROP POLICY console_overview_read ON deploy_event")
    op.execute("REVOKE SELECT (org_error_count) ON posture_run FROM soc_console_writer")
    op.execute("REVOKE SELECT (source_id, last_error) ON reconcile_cursor FROM soc_console_writer")
    op.execute("REVOKE SELECT (namespace, name, enabled) ON rule_inventory FROM soc_console_writer")
    op.execute(f"REVOKE SELECT ({SENSOR_COLUMNS}) ON sensor_state FROM soc_console_writer")
    op.execute("REVOKE SELECT (id, client_id, type, enabled) ON source FROM soc_console_writer")
    op.execute("DROP TABLE deploy_event")
