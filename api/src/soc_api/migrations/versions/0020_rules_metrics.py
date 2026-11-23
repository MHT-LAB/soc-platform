"""Rules tab metrics: how often each rule fires and how often its cases were noise.

Revision ID: 0020
Revises: 0019

One new read-only function, rules_metrics(client), for the console. It does not touch
ops_overview(). Nothing is stored: every number is worked out from alerts and cases.

  rules        per rule name, over the last 7 and 30 days (not the page's period):
                 alerts_7, alerts_30            how often it fired
                 judged                         its cases that were closed with a verdict
                                                (a duplicate says nothing about the rule)
                 noise                          of those, closed as our test, our admin work
                                                or a false positive
  tactics      per (ATT&CK tactic, rule) in the last 30 days: the alert count (the tactic is
               read from alert.mitre_hint, written "Tactic / Txxxx"); the page groups them
  deployed_at  when the newest manifest on record was deployed (rules_drift.manifest_at_max),
               or null when nothing has been deployed from git

A case counts for each rule that has an alert in it. The client argument is 'all' or a slug.
Only the console's login may call it; it is owned by the console's writer role, which already
reads these tables for ops_overview().
"""

from alembic import op

revision = "0020"
down_revision = "0019"

SIGNATURE = "rules_metrics(text)"

FUNCTION = r"""
CREATE FUNCTION rules_metrics(p_client text DEFAULT 'all') RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    cid uuid;
    v_rules jsonb;
    v_tactics jsonb;
    v_deployed bigint;
BEGIN
    IF p_client IS NULL THEN
        RAISE EXCEPTION 'unknown client';
    END IF;
    IF p_client <> 'all' THEN
        SELECT id INTO cid FROM client WHERE slug = p_client;
        IF cid IS NULL THEN
            RAISE EXCEPTION 'unknown client';
        END IF;
    END IF;

    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'rule', r.rule, 'alerts_7', r.alerts_7, 'alerts_30', r.alerts_30,
               'judged', r.judged, 'noise', r.noise
           ) ORDER BY r.alerts_30 DESC, r.rule), '[]') INTO v_rules
    FROM (
        SELECT left(coalesce(a.rule, ''), 200) AS rule,
               count(*) FILTER (WHERE a.received_at >= now() - interval '7 days') AS alerts_7,
               count(*) AS alerts_30,
               count(DISTINCT a.case_id) FILTER (
                   WHERE c.status = 'closed' AND c.verdict IS NOT NULL
                     AND c.verdict <> 'duplicate') AS judged,
               count(DISTINCT a.case_id) FILTER (
                   WHERE c.status = 'closed'
                     AND c.verdict IN ('test', 'authorized_activity', 'false_positive')) AS noise
        FROM alert a
        LEFT JOIN soc_case c ON c.client_id = a.client_id AND c.id = a.case_id
        WHERE a.received_at >= now() - interval '30 days'
          AND (cid IS NULL OR a.client_id = cid)
        GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT 50
    ) r;

    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'tactic', t.tactic, 'rule', t.rule, 'alerts', t.alerts
           ) ORDER BY t.alerts DESC, t.tactic, t.rule), '[]') INTO v_tactics
    FROM (
        SELECT left(btrim(split_part(a.mitre_hint, '/', 1)), 60) AS tactic,
               left(coalesce(a.rule, ''), 200) AS rule,
               count(*) AS alerts
        FROM alert a
        WHERE a.received_at >= now() - interval '30 days'
          AND (cid IS NULL OR a.client_id = cid)
          AND a.mitre_hint IS NOT NULL AND btrim(split_part(a.mitre_hint, '/', 1)) <> ''
        GROUP BY 1, 2 ORDER BY count(*) DESC, 1, 2 LIMIT 500
    ) t;

    SELECT manifest_at_max INTO v_deployed FROM rules_drift;

    RETURN jsonb_build_object('rules', v_rules, 'tactics', v_tactics, 'deployed_at', v_deployed);
END;
$$
"""


def upgrade() -> None:
    op.execute(FUNCTION)
    op.execute("GRANT soc_console_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_console_writer")
    op.execute(f"REVOKE ALL ON FUNCTION {SIGNATURE} FROM PUBLIC")
    op.execute(f"ALTER FUNCTION {SIGNATURE} OWNER TO soc_console_writer")
    op.execute(f"GRANT EXECUTE ON FUNCTION {SIGNATURE} TO soc_console")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_console_writer")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {SIGNATURE}")
