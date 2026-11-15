"""Pager bounds: a flood cannot hide a real page, an acknowledged case cannot swallow alerts
for ever, and cases group on the sensor, not on a host name.

Revision ID: 0017
Revises: 0016

Three fixes from the outside design review (notes: R2, R3 with decision D1, R4).

R3 / D1, bound the cases the caser keeps filling (assign_cases):
  * an acknowledged case that gains an alert REOPEN_AFTER or more after its acknowledgement
    (or after its last push of this kind) is pushed once more, kind `reopen`, then that
    clock starts again from the push;
  * a case whose first alert is MAX_CASE_AGE or more older than the new alert stops
    collecting: the alert opens a new case, which pages as any new case does;
  * an alert of higher severity than its case raises the case and pushes once (kind
    `raised`), whatever the case's state (open or acknowledged).
  A closed case is never reused (as before). The two thresholds are the constants below and
  nowhere else. New case events: `severity_raised` and `repushed` (the clock marker).

R2, fairness in the claim order (claim_pages):
  when more pages are due than the cap lets out, a page for a (client, rule, host) with no
  push inside the cap window goes before more pages for a group that was just pushed or that
  has an earlier page in this claim; within that, priority, then age, as before. The window
  is a new argument with a default, so the previous worker still calls it unchanged.
  held_summary() gives the held notice something useful to say: how many are waiting, from
  how many hosts, and the highest case severity among them. Counts and a fixed word only:
  no host name, rule or client text.

R4, grouping key:
  the key is the sensor id (routing.sid, which the endpoint cannot rename), and only when
  there is none, the host name. Two alerts whose key is empty, or that carry no rule, are
  never grouped. alert_case_group is rebuilt on the new key. Nothing existing is rewritten:
  open cases stay as they are, and an old alert with a host name but no sensor id still
  matches a new alert of the same kind (same key).

Table rights the new rules need, no wider than that, for the worker's writer role (which
only functions of the worker's login reach): UPDATE (severity) on soc_case, and SELECT on
four columns of case_event (never the actor or the text). Function owners and the roles that
may call them are unchanged. notification.kind accepts `reopen` and `raised`, which may
repeat on a case (so the unique index on case and kind now covers the other three only).

Downgrade restores both previous function definitions and the previous index. Rows of the
two new kinds are removed first (they cannot exist under the old constraint); the case
history events the new rules wrote stay, as history.
"""

from alembic import op
from sqlalchemy import text

revision = "0017"
down_revision = "0016"

# The thresholds. Everything else in this file reads these two.
REOPEN_AFTER = "60 minutes"
MAX_CASE_AGE = "24 hours"

UNASSIGNED = "00000000-0000-4000-8000-000000000001"

# The grouping key of an alert: sensor id, else host name; NULL when neither is there.
# The prefixes keep a host name from ever equalling a sensor id.
KEY = (
    "coalesce('sid:' || nullif({p}raw #>> '{{routing,sid}}', ''), "
    "'host:' || nullif({p}raw #>> '{{routing,hostname}}', ''))"
)


def key(prefix: str = "") -> str:
    return KEY.format(p=prefix)


OLD_INDEX = (
    "CREATE INDEX alert_case_group ON alert "
    "(client_id, rule, ((raw -> 'routing') ->> 'hostname'), received_at DESC) "
    "WHERE case_id IS NOT NULL"
)
NEW_INDEX = (
    f"CREATE INDEX alert_case_group ON alert (client_id, rule, ({key()}), received_at DESC) "
    "WHERE case_id IS NOT NULL"
)

KINDS_OLD = "'page', 'repage1', 'repage2'"
KINDS_NEW = "'page', 'repage1', 'repage2', 'reopen', 'raised'"

# assign_cases as 0004 left it (own clock), for the downgrade.
OLD_ASSIGN = r"""
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
                  AND c.status IN ('open', 'acknowledged')
                  AND x.received_at >= a.received_at - interval '60 minutes'
                ORDER BY x.received_at DESC LIMIT 1;
                IF target IS NOT NULL THEN
                    UPDATE alert SET case_id = target WHERE id = a.id;
                    INSERT INTO case_event (at, client_id, case_id, actor, kind, body)
                    VALUES (clock_timestamp(), a.client_id, target, 'system', 'alert_attached', a.id::text);
                ELSE
                    sev := a.severity;
                    IF a.client_id = '00000000-0000-4000-8000-000000000001'::uuid
                       AND sev IN ('info', 'low') THEN
                        sev := 'medium';
                    END IF;
                    INSERT INTO soc_case (client_id, severity) VALUES (a.client_id, sev)
                    RETURNING id INTO target;
                    UPDATE alert SET case_id = target WHERE id = a.id;
                    INSERT INTO case_event (at, client_id, case_id, actor, kind, body)
                    VALUES (clock_timestamp(), a.client_id, target, 'system', 'opened', a.id::text);
                    n_cases := n_cases + 1;
                    raw_prio := p_policy -> a.cat;
                    IF raw_prio IS NOT NULL AND jsonb_typeof(raw_prio) = 'number'
                       AND (raw_prio #>> '{}') ~ '^[0-5]$' THEN
                        prio := (raw_prio #>> '{}')::integer;
                    ELSE
                        prio := CASE sev WHEN 'info' THEN 0 WHEN 'low' THEN 3
                                         WHEN 'medium' THEN 4 ELSE 5 END;
                    END IF;
                    IF a.client_id = '00000000-0000-4000-8000-000000000001'::uuid THEN
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
"""  # noqa: E501

# claim_pages as 0007 left it, for the downgrade.
OLD_CLAIM = r"""
CREATE FUNCTION claim_pages(p_batch integer)
        RETURNS TABLE (
            id uuid, priority smallint, attempts integer, client_slug text, rule text,
            host text, link text, case_short text, detected_at timestamptz,
            case_id uuid, kind text,
            late_s double precision
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
                   left(t.case_id::text, 8), fa.detected_at, t.case_id, t.kind,
                   extract(epoch FROM fa.received_at - fa.detected_at)::double precision
            FROM taken t
            JOIN client cl ON cl.id = t.client_id
            JOIN LATERAL (
                SELECT x.rule, x.raw, x.detected_at, x.received_at FROM alert x
                WHERE x.client_id = t.client_id AND x.case_id = t.case_id
                ORDER BY x.received_at, x.id LIMIT 1
            ) fa ON true
            ORDER BY t.priority DESC, t.id;
        END
        $$
"""

NEW_ASSIGN = r"""
CREATE OR REPLACE FUNCTION assign_cases(p_batch integer, p_policy jsonb DEFAULT '{}')
        RETURNS TABLE (alerts_assigned integer, cases_opened integer, pages_queued integer)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            a record;
            target uuid;
            tstatus text;
            tsev text;
            topened timestamptz;
            clock_ref timestamptz;
            asev text;
            sev text;
            prio integer;
            raw_prio jsonb;
            push_kind text;
            do_raise boolean;
            do_reopen boolean;
            sev_order text[] := ARRAY['info', 'low', 'medium', 'high', 'critical'];
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
                       __KEY_A__ AS gkey,
                       raw ->> 'cat' AS cat
                FROM alert WHERE case_id IS NULL
                ORDER BY received_at, id LIMIT p_batch
            LOOP
                asev := a.severity;
                IF a.client_id = '__UNASSIGNED__'::uuid AND asev IN ('info', 'low') THEN
                    asev := 'medium';
                END IF;
                target := NULL;
                -- an alert with no rule, or no sensor id and no host name, joins nothing
                IF a.gkey IS NOT NULL AND coalesce(a.rule, '') <> '' THEN
                    SELECT x.case_id, c.status, c.severity, c.opened_at
                    INTO target, tstatus, tsev, topened
                    FROM alert x JOIN soc_case c ON c.client_id = x.client_id AND c.id = x.case_id
                    WHERE x.client_id = a.client_id
                      AND x.rule = a.rule
                      AND __KEY_X__ = a.gkey
                      AND c.status IN ('open', 'acknowledged')
                      AND a.received_at < c.opened_at + interval '__MAX_AGE__'
                      AND x.received_at >= a.received_at - interval '60 minutes'
                    ORDER BY x.received_at DESC LIMIT 1;
                END IF;
                IF target IS NOT NULL THEN
                    UPDATE alert SET case_id = target WHERE id = a.id;
                    INSERT INTO case_event (at, client_id, case_id, actor, kind, body)
                    VALUES (clock_timestamp(), a.client_id, target, 'system', 'alert_attached',
                            a.id::text);
                    do_raise := array_position(sev_order, asev) > array_position(sev_order, tsev);
                    do_reopen := false;
                    IF tstatus = 'acknowledged' THEN
                        SELECT max(e.at) INTO clock_ref FROM case_event e
                        WHERE e.client_id = a.client_id AND e.case_id = target
                          AND e.kind IN ('acked', 'repushed');
                        do_reopen := a.received_at - coalesce(clock_ref, topened)
                                     >= interval '__REOPEN_AFTER__';
                    END IF;
                    IF do_raise THEN
                        UPDATE soc_case SET severity = asev
                        WHERE client_id = a.client_id AND id = target;
                        INSERT INTO case_event (at, client_id, case_id, actor, kind, body)
                        VALUES (clock_timestamp(), a.client_id, target, 'system',
                                'severity_raised', tsev || ' to ' || asev);
                        tsev := asev;
                    END IF;
                    IF do_raise OR do_reopen THEN
                        raw_prio := p_policy -> a.cat;
                        IF raw_prio IS NOT NULL AND jsonb_typeof(raw_prio) = 'number'
                           AND (raw_prio #>> '{}') ~ '^[0-5]$' THEN
                            prio := (raw_prio #>> '{}')::integer;
                        ELSE
                            prio := CASE tsev WHEN 'info' THEN 0 WHEN 'low' THEN 3
                                              WHEN 'medium' THEN 4 ELSE 5 END;
                        END IF;
                        IF a.client_id = '__UNASSIGNED__'::uuid THEN
                            prio := greatest(prio, 4);
                        END IF;
                        IF prio > 0 THEN
                            push_kind := CASE WHEN do_raise THEN 'raised' ELSE 'reopen' END;
                            INSERT INTO notification (client_id, case_id, channel, priority, kind)
                            VALUES (a.client_id, target, 'ntfy', prio, push_kind);
                            INSERT INTO case_event (at, client_id, case_id, actor, kind, body)
                            VALUES (a.received_at, a.client_id, target, 'system', 'repushed',
                                    CASE WHEN do_raise THEN 'higher severity'
                                         ELSE 'new alerts after acknowledgement' END);
                            n_pages := n_pages + 1;
                        END IF;
                    END IF;
                ELSE
                    sev := asev;
                    INSERT INTO soc_case (client_id, severity) VALUES (a.client_id, sev)
                    RETURNING id INTO target;
                    UPDATE alert SET case_id = target WHERE id = a.id;
                    INSERT INTO case_event (at, client_id, case_id, actor, kind, body)
                    VALUES (clock_timestamp(), a.client_id, target, 'system', 'opened',
                            a.id::text);
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

NEW_CLAIM = r"""
CREATE FUNCTION claim_pages(p_batch integer, p_window interval DEFAULT interval '10 minutes')
        RETURNS TABLE (
            id uuid, priority smallint, attempts integer, client_slug text, rule text,
            host text, link text, case_short text, detected_at timestamptz,
            case_id uuid, kind text, late_s double precision
        )
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        #variable_conflict use_column
        BEGIN
            IF p_batch IS NULL OR p_batch < 1 OR p_batch > 100 THEN
                RAISE EXCEPTION 'batch must be between 1 and 100';
            END IF;
            IF p_window IS NULL OR p_window < interval '1 second'
               OR p_window > interval '7 days' THEN
                RAISE EXCEPTION 'window must be between 1 second and 7 days';
            END IF;
            RETURN QUERY
            WITH pend AS (
                -- everything that could go out now, with the (client, rule, host) it is about
                SELECT n.id, n.priority, n.created_at, n.client_id,
                       g.rule AS g_rule, __KEY_G__ AS g_key
                FROM notification n
                LEFT JOIN LATERAL (
                    SELECT x.rule, x.raw FROM alert x
                    WHERE x.client_id = n.client_id AND x.case_id = n.case_id
                    ORDER BY x.received_at, x.id LIMIT 1
                ) g ON true
                WHERE n.status = 'pending' AND n.next_attempt_at <= now()
                  AND (n.kind IN ('page', 'reopen', 'raised') OR EXISTS (
                      SELECT 1 FROM soc_case c
                      WHERE c.client_id = n.client_id AND c.id = n.case_id
                        AND c.status = 'open'))
            ), ranked AS (
                SELECT p.id, p.priority, p.created_at, p.client_id, p.g_key,
                       row_number() OVER (
                           PARTITION BY p.client_id, coalesce(p.g_rule, ''), coalesce(p.g_key, '')
                           ORDER BY p.priority DESC, p.created_at, p.id) AS rn,
                       EXISTS (
                           SELECT 1 FROM notification s
                           JOIN LATERAL (
                               SELECT y.rule, y.raw FROM alert y
                               WHERE y.client_id = s.client_id AND y.case_id = s.case_id
                               ORDER BY y.received_at, y.id LIMIT 1
                           ) sg ON true
                           WHERE s.client_id = p.client_id AND s.status = 'sent'
                             AND s.sent_at >= now() - p_window
                             AND coalesce(sg.rule, '') = coalesce(p.g_rule, '')
                             AND coalesce(__KEY_SG__, '') = coalesce(p.g_key, '')
                       ) AS pushed
                FROM pend p
            ), tiered AS (
                -- tier 0: the first page of a group nobody was pushed about in this window.
                -- Then round-robin over hosts, so one host with many rules cannot fill the
                -- batch; inside a round, priority, then age.
                SELECT r.id, r.priority, r.created_at, (r.pushed OR r.rn > 1) AS repeat,
                       row_number() OVER (
                           PARTITION BY r.client_id, coalesce(r.g_key, '')
                           ORDER BY (r.pushed OR r.rn > 1), r.priority DESC, r.created_at, r.id
                       ) AS host_rn
                FROM ranked r
            ), due AS (
                SELECT n.id FROM tiered t
                JOIN notification n ON n.id = t.id
                WHERE n.status = 'pending' AND n.next_attempt_at <= now()
                ORDER BY t.repeat, t.host_rn, t.priority DESC, t.created_at, t.id
                LIMIT p_batch FOR UPDATE OF n SKIP LOCKED
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
                   left(t.case_id::text, 8), fa.detected_at, t.case_id, t.kind,
                   extract(epoch FROM fa.received_at - fa.detected_at)::double precision
            FROM taken t
            JOIN client cl ON cl.id = t.client_id
            JOIN LATERAL (
                SELECT x.rule, x.raw, x.detected_at, x.received_at FROM alert x
                WHERE x.client_id = t.client_id AND x.case_id = t.case_id
                ORDER BY x.received_at, x.id LIMIT 1
            ) fa ON true
            ORDER BY t.priority DESC, t.id;
        END
        $$
"""

HELD = r"""
CREATE FUNCTION held_summary()
        RETURNS TABLE (waiting bigint, hosts bigint, severity text)
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT count(*), count(DISTINCT (n.client_id, coalesce(__KEY_G__, ''))),
                   (ARRAY['info', 'low', 'medium', 'high', 'critical'])[
                       max(array_position(ARRAY['info', 'low', 'medium', 'high', 'critical'],
                                          c.severity))]
            FROM notification n
            JOIN soc_case c ON c.client_id = n.client_id AND c.id = n.case_id
            LEFT JOIN LATERAL (
                SELECT x.raw FROM alert x
                WHERE x.client_id = n.client_id AND x.case_id = n.case_id
                ORDER BY x.received_at, x.id LIMIT 1
            ) g ON true
            WHERE n.status = 'pending' AND n.next_attempt_at <= now()
              AND (n.kind IN ('page', 'reopen', 'raised') OR c.status = 'open')
        $$
"""


def assign_cases(*, new: bool) -> str:
    if not new:
        return OLD_ASSIGN
    return (
        NEW_ASSIGN.replace("__UNASSIGNED__", UNASSIGNED)
        .replace("__KEY_A__", key())
        .replace("__KEY_X__", key("x."))
        .replace("__MAX_AGE__", MAX_CASE_AGE)
        .replace("__REOPEN_AFTER__", REOPEN_AFTER)
    )


def claim_pages(*, new: bool) -> str:
    if not new:
        return OLD_CLAIM
    return NEW_CLAIM.replace("__KEY_G__", key("g.")).replace("__KEY_SG__", key("sg."))


def held_summary() -> str:
    return HELD.replace("__KEY_G__", key("g."))


def regrant_claim(signature: str) -> None:
    op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
    op.execute("GRANT soc_worker_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_worker_writer")
    op.execute(f"ALTER FUNCTION {signature} OWNER TO soc_worker_writer")
    op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO soc_worker")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_worker_writer")


def _queue_repages(old: str, new: str) -> None:
    """queue_repages(), rewritten from its stored definition in one place: the conflict
    target, which now names the partial unique index. CREATE OR REPLACE keeps owner, search
    path and grants."""
    conn = op.get_bind()
    definition = conn.execute(
        text("SELECT pg_get_functiondef('queue_repages(interval, interval)'::regprocedure)")
    ).scalar_one()
    if definition.count(old) != 2:
        raise RuntimeError("queue_repages() is not the definition this migration expects")
    conn.execute(text("GRANT soc_worker_writer TO current_user"))
    conn.exec_driver_sql(definition.replace(old, new))


CONFLICT_OLD = "ON CONFLICT (case_id, kind) DO NOTHING"
CONFLICT_NEW = f"ON CONFLICT (case_id, kind) WHERE kind IN ({KINDS_OLD}) DO NOTHING"


def upgrade() -> None:
    # ---- notification kinds ----
    op.execute("ALTER TABLE notification DROP CONSTRAINT notification_kind_check")
    op.execute(
        f"ALTER TABLE notification ADD CONSTRAINT notification_kind_check "
        f"CHECK (kind IN ({KINDS_NEW}))"
    )
    op.execute("DROP INDEX notification_case_kind")
    op.execute(
        "CREATE UNIQUE INDEX notification_case_kind ON notification (case_id, kind) "
        f"WHERE kind IN ({KINDS_OLD})"
    )
    _queue_repages(CONFLICT_OLD, CONFLICT_NEW)

    # ---- what the caser now needs ----
    op.execute("GRANT UPDATE (severity) ON soc_case TO soc_worker_writer")
    op.execute(
        "CREATE POLICY worker_update ON soc_case FOR UPDATE TO soc_worker_writer "
        "USING (true) WITH CHECK (true)"
    )
    op.execute("GRANT SELECT (client_id, case_id, at, kind) ON case_event TO soc_worker_writer")
    op.execute(
        "CREATE POLICY worker_select ON case_event FOR SELECT TO soc_worker_writer USING (true)"
    )

    # ---- grouping on the sensor ----
    op.execute("DROP INDEX alert_case_group")
    op.execute(NEW_INDEX)

    # ---- the functions ----
    op.execute(assign_cases(new=True))
    op.execute("DROP FUNCTION claim_pages(integer)")
    op.execute(claim_pages(new=True))
    regrant_claim("claim_pages(integer, interval)")
    op.execute(held_summary())
    regrant_claim("held_summary()")


def downgrade() -> None:
    op.execute("DROP FUNCTION held_summary()")
    op.execute("DROP FUNCTION claim_pages(integer, interval)")
    op.execute(claim_pages(new=False))
    regrant_claim("claim_pages(integer)")
    op.execute(assign_cases(new=False))

    op.execute("DROP INDEX alert_case_group")
    op.execute(OLD_INDEX)

    op.execute("DROP POLICY worker_select ON case_event")
    op.execute("REVOKE SELECT (client_id, case_id, at, kind) ON case_event FROM soc_worker_writer")
    op.execute("DROP POLICY worker_update ON soc_case")
    op.execute("REVOKE UPDATE (severity) ON soc_case FROM soc_worker_writer")

    _queue_repages(CONFLICT_NEW, CONFLICT_OLD)
    op.execute("DELETE FROM notification WHERE kind IN ('reopen', 'raised')")
    op.execute("DROP INDEX notification_case_kind")
    op.execute("CREATE UNIQUE INDEX notification_case_kind ON notification (case_id, kind)")
    op.execute("ALTER TABLE notification DROP CONSTRAINT notification_kind_check")
    op.execute(
        f"ALTER TABLE notification ADD CONSTRAINT notification_kind_check "
        f"CHECK (kind IN ({KINDS_OLD}))"
    )
