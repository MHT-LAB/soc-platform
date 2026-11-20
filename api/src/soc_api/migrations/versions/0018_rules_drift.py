"""Rule drift: the posture collector says whether each rule is still what the deploy wrote.

Revision ID: 0018
Revises: 0017

The rules deploy (E3) stamps every rule it writes with a keyed hash and writes a manifest
that lists the managed names. The posture collector, when it holds the stamp key, recomputes
each stamp from the body it just read and says, per general rule, `ok`, `changed` (edited,
re-tagged, or the stamp removed) or `unmanaged` (a managed name made by hand), and says
whether the manifest is intact and which listed rules are no longer there. Nothing here
holds a rule body: only the verdict, and the names of rules that are missing or wrong.

  rule_inventory.drift     nullable: NULL is "not a managed rule, or not checked"
  rules_drift              one row, present only while drift is being checked: the manifest
                           state (`ok`, `bad`, `absent`, `none`), how many listed rules are
                           missing, and up to 200 of their names
  rules_drift_health()     for the pager worker: (checked, how many things are wrong)
  posture_record()         accepts the new fields (all optional, so a collector without the
                           stamp key still works) and writes them in the same transaction
  ops_overview()           health.rules_drift (the same count the pager uses) and a
                           `rules_drift` block with the names, for the Rules tab and the
                           System page

posture_record() and ops_overview() are rewritten from their stored definitions (CREATE OR
REPLACE keeps owner, search_path and grants); each change is an exact-once text swap, and the
migration refuses to run if an anchor is not there exactly once. Downgrade swaps back, which
gives the previous definitions exactly.
"""

from alembic import op
from sqlalchemy import text

revision = "0018"
down_revision = "0017"

# ---- posture_record(): validate and write the new fields ----

REC_RULE_CHECK_OLD = "OR jsonb_typeof(x -> 'enabled') IS DISTINCT FROM 'boolean'"
REC_RULE_CHECK_NEW = """OR jsonb_typeof(x -> 'enabled') IS DISTINCT FROM 'boolean'
                   OR jsonb_typeof(x -> 'drift') NOT IN ('string', 'null')
                   OR (jsonb_typeof(x -> 'drift') = 'string'
                       AND (x ->> 'drift') NOT IN ('ok', 'changed', 'unmanaged'))"""

REC_INSERT_OLD = "INSERT INTO rule_inventory (namespace, name, enabled, updated_at)"
REC_INSERT_NEW = "INSERT INTO rule_inventory (namespace, name, enabled, drift, updated_at)"
REC_SELECT_OLD = "SELECT x ->> 'namespace', x ->> 'name', (x ->> 'enabled')::boolean, now()"
REC_SELECT_NEW = (
    "SELECT x ->> 'namespace', x ->> 'name', (x ->> 'enabled')::boolean, x ->> 'drift', now()"
)
REC_SET_OLD = "SET enabled = EXCLUDED.enabled, updated_at = now();"
REC_SET_NEW = "SET enabled = EXCLUDED.enabled, drift = EXCLUDED.drift, updated_at = now();"

REC_STATE_OLD = "-- the time series point, counted from the same list"
REC_STATE_NEW = """-- drift: manifest state and the listed rules that are gone. Only while the
            -- collector holds the stamp key; no row means "not checked".
            IF jsonb_typeof(p_doc -> 'drift') NOT IN ('object', 'null') THEN
                RAISE EXCEPTION 'bad drift in posture document';
            END IF;
            IF jsonb_typeof(p_doc -> 'drift') = 'object' THEN
                IF coalesce(p_doc -> 'drift' ->> 'manifest', '')
                       NOT IN ('ok', 'bad', 'absent', 'none')
                   OR jsonb_typeof(p_doc -> 'drift' -> 'missing') IS DISTINCT FROM 'array'
                   OR jsonb_array_length(p_doc -> 'drift' -> 'missing') > 200
                   OR jsonb_typeof(p_doc -> 'drift' -> 'missing_count') IS DISTINCT FROM 'number'
                   OR (p_doc -> 'drift' ->> 'missing_count') !~ '^[0-9]{1,6}$'
                   OR EXISTS (
                        SELECT 1 FROM jsonb_array_elements(p_doc -> 'drift' -> 'missing') m
                        WHERE jsonb_typeof(m) IS DISTINCT FROM 'string'
                           OR char_length(m #>> '{}') NOT BETWEEN 1 AND 255) THEN
                    RAISE EXCEPTION 'bad drift in posture document';
                END IF;
                INSERT INTO rules_drift (singleton, manifest, missing_count, missing, updated_at)
                SELECT true, p_doc -> 'drift' ->> 'manifest',
                       (p_doc -> 'drift' ->> 'missing_count')::integer,
                       ARRAY(SELECT m #>> '{}'
                             FROM jsonb_array_elements(p_doc -> 'drift' -> 'missing') m),
                       now()
                -- Once a manifest has been seen, "none" (no manifest, no stamped rule) can
                -- only mean both were deleted: it is kept as "absent" until a manifest is back.
                ON CONFLICT (singleton) DO UPDATE SET
                    manifest = CASE WHEN EXCLUDED.manifest = 'none'
                                         AND rules_drift.manifest <> 'none'
                                    THEN 'absent' ELSE EXCLUDED.manifest END,
                    missing_count = EXCLUDED.missing_count,
                    missing = EXCLUDED.missing, updated_at = now();
            ELSE
                DELETE FROM rules_drift;
            END IF;

            -- the time series point, counted from the same list"""

RECORD_SWAPS = [
    (REC_RULE_CHECK_OLD, REC_RULE_CHECK_NEW),
    (REC_INSERT_OLD, REC_INSERT_NEW),
    (REC_SELECT_OLD, REC_SELECT_NEW),
    (REC_SET_OLD, REC_SET_NEW),
    (REC_STATE_OLD, REC_STATE_NEW),
]

# ---- ops_overview(): what the System page and the Rules tab read ----

WRONG_COUNT = """(SELECT (SELECT count(*) FROM rule_inventory
                        WHERE drift IN ('changed', 'unmanaged'))
                   + coalesce((SELECT missing_count FROM rules_drift), 0)
                   + coalesce((SELECT (manifest IN ('bad', 'absent'))::integer
                               FROM rules_drift), 0))"""

OV_HEALTH_OLD = "'posture_quiet_s', h.posture_quiet_s,"
OV_HEALTH_NEW = f"""'posture_quiet_s', h.posture_quiet_s,
        'rules_drift', CASE WHEN EXISTS (SELECT 1 FROM rules_drift)
                            THEN {WRONG_COUNT} END,"""

OV_BLOCK_OLD = "'rule_inventory', v_inventory"
OV_BLOCK_NEW = """'rule_inventory', v_inventory,
        'rules_drift', (SELECT jsonb_build_object(
            'manifest', dr.manifest,
            'missing_count', dr.missing_count,
            'missing', to_jsonb(dr.missing),
            'ok', (SELECT count(*) FROM rule_inventory WHERE drift = 'ok'),
            'rules', (SELECT coalesce(jsonb_agg(jsonb_build_object(
                                'name', w.name, 'state', w.drift) ORDER BY w.name), '[]')
                      FROM (SELECT name, drift FROM rule_inventory
                            WHERE drift IN ('changed', 'unmanaged')
                            ORDER BY name LIMIT 100) w))
          FROM rules_drift dr)"""

OVERVIEW_SWAPS = [(OV_HEALTH_OLD, OV_HEALTH_NEW), (OV_BLOCK_OLD, OV_BLOCK_NEW)]


# The two roles whose functions are rewritten, as fixed statements (no SQL is built from text).
GRANTS = {
    "soc_posture_writer": text("GRANT soc_posture_writer TO current_user"),
    "soc_console_writer": text("GRANT soc_console_writer TO current_user"),
}
DEFINITION = text("SELECT pg_get_functiondef(CAST(:signature AS regprocedure))")


def _swap(signature: str, role: str, swaps: list[tuple[str, str]], *, reverse: bool) -> None:
    conn = op.get_bind()
    definition = conn.execute(DEFINITION, {"signature": signature}).scalar_one()
    for old, new in swaps:
        a, b = (new, old) if reverse else (old, new)
        if definition.count(a) != 1:
            raise RuntimeError(f"{signature} is not the definition this migration expects")
        definition = definition.replace(a, b)
    conn.execute(GRANTS[role])
    conn.exec_driver_sql(definition)


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE rule_inventory
            ADD COLUMN drift text CHECK (drift IN ('ok', 'changed', 'unmanaged'))
        """
    )
    op.execute(
        """
        CREATE TABLE rules_drift (
            singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
            manifest text NOT NULL CHECK (manifest IN ('ok', 'bad', 'absent', 'none')),
            missing_count integer NOT NULL CHECK (missing_count BETWEEN 0 AND 999999),
            missing text[] NOT NULL CHECK (cardinality(missing) <= 200),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("ALTER TABLE rules_drift ENABLE ROW LEVEL SECURITY")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON rules_drift TO soc_posture_writer")
    for command in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        clause = {
            "INSERT": "WITH CHECK (true)",
            "UPDATE": "USING (true) WITH CHECK (true)",
        }.get(command, "USING (true)")
        op.execute(
            f"CREATE POLICY posture_{command.lower()} ON rules_drift FOR {command} "
            f"TO soc_posture_writer {clause}"
        )
    # The console's writer reads the verdicts and the names; the pager worker's writer reads
    # the verdict column and the one row, to count.
    for role, policy in (
        ("soc_console_writer", "console_overview_read"),
        ("soc_worker_writer", "worker_drift_read"),
    ):
        op.execute(f"GRANT SELECT ON rules_drift TO {role}")
        op.execute(f"CREATE POLICY {policy} ON rules_drift FOR SELECT TO {role} USING (true)")
    op.execute("GRANT SELECT (drift) ON rule_inventory TO soc_console_writer, soc_worker_writer")
    op.execute(
        "CREATE POLICY worker_drift_read ON rule_inventory FOR SELECT "
        "TO soc_worker_writer USING (true)"
    )

    op.execute(
        """
        CREATE FUNCTION rules_drift_health()
        RETURNS TABLE (checked boolean, wrong integer)
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT EXISTS (SELECT 1 FROM rules_drift),
                   ("""
        + WRONG_COUNT
        + """)::integer
        $$
        """
    )
    op.execute("GRANT soc_worker_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_worker_writer")
    op.execute("REVOKE ALL ON FUNCTION rules_drift_health() FROM PUBLIC")
    op.execute("ALTER FUNCTION rules_drift_health() OWNER TO soc_worker_writer")
    op.execute("GRANT EXECUTE ON FUNCTION rules_drift_health() TO soc_worker")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_worker_writer")

    _swap("posture_record(jsonb)", "soc_posture_writer", RECORD_SWAPS, reverse=False)
    _swap("ops_overview(integer, text)", "soc_console_writer", OVERVIEW_SWAPS, reverse=False)


def downgrade() -> None:
    _swap("ops_overview(integer, text)", "soc_console_writer", OVERVIEW_SWAPS, reverse=True)
    _swap("posture_record(jsonb)", "soc_posture_writer", RECORD_SWAPS, reverse=True)
    op.execute("DROP FUNCTION rules_drift_health()")
    op.execute("DROP POLICY worker_drift_read ON rule_inventory")
    op.execute("REVOKE SELECT (drift) ON rule_inventory FROM soc_console_writer, soc_worker_writer")
    op.execute("DROP TABLE rules_drift")
    op.execute("ALTER TABLE rule_inventory DROP COLUMN drift")
