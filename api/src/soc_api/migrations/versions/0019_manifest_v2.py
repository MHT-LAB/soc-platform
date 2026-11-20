"""Manifest v2: a whole older deploy put back by hand is "stale".

Revision ID: 0019
Revises: 0018

The rules deploy's manifest now lists each managed name with its stamp and carries the deploy
time, all under its check value. The collector already catches one rule put back to an older
deployed body (its stamp is valid but is not the one the manifest lists). What it cannot see
alone is the whole set put back together with that deploy's own manifest: everything would
verify. So the collector sends the manifest's deploy time, the database keeps the newest one
it has seen, and a good manifest older than that is stored as `stale` and counted as drift
until a newer deploy.

  rules_drift.manifest_at       the deploy time of the manifest the collector just read
  rules_drift.manifest_at_max   the newest deploy time ever seen while drift was checked
  rules_drift.manifest          gains `stale`
  posture_record()              accepts `drift.manifest_at` (optional) and derives `stale`
  rules_drift_health(), ops_overview()   count `stale` like `bad` and `absent`

Same method as 0018: the functions are rewritten from their stored definitions with exact-once
text swaps, and downgrade swaps back.
"""

from alembic import op
from sqlalchemy import text

revision = "0019"
down_revision = "0018"

REC_CHECK_OLD = "OR (p_doc -> 'drift' ->> 'missing_count') !~ '^[0-9]{1,6}$'"
REC_CHECK_NEW = """OR (p_doc -> 'drift' ->> 'missing_count') !~ '^[0-9]{1,6}$'
                   OR coalesce(jsonb_typeof(p_doc -> 'drift' -> 'manifest_at'), 'null')
                       NOT IN ('number', 'null')
                   OR (jsonb_typeof(p_doc -> 'drift' -> 'manifest_at') = 'number'
                       AND (p_doc -> 'drift' ->> 'manifest_at') !~ '^[0-9]{1,10}$')"""

REC_WRITE_OLD = """INSERT INTO rules_drift (singleton, manifest, missing_count, missing, updated_at)
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
                    missing = EXCLUDED.missing, updated_at = now();"""
REC_WRITE_NEW = """INSERT INTO rules_drift (singleton, manifest, missing_count, missing,
                                         manifest_at, manifest_at_max, updated_at)
                SELECT true, p_doc -> 'drift' ->> 'manifest',
                       (p_doc -> 'drift' ->> 'missing_count')::integer,
                       ARRAY(SELECT m #>> '{}'
                             FROM jsonb_array_elements(p_doc -> 'drift' -> 'missing') m),
                       (p_doc -> 'drift' ->> 'manifest_at')::bigint,
                       (p_doc -> 'drift' ->> 'manifest_at')::bigint,
                       now()
                -- Once a manifest has been seen, "none" (no manifest, no stamped rule) can
                -- only mean both were deleted: it is kept as "absent" until a manifest is back.
                -- A good manifest older than the newest one seen is "stale": a whole older
                -- deploy was put back by hand. It stays so until a newer deploy.
                ON CONFLICT (singleton) DO UPDATE SET
                    manifest = CASE WHEN EXCLUDED.manifest = 'none'
                                         AND rules_drift.manifest <> 'none'
                                    THEN 'absent'
                                    WHEN EXCLUDED.manifest = 'ok'
                                         AND EXCLUDED.manifest_at < rules_drift.manifest_at_max
                                    THEN 'stale'
                                    ELSE EXCLUDED.manifest END,
                    missing_count = EXCLUDED.missing_count,
                    missing = EXCLUDED.missing,
                    manifest_at = EXCLUDED.manifest_at,
                    manifest_at_max = GREATEST(rules_drift.manifest_at_max, EXCLUDED.manifest_at),
                    updated_at = now();"""

RECORD_SWAPS = [(REC_CHECK_OLD, REC_CHECK_NEW), (REC_WRITE_OLD, REC_WRITE_NEW)]

COUNT_OLD = "(manifest IN ('bad', 'absent'))"
COUNT_NEW = "(manifest IN ('bad', 'absent', 'stale'))"
COUNT_SWAPS = [(COUNT_OLD, COUNT_NEW)]

# The roles that own the rewritten functions, as fixed statements (no SQL built from text).
GRANTS = {
    "soc_posture_writer": text("GRANT soc_posture_writer TO current_user"),
    "soc_console_writer": text("GRANT soc_console_writer TO current_user"),
    "soc_worker_writer": text("GRANT soc_worker_writer TO current_user"),
}
DEFINITION = text("SELECT pg_get_functiondef(CAST(:signature AS regprocedure))")

FUNCTIONS = [
    ("posture_record(jsonb)", "soc_posture_writer", RECORD_SWAPS),
    ("rules_drift_health()", "soc_worker_writer", COUNT_SWAPS),
    ("ops_overview(integer, text)", "soc_console_writer", COUNT_SWAPS),
]


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
    op.execute("ALTER TABLE rules_drift ADD COLUMN manifest_at bigint")
    op.execute("ALTER TABLE rules_drift ADD COLUMN manifest_at_max bigint")
    op.execute(
        "ALTER TABLE rules_drift ADD CONSTRAINT rules_drift_manifest_at_range CHECK "
        "(manifest_at BETWEEN 1 AND 4102444800 AND manifest_at_max BETWEEN 1 AND 4102444800)"
    )
    op.execute("ALTER TABLE rules_drift DROP CONSTRAINT rules_drift_manifest_check")
    op.execute(
        "ALTER TABLE rules_drift ADD CONSTRAINT rules_drift_manifest_check "
        "CHECK (manifest IN ('ok', 'bad', 'absent', 'none', 'stale'))"
    )
    for signature, role, swaps in FUNCTIONS:
        _swap(signature, role, swaps, reverse=False)


def downgrade() -> None:
    for signature, role, swaps in reversed(FUNCTIONS):
        _swap(signature, role, swaps, reverse=True)
    op.execute("UPDATE rules_drift SET manifest = 'bad' WHERE manifest = 'stale'")
    op.execute("ALTER TABLE rules_drift DROP CONSTRAINT rules_drift_manifest_check")
    op.execute(
        "ALTER TABLE rules_drift ADD CONSTRAINT rules_drift_manifest_check "
        "CHECK (manifest IN ('ok', 'bad', 'absent', 'none'))"
    )
    op.execute("ALTER TABLE rules_drift DROP CONSTRAINT rules_drift_manifest_at_range")
    op.execute("ALTER TABLE rules_drift DROP COLUMN manifest_at_max")
    op.execute("ALTER TABLE rules_drift DROP COLUMN manifest_at")
