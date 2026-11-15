"""The posture snapshot may say "org errors unknown".

Revision ID: 0015
Revises: 0014

On the live organization the posture key reads sensors and rules but not the error list
(401), so the collector now stores the error count as unknown (JSON null -> NULL in
posture_run.org_error_count, which was always nullable) instead of failing every run or
writing a false zero. posture_record() is changed in exactly one place: the count must be
a number or null, and must still be present. The function is rewritten from its stored
definition (CREATE OR REPLACE keeps its owner, search_path and grants), and the migration
refuses to run if the line it changes is not there exactly once. Downgrade puts the old
line back.
"""

from alembic import op
from sqlalchemy import text

revision = "0015"
down_revision = "0014"

OLD = """IF jsonb_typeof(org -> 'count') IS DISTINCT FROM 'number'
               OR (org ->> 'count') !~ '^[0-9]{1,6}$'"""
NEW = """IF coalesce(jsonb_typeof(org -> 'count'), 'missing') NOT IN ('number', 'null')
               OR (jsonb_typeof(org -> 'count') = 'number'
                   AND (org ->> 'count') !~ '^[0-9]{1,6}$')"""


def _swap(old: str, new: str) -> None:
    conn = op.get_bind()
    definition = conn.execute(
        text("SELECT pg_get_functiondef('posture_record(jsonb)'::regprocedure)")
    ).scalar_one()
    if definition.count(old) != 1:
        raise RuntimeError("posture_record() is not the definition this migration expects")
    conn.execute(text("GRANT soc_posture_writer TO current_user"))
    conn.exec_driver_sql(definition.replace(old, new))


def upgrade() -> None:
    _swap(OLD, NEW)


def downgrade() -> None:
    _swap(NEW, OLD)
