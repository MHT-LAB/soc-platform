"""pipeline_metrics() also counts the reopen and raised pushes.

Revision ID: 0021
Revises: 0020

Migration 0017 gave a case two more kinds of push: `reopen` (a closed case that fired again)
and `raised` (an alert of higher severity than its case). pipeline_metrics() still counted
only page, repage1 and repage2, so those pushes went out and appeared nowhere on /metrics.

One exact-once text swap in the function's stored definition (the kind list), the same way
0018 and 0019 patch functions: CREATE OR REPLACE keeps the owner and the grants, the migration
refuses to run if the anchor is not there exactly once, and the downgrade swaps back, which
gives the 0009 definition exactly. The kinds are a fixed list in the SQL, and the exporter's
own fixed list (metrics.KINDS) decides which labels may reach the page.
"""

from alembic import op
from sqlalchemy import text

revision = "0021"
down_revision = "0020"

KINDS_OLD = "kinds(kind) AS (VALUES ('page'), ('repage1'), ('repage2'))"
KINDS_NEW = "kinds(kind) AS (VALUES ('page'), ('repage1'), ('repage2'), ('reopen'), ('raised'))"
SWAPS = [(KINDS_OLD, KINDS_NEW)]

GRANT = text("GRANT soc_console_writer TO current_user")
DEFINITION = text("SELECT pg_get_functiondef(CAST(:signature AS regprocedure))")
SIGNATURE = "pipeline_metrics()"


def _swap(*, reverse: bool) -> None:
    conn = op.get_bind()
    definition = conn.execute(DEFINITION, {"signature": SIGNATURE}).scalar_one()
    for old, new in SWAPS:
        a, b = (new, old) if reverse else (old, new)
        if definition.count(a) != 1:
            raise RuntimeError(f"{SIGNATURE} is not the definition this migration expects")
        definition = definition.replace(a, b)
    conn.execute(GRANT)
    conn.exec_driver_sql(definition)


def upgrade() -> None:
    _swap(reverse=False)


def downgrade() -> None:
    _swap(reverse=True)
