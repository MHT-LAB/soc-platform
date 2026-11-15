"""Two indexes the case pages and the pager's queue read through.

Revision ID: 0014
Revises: 0013

  alert (case_id, received_at)     "the alerts of this case": list_cases, get_case and
                                   claim_pages all ask for it, once per case row.
  case_event (case_id, at)         "the events of this case", oldest first: the queue and
                                   the case page read it for every case.

Neither table had an index for these beyond its key. Fine at today's volume; the queue
page would slow once alerts pass tens of thousands. Indexes only: no table, column,
function or grant changes, so the previous release runs against this schema unchanged.
Downgrade drops both.
"""

from alembic import op

revision = "0014"
down_revision = "0013"


def upgrade() -> None:
    op.execute("CREATE INDEX alert_case_received ON alert (case_id, received_at)")
    op.execute("CREATE INDEX case_event_case_at ON case_event (case_id, at)")


def downgrade() -> None:
    op.execute("DROP INDEX case_event_case_at")
    op.execute("DROP INDEX alert_case_received")
