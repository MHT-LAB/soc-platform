"""Worker: how many pages are due, without claiming any.

Revision ID: 0003
Revises: 0002

The page-storm cap holds pages back when too many would go out at once, and says how
many are waiting. Counting them must not take a lease, so this is a plain read in the
same shape as the other worker functions: SECURITY DEFINER, owned by soc_worker_writer,
executable by soc_worker only.
"""

from alembic import op

revision = "0003"
down_revision = "0002"

FUNCTION = "due_page_count()"


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION due_page_count() RETURNS bigint
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT count(*) FROM notification
            WHERE status = 'pending' AND next_attempt_at <= now()
        $$
        """
    )
    op.execute("GRANT soc_worker_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_worker_writer")
    op.execute(f"REVOKE ALL ON FUNCTION {FUNCTION} FROM PUBLIC")
    op.execute(f"ALTER FUNCTION {FUNCTION} OWNER TO soc_worker_writer")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FUNCTION} TO soc_worker")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_worker_writer")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {FUNCTION}")
