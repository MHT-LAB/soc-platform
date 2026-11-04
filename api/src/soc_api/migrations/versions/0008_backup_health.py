"""Backup health for the pager: when the last good database dump was taken.

Revision ID: 0008
Revises: 0007

deploy/backup.sh tells the database when a dump has been written, verified and stored;
the pager worker asks how long ago that was. Same pattern as the catch-up health in 0007.

  backup_state        one row. started_at is when this migration ran, last_ok_at and
                      last_bytes are filled in by each good dump. No role can touch the table
                      directly except through the two functions below.
  backup_mark_ok(n)   records "a good dump of n bytes exists now". Not granted to any
                      service role: the backup script calls it as the database superuser
                      over the container's own socket, and only after its own checks.
  backup_health()     one row for the "SOC STALE" check and the weekly OK line:
                      age_s  seconds since the last good dump, or since this migration ran
                             when there has been none (so deploying this before the backup
                             timer exists does not page at once, and a timer that never
                             runs still goes stale);
                      bytes  size of the last good dump, NULL when there has been none.
                      No file names, paths or errors. Executable by soc_worker only.

Additive: the previous release's worker never calls either function. Downgrade drops all of
it.
"""

from alembic import op

revision = "0008"
down_revision = "0007"


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE backup_state (
            id boolean PRIMARY KEY DEFAULT true CHECK (id),
            started_at timestamptz NOT NULL DEFAULT now(),
            last_ok_at timestamptz,
            last_bytes bigint CHECK (last_bytes > 0)
        )
        """
    )
    op.execute("INSERT INTO backup_state (id) VALUES (true)")
    op.execute("ALTER TABLE backup_state ENABLE ROW LEVEL SECURITY")
    # The worker's writer reads three columns, through an RLS policy; nobody else has any right.
    op.execute(
        "GRANT SELECT (started_at, last_ok_at, last_bytes) ON backup_state TO soc_worker_writer"
    )
    op.execute(
        "CREATE POLICY worker_backup_read ON backup_state FOR SELECT "
        "TO soc_worker_writer USING (true)"
    )

    op.execute(
        """
        CREATE FUNCTION backup_mark_ok(p_bytes bigint) RETURNS void
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        BEGIN
            IF p_bytes IS NULL OR p_bytes < 1 THEN
                RAISE EXCEPTION 'a dump has at least one byte';
            END IF;
            UPDATE backup_state SET last_ok_at = now(), last_bytes = p_bytes WHERE id;
        END
        $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION backup_mark_ok(bigint) FROM PUBLIC")

    op.execute(
        """
        CREATE FUNCTION backup_health()
        RETURNS TABLE (age_s double precision, bytes bigint)
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT extract(epoch FROM now() - coalesce(last_ok_at, started_at))
                       ::double precision,
                   last_bytes
            FROM backup_state
        $$
        """
    )
    op.execute("GRANT soc_worker_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_worker_writer")
    op.execute("REVOKE ALL ON FUNCTION backup_health() FROM PUBLIC")
    op.execute("ALTER FUNCTION backup_health() OWNER TO soc_worker_writer")
    op.execute("GRANT EXECUTE ON FUNCTION backup_health() TO soc_worker")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_worker_writer")


def downgrade() -> None:
    op.execute("DROP FUNCTION backup_health()")
    op.execute("DROP FUNCTION backup_mark_ok(bigint)")
    op.execute("DROP POLICY worker_backup_read ON backup_state")
    op.execute("DROP TABLE backup_state")
