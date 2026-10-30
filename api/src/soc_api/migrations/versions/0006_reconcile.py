"""Reconcile: the database side of the catch-up worker.

Revision ID: 0006
Revises: 0005

The webhook from the detection source gives up after a few fast retries, so an outage
loses alerts. A reconcile worker (a later PR) pulls detections for a time window from
the source's API and inserts what is missing. It gets the same shape of access as the
other services: a login role (soc_reconcile) with no table privileges, whose only way in
is EXECUTE on SECURITY DEFINER functions.

  ingest_alert              the same function the webhook uses, so a detection is
                            normalized, attributed and de-duplicated the same way
                            whichever path delivers it first (unique per source and id)
  reconcile_cursor_get      where the last successful window ended, per source
  reconcile_cursor_advance  moves that point forward after a good run; never backwards,
                            never into the future
  reconcile_cursor_fail     records a short failure code without moving the cursor

The cursor functions run as soc_reconcile_writer (NOLOGIN, owns no tables), which can
read three columns of source (to find a source by slug) and touch reconcile_cursor, and
nothing else. soc_reconcile gets its login and password in a later PR.
"""

from alembic import op

revision = "0006"
down_revision = "0005"

FUNCTIONS = [
    "reconcile_cursor_get(text)",
    "reconcile_cursor_advance(text, timestamptz)",
    "reconcile_cursor_fail(text, text)",
]


def upgrade() -> None:
    # Same rule as 0001: a pre-existing role with extra privileges stops the migration.
    op.execute(
        """
        DO $$
        DECLARE
            r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY['soc_reconcile', 'soc_reconcile_writer'] LOOP
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS '
                                   'NOCREATEDB NOCREATEROLE', r);
                ELSIF EXISTS (
                    SELECT FROM pg_roles WHERE rolname = r
                    AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole
                         OR (r = 'soc_reconcile_writer' AND rolcanlogin))
                ) THEN
                    RAISE EXCEPTION 'role % has privileges it must not have', r;
                END IF;
            END LOOP;
        END $$
        """
    )

    # window_end is NULL until the first good run (a failure can be recorded before it).
    op.execute(
        """
        CREATE TABLE reconcile_cursor (
            source_id uuid PRIMARY KEY REFERENCES source (id),
            window_end timestamptz,
            last_success timestamptz,
            last_error text CHECK (char_length(last_error) <= 40),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("ALTER TABLE reconcile_cursor ENABLE ROW LEVEL SECURITY")
    op.execute("GRANT SELECT, INSERT, UPDATE ON reconcile_cursor TO soc_reconcile_writer")
    # Only what finding a source by slug needs; not client_id, external_id or secret_ref.
    op.execute("GRANT SELECT (id, slug, enabled) ON source TO soc_reconcile_writer")
    op.execute(
        "CREATE POLICY reconcile_read ON source FOR SELECT TO soc_reconcile_writer USING (true)"
    )
    op.execute(
        "CREATE POLICY reconcile_select ON reconcile_cursor FOR SELECT TO soc_reconcile_writer "
        "USING (true)"
    )
    op.execute(
        "CREATE POLICY reconcile_insert ON reconcile_cursor FOR INSERT TO soc_reconcile_writer "
        "WITH CHECK (true)"
    )
    op.execute(
        "CREATE POLICY reconcile_update ON reconcile_cursor FOR UPDATE TO soc_reconcile_writer "
        "USING (true) WITH CHECK (true)"
    )

    op.execute(
        """
        CREATE FUNCTION reconcile_cursor_get(p_source text) RETURNS timestamptz
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT c.window_end
            FROM reconcile_cursor c JOIN source s ON s.id = c.source_id
            WHERE s.slug = p_source AND s.enabled
        $$
        """
    )
    # The cursor is the end of the last window that was fetched completely. It only moves
    # forward (a late or repeated call changes nothing) and not past the present, so a bad
    # caller cannot make the next run skip a stretch of time.
    op.execute(
        """
        CREATE FUNCTION reconcile_cursor_advance(p_source text, p_window_end timestamptz)
        RETURNS timestamptz
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            sid uuid;
            result timestamptz;
        BEGIN
            IF p_window_end IS NULL OR p_window_end > now() + interval '1 minute' THEN
                RAISE EXCEPTION 'bad window end';
            END IF;
            SELECT id INTO sid FROM source WHERE slug = p_source AND enabled;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown source';
            END IF;
            INSERT INTO reconcile_cursor (source_id, window_end, last_success, last_error)
            VALUES (sid, p_window_end, now(), NULL)
            ON CONFLICT (source_id) DO UPDATE
                SET window_end = GREATEST(reconcile_cursor.window_end, EXCLUDED.window_end),
                    last_success = now(), last_error = NULL, updated_at = now()
            RETURNING window_end INTO result;
            RETURN result;
        END
        $$
        """
    )
    # p_error is a short code from the caller; anything else is replaced, never stored raw.
    op.execute(
        """
        CREATE FUNCTION reconcile_cursor_fail(p_source text, p_error text) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            sid uuid;
            code text;
        BEGIN
            SELECT id INTO sid FROM source WHERE slug = p_source AND enabled;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown source';
            END IF;
            code := left(regexp_replace(coalesce(p_error, ''), '[^A-Za-z0-9_.=: -]', '?', 'g'), 40);
            IF code = '' THEN
                code := 'unknown';
            END IF;
            INSERT INTO reconcile_cursor (source_id, last_error)
            VALUES (sid, code)
            ON CONFLICT (source_id) DO UPDATE SET last_error = code, updated_at = now();
        END
        $$
        """
    )

    op.execute("GRANT soc_reconcile_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_reconcile_writer")
    for function in FUNCTIONS:
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"ALTER FUNCTION {function} OWNER TO soc_reconcile_writer")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO soc_reconcile")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_reconcile_writer")
    # The webhook's own insert function, as it is: same checks, same de-duplication.
    op.execute("GRANT EXECUTE ON FUNCTION ingest_alert TO soc_reconcile")


def downgrade() -> None:
    # Roles are cluster-wide and outlive the schema, as in 0001.
    op.execute("REVOKE EXECUTE ON FUNCTION ingest_alert FROM soc_reconcile")
    for function in FUNCTIONS:
        op.execute(f"DROP FUNCTION {function}")
    op.execute("DROP TABLE reconcile_cursor")
    op.execute("DROP POLICY reconcile_read ON source")
    op.execute("REVOKE SELECT (id, slug, enabled) ON source FROM soc_reconcile_writer")
