"""Posture: the database side of the posture collector, and its STALE signal.

Revision ID: 0011
Revises: 0010

A new service (soc_api.posture) snapshots the sensor fleet, the detection-rule inventory and
the organization's error count from the detection source's API every few minutes, for the
console's Ops Overview. It gets the same shape of access as the other services: a login role
(soc_posture) with no table privileges, whose only way in is EXECUTE on SECURITY DEFINER
functions owned by a role that never logs in (soc_posture_writer).

Tables (all with row level security; only the writer role has any right)
  posture_run     one row per attempt: when, whether it worked, a short failure code, and the
                  organization's error count and newest error component (no messages)
  sensor_state    the current row per sensor id, updated in place; sensors that disappear are
                  removed
  sensor_count    time series: when, online, offline, isolated
  rule_inventory  the current rules: namespace, name, enabled (never a rule body)

Functions
  posture_record(jsonb)   the collector's write path, one transaction: validates the document
                          (sizes, types, patterns), replaces sensor_state and rule_inventory,
                          appends the sensor_count point (computed here from the sensor list,
                          so the counts and the rows cannot disagree) and a good posture_run,
                          and prunes the two series to 30 days. Anything invalid raises and
                          nothing is written.
  posture_fail(text)      records a failed attempt with a short cleaned code; touches nothing else
  posture_health()        for the pager worker: how many runs there have ever been, and how long
                          since the last good one (since the first run when none was good).
                          NULL quiet time when there has been no run at all, so a host that
                          never turned the collector on is never flagged. Owned by
                          soc_worker_writer, EXECUTE for soc_worker only.

console_health() gains two columns (posture_runs, posture_quiet_s) so the banner and the push
agree. A function's result columns cannot change in place, so it is dropped and created again;
the previous release's console reads columns by name and ignores the new ones. Downgrade
restores 0010's definition exactly and removes everything else.
"""

from alembic import op

revision = "0011"
down_revision = "0010"

WRITE_FUNCTIONS = ["posture_record(jsonb)", "posture_fail(text)"]
RETENTION = "30 days"

OLD_CONSOLE_HEALTH = """
        CREATE FUNCTION console_health()
        RETURNS TABLE (
            oldest_pending_page_s bigint, failed_last_24h bigint,
            oldest_unassigned_alert_s bigint, reconcile_sources integer,
            reconcile_quiet_s double precision, backup_age_s double precision
        )
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT
                (SELECT floor(extract(epoch FROM now() - min(created_at)))::bigint
                  FROM notification WHERE status = 'pending'),
                (SELECT count(*) FROM notification
                  WHERE status = 'failed' AND created_at >= now() - interval '24 hours'),
                (SELECT floor(extract(epoch FROM now() - min(received_at)))::bigint
                  FROM alert WHERE case_id IS NULL),
                (SELECT count(*)::integer FROM reconcile_cursor),
                (SELECT max(extract(epoch FROM now() - coalesce(last_success, started_at)))
                        ::double precision FROM reconcile_cursor),
                (SELECT extract(epoch FROM now() - coalesce(last_ok_at, started_at))
                        ::double precision FROM backup_state)
        $$
"""

NEW_CONSOLE_HEALTH = """
        CREATE FUNCTION console_health()
        RETURNS TABLE (
            oldest_pending_page_s bigint, failed_last_24h bigint,
            oldest_unassigned_alert_s bigint, reconcile_sources integer,
            reconcile_quiet_s double precision, backup_age_s double precision,
            posture_runs integer, posture_quiet_s double precision
        )
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT
                (SELECT floor(extract(epoch FROM now() - min(created_at)))::bigint
                  FROM notification WHERE status = 'pending'),
                (SELECT count(*) FROM notification
                  WHERE status = 'failed' AND created_at >= now() - interval '24 hours'),
                (SELECT floor(extract(epoch FROM now() - min(received_at)))::bigint
                  FROM alert WHERE case_id IS NULL),
                (SELECT count(*)::integer FROM reconcile_cursor),
                (SELECT max(extract(epoch FROM now() - coalesce(last_success, started_at)))
                        ::double precision FROM reconcile_cursor),
                (SELECT extract(epoch FROM now() - coalesce(last_ok_at, started_at))
                        ::double precision FROM backup_state),
                (SELECT count(*)::integer FROM posture_run),
                (SELECT extract(epoch FROM now() - coalesce(
                            max(at) FILTER (WHERE ok), min(at)))::double precision
                  FROM posture_run)
        $$
"""


def recreate_console_health(definition: str) -> None:
    op.execute("DROP FUNCTION console_health()")
    op.execute(definition)
    op.execute("GRANT soc_console_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_console_writer")
    op.execute("REVOKE ALL ON FUNCTION console_health() FROM PUBLIC")
    op.execute("ALTER FUNCTION console_health() OWNER TO soc_console_writer")
    op.execute("GRANT EXECUTE ON FUNCTION console_health() TO soc_console")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_console_writer")


def upgrade() -> None:
    # Same rule as 0001: a pre-existing role with extra privileges stops the migration.
    op.execute(
        """
        DO $$
        DECLARE
            r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY['soc_posture', 'soc_posture_writer'] LOOP
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS '
                                   'NOCREATEDB NOCREATEROLE', r);
                ELSIF EXISTS (
                    SELECT FROM pg_roles WHERE rolname = r
                    AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole
                         OR (r = 'soc_posture_writer' AND rolcanlogin))
                ) THEN
                    RAISE EXCEPTION 'role % has privileges it must not have', r;
                END IF;
            END LOOP;
        END $$
        """
    )

    op.execute(
        """
        CREATE TABLE posture_run (
            id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            at timestamptz NOT NULL DEFAULT now(),
            ok boolean NOT NULL,
            error text CHECK (char_length(error) <= 40),
            org_error_count integer CHECK (org_error_count >= 0),
            org_error_component text CHECK (char_length(org_error_component) <= 40),
            CHECK (ok OR error IS NOT NULL)
        )
        """
    )
    op.execute("CREATE INDEX posture_run_at ON posture_run (at)")
    op.execute(
        """
        CREATE TABLE sensor_state (
            sid text PRIMARY KEY CHECK (sid ~ '^[A-Za-z0-9-]{8,64}$'),
            hostname text NOT NULL CHECK (char_length(hostname) <= 253),
            platform text NOT NULL CHECK (char_length(platform) <= 40),
            version text CHECK (char_length(version) <= 40),
            online boolean NOT NULL,
            isolated boolean NOT NULL,
            tags text[] NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 20),
            last_seen timestamptz,
            updated_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE sensor_count (
            at timestamptz NOT NULL DEFAULT now(),
            online integer NOT NULL CHECK (online >= 0),
            offline integer NOT NULL CHECK (offline >= 0),
            isolated integer NOT NULL CHECK (isolated >= 0)
        )
        """
    )
    op.execute("CREATE INDEX sensor_count_at ON sensor_count (at)")
    op.execute(
        """
        CREATE TABLE rule_inventory (
            namespace text NOT NULL CHECK (namespace ~ '^[a-z0-9-]{1,32}$'),
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255),
            enabled boolean NOT NULL,
            updated_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (namespace, name)
        )
        """
    )

    for table in ("posture_run", "sensor_state", "sensor_count", "rule_inventory"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute("GRANT SELECT, INSERT, DELETE ON posture_run, sensor_count TO soc_posture_writer")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON sensor_state, rule_inventory TO soc_posture_writer"
    )
    op.execute("GRANT USAGE ON SEQUENCE posture_run_id_seq TO soc_posture_writer")
    for table, commands in (
        ("posture_run", ("SELECT", "INSERT", "DELETE")),
        ("sensor_count", ("SELECT", "INSERT", "DELETE")),
        ("sensor_state", ("SELECT", "INSERT", "UPDATE", "DELETE")),
        ("rule_inventory", ("SELECT", "INSERT", "UPDATE", "DELETE")),
    ):
        for command in commands:
            clause = "WITH CHECK (true)" if command == "INSERT" else "USING (true)"
            if command == "UPDATE":
                clause = "USING (true) WITH CHECK (true)"
            op.execute(
                f"CREATE POLICY posture_{command.lower()} ON {table} FOR {command} "
                f"TO soc_posture_writer {clause}"
            )

    # The pager worker's writer and the console's writer read two columns of posture_run.
    for role, policy in (
        ("soc_worker_writer", "worker_posture_read"),
        ("soc_console_writer", "console_health_read"),
    ):
        op.execute(f"GRANT SELECT (at, ok) ON posture_run TO {role}")
        op.execute(f"CREATE POLICY {policy} ON posture_run FOR SELECT TO {role} USING (true)")

    # ---- the write path ----
    op.execute(
        """
        CREATE FUNCTION posture_record(p_doc jsonb) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            sensors jsonb := p_doc -> 'sensors';
            rules jsonb := p_doc -> 'rules';
            org jsonb := p_doc -> 'org_errors';
            n_online integer;
            n_offline integer;
            n_isolated integer;
            org_count integer;
            org_component text;
        BEGIN
            IF jsonb_typeof(p_doc) IS DISTINCT FROM 'object'
               OR jsonb_typeof(sensors) IS DISTINCT FROM 'array'
               OR jsonb_typeof(rules) IS DISTINCT FROM 'array'
               OR jsonb_typeof(org) IS DISTINCT FROM 'object' THEN
                RAISE EXCEPTION 'bad posture document';
            END IF;
            IF jsonb_array_length(sensors) > 5000 OR jsonb_array_length(rules) > 5000 THEN
                RAISE EXCEPTION 'posture document too large';
            END IF;

            -- every sensor: an object with the right types and sizes
            IF EXISTS (
                SELECT 1 FROM jsonb_array_elements(sensors) s
                WHERE jsonb_typeof(s) IS DISTINCT FROM 'object'
                   OR jsonb_typeof(s -> 'sid') IS DISTINCT FROM 'string'
                   OR (s ->> 'sid') !~ '^[A-Za-z0-9-]{8,64}$'
                   OR jsonb_typeof(s -> 'hostname') IS DISTINCT FROM 'string'
                   OR char_length(s ->> 'hostname') > 253
                   OR jsonb_typeof(s -> 'platform') IS DISTINCT FROM 'string'
                   OR char_length(s ->> 'platform') > 40
                   OR jsonb_typeof(s -> 'version') NOT IN ('string', 'null')
                   OR char_length(s ->> 'version') > 40
                   OR jsonb_typeof(s -> 'online') IS DISTINCT FROM 'boolean'
                   OR jsonb_typeof(s -> 'isolated') IS DISTINCT FROM 'boolean'
                   OR jsonb_typeof(s -> 'tags') IS DISTINCT FROM 'array'
                   OR jsonb_array_length(s -> 'tags') > 20
                   OR jsonb_typeof(s -> 'last_seen_s') NOT IN ('number', 'null')
                   OR (jsonb_typeof(s -> 'last_seen_s') = 'number'
                       AND ((s ->> 'last_seen_s')::numeric NOT BETWEEN 0 AND 4102444800))
                   OR EXISTS (
                        SELECT 1 FROM jsonb_array_elements(s -> 'tags') t
                        WHERE jsonb_typeof(t) IS DISTINCT FROM 'string'
                           OR char_length(t #>> '{}') NOT BETWEEN 1 AND 64)
            ) THEN
                RAISE EXCEPTION 'bad sensor in posture document';
            END IF;
            IF (SELECT count(DISTINCT s ->> 'sid') FROM jsonb_array_elements(sensors) s)
               <> jsonb_array_length(sensors) THEN
                RAISE EXCEPTION 'duplicate sensor in posture document';
            END IF;

            IF EXISTS (
                SELECT 1 FROM jsonb_array_elements(rules) x
                WHERE jsonb_typeof(x) IS DISTINCT FROM 'object'
                   OR jsonb_typeof(x -> 'namespace') IS DISTINCT FROM 'string'
                   OR (x ->> 'namespace') !~ '^[a-z0-9-]{1,32}$'
                   OR jsonb_typeof(x -> 'name') IS DISTINCT FROM 'string'
                   OR char_length(x ->> 'name') NOT BETWEEN 1 AND 255
                   OR jsonb_typeof(x -> 'enabled') IS DISTINCT FROM 'boolean'
            ) THEN
                RAISE EXCEPTION 'bad rule in posture document';
            END IF;
            IF (SELECT count(DISTINCT (x ->> 'namespace', x ->> 'name'))
                FROM jsonb_array_elements(rules) x) <> jsonb_array_length(rules) THEN
                RAISE EXCEPTION 'duplicate rule in posture document';
            END IF;

            IF jsonb_typeof(org -> 'count') IS DISTINCT FROM 'number'
               OR (org ->> 'count') !~ '^[0-9]{1,6}$'
               OR jsonb_typeof(org -> 'newest') NOT IN ('string', 'null')
               OR (jsonb_typeof(org -> 'newest') = 'string'
                   AND (org ->> 'newest') !~ '^[A-Za-z0-9_.:-]{1,40}$') THEN
                RAISE EXCEPTION 'bad org errors in posture document';
            END IF;
            org_count := (org ->> 'count')::integer;
            org_component := org ->> 'newest';

            -- current state: replace
            DELETE FROM sensor_state
            WHERE sid NOT IN (SELECT s ->> 'sid' FROM jsonb_array_elements(sensors) s);
            INSERT INTO sensor_state
                (sid, hostname, platform, version, online, isolated, tags, last_seen, updated_at)
            SELECT s ->> 'sid', s ->> 'hostname', s ->> 'platform', s ->> 'version',
                   (s ->> 'online')::boolean, (s ->> 'isolated')::boolean,
                   ARRAY(SELECT t #>> '{}' FROM jsonb_array_elements(s -> 'tags') t),
                   CASE WHEN jsonb_typeof(s -> 'last_seen_s') = 'number'
                        THEN to_timestamp((s ->> 'last_seen_s')::double precision) END,
                   now()
            FROM jsonb_array_elements(sensors) s
            ON CONFLICT (sid) DO UPDATE SET
                hostname = EXCLUDED.hostname, platform = EXCLUDED.platform,
                version = EXCLUDED.version, online = EXCLUDED.online,
                isolated = EXCLUDED.isolated, tags = EXCLUDED.tags,
                last_seen = EXCLUDED.last_seen, updated_at = now();

            DELETE FROM rule_inventory r
            WHERE NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements(rules) x
                WHERE x ->> 'namespace' = r.namespace AND x ->> 'name' = r.name);
            INSERT INTO rule_inventory (namespace, name, enabled, updated_at)
            SELECT x ->> 'namespace', x ->> 'name', (x ->> 'enabled')::boolean, now()
            FROM jsonb_array_elements(rules) x
            ON CONFLICT (namespace, name) DO UPDATE
                SET enabled = EXCLUDED.enabled, updated_at = now();

            -- the time series point, counted from the same list
            SELECT count(*) FILTER (WHERE (s ->> 'online')::boolean),
                   count(*) FILTER (WHERE NOT (s ->> 'online')::boolean),
                   count(*) FILTER (WHERE (s ->> 'isolated')::boolean)
            INTO n_online, n_offline, n_isolated
            FROM jsonb_array_elements(sensors) s;
            INSERT INTO sensor_count (online, offline, isolated)
            VALUES (n_online, n_offline, n_isolated);

            INSERT INTO posture_run (ok, org_error_count, org_error_component)
            VALUES (true, org_count, org_component);

            DELETE FROM sensor_count WHERE at < now() - interval '__RETENTION__';
            DELETE FROM posture_run WHERE at < now() - interval '__RETENTION__';
        END
        $$
        """.replace("__RETENTION__", RETENTION)
    )
    # p_error is a short code from the caller; anything else is replaced, never stored raw.
    op.execute(
        """
        CREATE FUNCTION posture_fail(p_error text) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            code text;
        BEGIN
            code := left(regexp_replace(coalesce(p_error, ''), '[^A-Za-z0-9_.=: -]', '?', 'g'), 40);
            IF code = '' THEN
                code := 'unknown';
            END IF;
            INSERT INTO posture_run (ok, error) VALUES (false, code);
            DELETE FROM sensor_count WHERE at < now() - interval '__RETENTION__';
            DELETE FROM posture_run WHERE at < now() - interval '__RETENTION__';
        END
        $$
        """.replace("__RETENTION__", RETENTION)
    )

    # ---- the pager worker's read ----
    op.execute(
        """
        CREATE FUNCTION posture_health()
        RETURNS TABLE (runs integer, quiet_s double precision)
        LANGUAGE sql SECURITY DEFINER STABLE
        SET search_path = pg_catalog, public, pg_temp
        AS $$
            SELECT count(*)::integer,
                   extract(epoch FROM now() - coalesce(max(at) FILTER (WHERE ok), min(at)))
                       ::double precision
            FROM posture_run
        $$
        """
    )

    op.execute("GRANT soc_posture_writer TO current_user")
    op.execute("GRANT soc_worker_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_posture_writer")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_worker_writer")
    for function in WRITE_FUNCTIONS:
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"ALTER FUNCTION {function} OWNER TO soc_posture_writer")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO soc_posture")
    op.execute("REVOKE ALL ON FUNCTION posture_health() FROM PUBLIC")
    op.execute("ALTER FUNCTION posture_health() OWNER TO soc_worker_writer")
    op.execute("GRANT EXECUTE ON FUNCTION posture_health() TO soc_worker")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_posture_writer")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_worker_writer")

    recreate_console_health(NEW_CONSOLE_HEALTH)


def downgrade() -> None:
    # Roles are cluster-wide and outlive the schema, as in 0001.
    recreate_console_health(OLD_CONSOLE_HEALTH)
    op.execute("DROP FUNCTION posture_health()")
    for function in WRITE_FUNCTIONS:
        op.execute(f"DROP FUNCTION {function}")
    op.execute("DROP POLICY worker_posture_read ON posture_run")
    op.execute("DROP POLICY console_health_read ON posture_run")
    op.execute("DROP TABLE rule_inventory")
    op.execute("DROP TABLE sensor_count")
    op.execute("DROP TABLE sensor_state")
    op.execute("DROP TABLE posture_run")
