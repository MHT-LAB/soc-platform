"""Schema v1: tenant tables, row-level security, ingest function.

Revision ID: 0001
Revises:

Isolation model (see docs/adr/0001-postgres-from-day-one.md):

* Every client-owned table carries client_id. The soc_app role (console,
  workers) sees only the rows whose client_id equals the app.client_id setting
  of its session; with the setting unset it sees nothing. soc_app is neither
  owner, superuser nor BYPASSRLS, so the policies bind it.
* The ingest handler connects as soc_ingest, which has no table privileges at
  all. Its single way in is ingest_alert(), a SECURITY DEFINER function that
  maps a delivery to a source, attributes it (unknown tenant -> Unassigned),
  and inserts idempotently. It reads nothing back, ignores app.client_id, and
  pins its search_path. It runs as soc_ingest_writer (NOLOGIN, can read source
  and insert alert, nothing else), not as the owner, and an RLS policy keeps
  each alert with its source's client or Unassigned.
* Roles are created NOLOGIN. Deploy gives soc_app and soc_ingest a login and
  password (private repo); this migration never holds a credential.
* The owner needs CREATEROLE, not SUPERUSER. A pre-existing service role with
  extra privileges stops the migration.

Tables are named after the design; the two SQL reserved words are prefixed
(soc_case, soc_user) so nothing needs quoting.
"""

from alembic import op

revision = "0001"
down_revision = None

UNASSIGNED = "00000000-0000-4000-8000-000000000001"

# Tables with a client_id column, in dependency order.
TENANT_TABLES = [
    "site",
    "endpoint",
    "source",
    "soc_case",
    "alert",
    "case_event",
    "notification",
    "usage",
    "soc_user",
]


def upgrade() -> None:
    op.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    # Roles are cluster-wide, so they may already exist. A privileged one stops
    # the migration (changing those attributes would need a superuser, and the
    # owner should not be one). soc_ingest_writer only owns ingest_alert() and
    # never logs in.
    op.execute(
        """
        DO $$
        DECLARE
            r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY['soc_app', 'soc_ingest', 'soc_ingest_writer'] LOOP
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS '
                                   'NOCREATEDB NOCREATEROLE', r);
                ELSIF EXISTS (
                    SELECT FROM pg_roles WHERE rolname = r
                    AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole
                         OR (r = 'soc_ingest_writer' AND rolcanlogin))
                ) THEN
                    RAISE EXCEPTION 'role % has privileges it must not have', r;
                END IF;
            END LOOP;
        END $$
        """
    )

    op.execute(
        """
        CREATE TABLE client (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{1,64}$'),
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
            tenant_id text,
            status text NOT NULL DEFAULT 'pilot'
                CHECK (status IN ('internal', 'pilot', 'paying')),
            tier text,
            timezone text NOT NULL DEFAULT 'America/New_York',
            contacts jsonb NOT NULL DEFAULT '[]',
            escalation_policy jsonb NOT NULL DEFAULT '{}',
            auto_response_allowed boolean NOT NULL DEFAULT false,
            retention_days integer NOT NULL DEFAULT 365 CHECK (retention_days > 0),
            vendor_account_id text,
            created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE site (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            client_id uuid NOT NULL REFERENCES client (id),
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
            controller_site_id text,
            UNIQUE (client_id, id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE endpoint (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            client_id uuid NOT NULL REFERENCES client (id),
            site_id uuid,
            sensor_id text NOT NULL UNIQUE,
            hostname text,
            platform text,
            tags text[] NOT NULL DEFAULT '{}',
            role text,
            criticality text,
            owner text,
            auto_response_allowed boolean NOT NULL DEFAULT false,
            enrolled_at timestamptz NOT NULL DEFAULT now(),
            last_seen timestamptz,
            UNIQUE (client_id, id),
            FOREIGN KEY (client_id, site_id) REFERENCES site (client_id, id)
        )
        """
    )
    # secret_ref names a secret in the secrets manager; the value is never stored.
    op.execute(
        """
        CREATE TABLE source (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            client_id uuid NOT NULL REFERENCES client (id),
            slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{1,32}$'),
            type text NOT NULL,
            external_id text,
            secret_ref text,
            enabled boolean NOT NULL DEFAULT true
        )
        """
    )
    op.execute(
        """
        CREATE TABLE soc_case (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            client_id uuid NOT NULL REFERENCES client (id),
            severity text NOT NULL
                CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
            status text NOT NULL DEFAULT 'open',
            verdict text,
            lane text,
            opened_at timestamptz NOT NULL DEFAULT now(),
            closed_at timestamptz,
            closing_note text,
            UNIQUE (client_id, id)
        )
        """
    )
    # Text fields are attacker-controlled; the CHECKs are the backstop behind the
    # truncation in ingest_alert(). raw is stored as untrusted data.
    op.execute(
        """
        CREATE TABLE alert (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            client_id uuid NOT NULL REFERENCES client (id),
            site_id uuid,
            endpoint_id uuid,
            source_id uuid NOT NULL REFERENCES source (id),
            event_id text NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 256),
            rule text CHECK (char_length(rule) <= 256),
            severity text NOT NULL DEFAULT 'medium'
                CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
            summary text CHECK (char_length(summary) <= 2000),
            actor text CHECK (char_length(actor) <= 512),
            mitre_hint text CHECK (char_length(mitre_hint) <= 256),
            raw jsonb NOT NULL CHECK (octet_length(raw::text) <= 262144),
            case_id uuid,
            verdict text,
            detected_at timestamptz,
            received_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (source_id, event_id),
            FOREIGN KEY (client_id, site_id) REFERENCES site (client_id, id),
            FOREIGN KEY (client_id, endpoint_id) REFERENCES endpoint (client_id, id),
            FOREIGN KEY (client_id, case_id) REFERENCES soc_case (client_id, id)
        )
        """
    )
    op.execute("CREATE INDEX alert_client_received ON alert (client_id, received_at DESC)")
    op.execute(
        """
        CREATE TABLE case_event (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            client_id uuid NOT NULL REFERENCES client (id),
            case_id uuid NOT NULL,
            at timestamptz NOT NULL DEFAULT now(),
            actor text NOT NULL,
            kind text NOT NULL,
            body text,
            FOREIGN KEY (client_id, case_id) REFERENCES soc_case (client_id, id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE notification (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            client_id uuid NOT NULL REFERENCES client (id),
            case_id uuid NOT NULL,
            channel text NOT NULL,
            sent_at timestamptz,
            acked_at timestamptz,
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            FOREIGN KEY (client_id, case_id) REFERENCES soc_case (client_id, id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE usage (
            client_id uuid NOT NULL REFERENCES client (id),
            month date NOT NULL CHECK (month = date_trunc('month', month)::date),
            alerts integer NOT NULL DEFAULT 0,
            cases integer NOT NULL DEFAULT 0,
            tokens_in bigint NOT NULL DEFAULT 0,
            tokens_out bigint NOT NULL DEFAULT 0,
            cost_usd numeric(12, 4) NOT NULL DEFAULT 0,
            PRIMARY KEY (client_id, month)
        )
        """
    )
    # Staff users have no client_id and are invisible to soc_app; a
    # client_viewer is tied to one client.
    op.execute(
        """
        CREATE TABLE soc_user (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            client_id uuid REFERENCES client (id),
            email text NOT NULL UNIQUE,
            role text NOT NULL
                CHECK (role IN ('commander', 'analyst', 'viewer', 'client_viewer')),
            contacts jsonb NOT NULL DEFAULT '{}',
            created_at timestamptz NOT NULL DEFAULT now(),
            CHECK ((role = 'client_viewer') = (client_id IS NOT NULL))
        )
        """
    )

    # Unmapped events are never dropped: they land with this client.
    op.execute(
        f"""
        INSERT INTO client (id, slug, name, status)
        VALUES ('{UNASSIGNED}', 'unassigned', 'Unassigned', 'internal')
        """
    )

    # ---- row-level security for soc_app ----
    op.execute(
        """
        CREATE FUNCTION app_client_id() RETURNS uuid
        LANGUAGE sql STABLE
        AS $$ SELECT nullif(current_setting('app.client_id', true), '')::uuid $$
        """
    )
    op.execute("ALTER TABLE client ENABLE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant ON client TO soc_app
        USING (id = app_client_id()) WITH CHECK (id = app_client_id())
        """
    )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant ON {table} TO soc_app
            USING (client_id = app_client_id()) WITH CHECK (client_id = app_client_id())
            """
        )

    # No DELETE anywhere; case_event is append-only.
    for table in ["client", *TENANT_TABLES]:
        if table != "case_event":
            op.execute(f"GRANT SELECT, INSERT, UPDATE ON {table} TO soc_app")
    op.execute("GRANT SELECT, INSERT ON case_event TO soc_app")
    op.execute("GRANT EXECUTE ON FUNCTION app_client_id() TO soc_app")

    # ---- ingest: one function, no table privileges ----
    # The function runs as soc_ingest_writer, not as the owner: it can read
    # sources and insert alerts, nothing else, and RLS still applies to it. The
    # insert policy pins attribution in the database too: an alert belongs to its
    # source's client or to Unassigned.
    op.execute("GRANT SELECT ON source TO soc_ingest_writer")
    op.execute("GRANT INSERT ON alert TO soc_ingest_writer")
    op.execute("CREATE POLICY ingest_read ON source FOR SELECT TO soc_ingest_writer USING (true)")
    op.execute(
        f"""
        CREATE POLICY ingest_insert ON alert FOR INSERT TO soc_ingest_writer
        WITH CHECK (
            client_id = '{UNASSIGNED}'::uuid
            OR client_id = (SELECT s.client_id FROM source s WHERE s.id = source_id)
        )
        """
    )
    op.execute(
        f"""
        CREATE FUNCTION ingest_alert(
            p_source text, p_tenant text, p_event_id text, p_rule text, p_severity text,
            p_summary text, p_actor text, p_mitre text, p_detected_at timestamptz, p_raw jsonb
        ) RETURNS text
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public, pg_temp
        AS $$
        DECLARE
            src record;
            cid uuid;
        BEGIN
            SELECT id, client_id, external_id INTO src
            FROM source WHERE slug = p_source AND enabled;
            IF NOT FOUND THEN
                RETURN 'unknown_source';
            END IF;
            IF p_event_id IS NULL OR char_length(p_event_id) NOT BETWEEN 1 AND 256 THEN
                RETURN 'invalid_event_id';
            END IF;
            IF p_raw IS NULL OR octet_length(p_raw::text) > 262144 THEN
                RETURN 'invalid_payload';
            END IF;
            IF src.external_id IS NULL OR src.external_id = p_tenant THEN
                cid := src.client_id;
            ELSE
                cid := '{UNASSIGNED}'::uuid;
            END IF;
            -- Not ON CONFLICT: that would need read access to alert. The only
            -- unique key a caller controls is (source_id, event_id).
            INSERT INTO alert (client_id, source_id, event_id, rule, severity, summary,
                               actor, mitre_hint, detected_at, raw)
            VALUES (cid, src.id, p_event_id, left(p_rule, 256),
                    CASE WHEN p_severity IN ('info', 'low', 'medium', 'high', 'critical')
                         THEN p_severity ELSE 'medium' END,
                    left(p_summary, 2000), left(p_actor, 512), left(p_mitre, 256),
                    p_detected_at, p_raw);
            RETURN 'inserted';
        EXCEPTION WHEN unique_violation THEN
            RETURN 'duplicate';
        END
        $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION ingest_alert FROM PUBLIC")
    # Handing the function over needs SET on the role and, for the new owner,
    # CREATE on the schema; the latter is taken back in the same transaction.
    op.execute("GRANT soc_ingest_writer TO current_user")
    op.execute("GRANT CREATE ON SCHEMA public TO soc_ingest_writer")
    op.execute("ALTER FUNCTION ingest_alert OWNER TO soc_ingest_writer")
    op.execute("REVOKE CREATE ON SCHEMA public FROM soc_ingest_writer")
    op.execute("GRANT EXECUTE ON FUNCTION ingest_alert TO soc_ingest")


def downgrade() -> None:
    # Roles are cluster-wide and outlive the schema; dropping the tables drops
    # their grants.
    op.execute("DROP FUNCTION ingest_alert")
    for table in ["usage", "notification", "case_event", "alert", "soc_case", "source"]:
        op.execute(f"DROP TABLE {table}")
    for table in ["soc_user", "endpoint", "site", "client"]:
        op.execute(f"DROP TABLE {table}")
    op.execute("DROP FUNCTION app_client_id")
