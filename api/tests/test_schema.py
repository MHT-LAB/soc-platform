"""Schema v1: migrations, row-level security, the ingest role.

These run against a real Postgres (see conftest.db). Each test gets a fresh
database; the roles are logged into for real, not simulated with SET ROLE.
"""

import json
import os
import uuid

import psycopg
import pytest
import sqlalchemy.exc
from conftest import ROLE_PASSWORD, SEED_FILE, TestDb
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from soc_api import db as soc_db
from soc_api.seed import seed_demo

UNASSIGNED = "00000000-0000-4000-8000-000000000001"
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
ALL_TABLES = ["client", *TENANT_TABLES]
INGEST = (
    "SELECT ingest_alert(%(source)s, %(tenant)s, %(event)s, 'rule-x', 'high', 'summary', "
    "'actor', 'T1059', now(), %(raw)s::jsonb)"
)


def ingest(conn: psycopg.Connection, source: str, tenant: str, event: str, raw: str = "{}") -> str:
    row = conn.execute(
        INGEST, {"source": source, "tenant": tenant, "event": event, "raw": raw}
    ).fetchone()
    assert row is not None
    return str(row[0])


def two_clients(db: TestDb) -> tuple[str, str]:
    """Two clients, each with a source (tenant id t-a / t-b), a site, endpoint, alert and case."""
    ids = []
    with db.connect() as c:
        for tag in ("a", "b"):
            cid = c.execute(
                "INSERT INTO client (slug, name, tenant_id) VALUES (%s, %s, %s) RETURNING id",
                (f"client-{tag}", f"Client {tag}", f"t-{tag}"),
            ).fetchone()
            assert cid is not None
            client_id = cid[0]
            ids.append(str(client_id))
            site = c.execute(
                "INSERT INTO site (client_id, name) VALUES (%s, 'hq') RETURNING id", (client_id,)
            ).fetchone()
            assert site is not None
            c.execute(
                "INSERT INTO endpoint (client_id, site_id, sensor_id) VALUES (%s, %s, %s)",
                (client_id, site[0], f"sensor-{tag}"),
            )
            c.execute(
                "INSERT INTO source (client_id, slug, type, external_id) "
                "VALUES (%s, %s, 'edr', %s)",
                (client_id, f"src-{tag}", f"t-{tag}"),
            )
            case = c.execute(
                "INSERT INTO soc_case (client_id, severity) VALUES (%s, 'high') RETURNING id",
                (client_id,),
            ).fetchone()
            assert case is not None
            c.execute(
                "INSERT INTO case_event (client_id, case_id, actor, kind) "
                "VALUES (%s, %s, 'x', 'k')",
                (client_id, case[0]),
            )
            c.execute(
                "INSERT INTO notification (client_id, case_id, channel) VALUES (%s, %s, 'ntfy')",
                (client_id, case[0]),
            )
            c.execute(
                "INSERT INTO usage (client_id, month) VALUES (%s, '2026-10-01')", (client_id,)
            )
            c.execute(
                "INSERT INTO soc_user (client_id, email, role) VALUES (%s, %s, 'client_viewer')",
                (client_id, f"viewer-{tag}@example.com"),
            )
            ingest_row = c.execute(
                "SELECT ingest_alert(%s, %s, 'seed-event', 'r', 'low', 's', 'a', 'm', now(), '{}')",
                (f"src-{tag}", f"t-{tag}"),
            ).fetchone()
            assert ingest_row == ("inserted",)
        c.execute("INSERT INTO soc_user (email, role) VALUES ('staff@example.com', 'analyst')")
    return ids[0], ids[1]


def count(conn: psycopg.Connection, table: str) -> int:
    row = conn.execute(f"SELECT count(*) FROM {table}").fetchone()
    assert row is not None
    return int(row[0])


# ---- migrations ----


def test_migrations_apply_and_create_every_table(db: TestDb) -> None:
    with db.connect() as c:
        tables = {
            r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        }
    assert tables - {"alembic_version"} == set(ALL_TABLES)


def test_unassigned_client_is_seeded(db: TestDb) -> None:
    with db.connect() as c:
        row = c.execute("SELECT slug FROM client WHERE id = %s", (UNASSIGNED,)).fetchone()
    assert row == ("unassigned",)


def test_downgrade_then_upgrade_again(db: TestDb) -> None:
    soc_db.downgrade(db.sqlalchemy_url(), "base")
    with db.connect() as c:
        left = [
            r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        ]
    assert left == ["alembic_version"]
    soc_db.upgrade(db.sqlalchemy_url())


def test_demo_seed_loads(db: TestDb) -> None:
    seed_demo(db.sqlalchemy_url(), SEED_FILE)
    with db.connect() as c:
        assert count(c, "endpoint") == 2
        # the demo source is bound to the demo tenant id
        out = ingest(c, "acme-lc", json.loads(SEED_FILE.read_text())["client"]["tenant_id"], "e1")
        assert out == "inserted"
        row = c.execute("SELECT c.slug FROM alert a JOIN client c ON c.id = a.client_id").fetchone()
    assert row == ("acme-demo",)


# ---- row-level security ----


@pytest.mark.parametrize("table", ALL_TABLES)
def test_every_tenant_table_has_rls_enabled(db: TestDb, table: str) -> None:
    with db.connect() as c:
        row = c.execute(
            "SELECT relrowsecurity FROM pg_class WHERE relname = %s", (table,)
        ).fetchone()
    assert row == (True,)


def test_service_roles_are_not_privileged_and_own_nothing(db: TestDb) -> None:
    with db.connect() as c:
        roles = c.execute(
            "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb "
            "FROM pg_roles WHERE rolname IN ('soc_app', 'soc_ingest')"
        ).fetchall()
        owned = c.execute(
            "SELECT count(*) FROM pg_class cl JOIN pg_roles r ON r.oid = cl.relowner "
            "WHERE r.rolname IN ('soc_app', 'soc_ingest') "
            "AND cl.relnamespace = 'public'::regnamespace"
        ).fetchone()
    assert len(roles) == 2
    assert all(r[1:] == (False, False, False, False) for r in roles)
    assert owned == (0,)


@pytest.mark.parametrize("table", ALL_TABLES)
def test_app_role_sees_only_its_own_client(db: TestDb, table: str) -> None:
    a, b = two_clients(db)
    key = "id" if table == "client" else "client_id"
    with db.connect("soc_app") as c:
        c.execute("SELECT set_config('app.client_id', %s, false)", (a,))
        rows = c.execute(f"SELECT {key} FROM {table}").fetchall()
    assert rows, f"{table}: expected rows for client a"
    assert {str(r[0]) for r in rows} == {a}
    assert b not in {str(r[0]) for r in rows}


@pytest.mark.parametrize("table", ALL_TABLES)
def test_app_role_sees_nothing_without_a_client(db: TestDb, table: str) -> None:
    two_clients(db)
    with db.connect("soc_app") as c:
        assert count(c, table) == 0


def test_app_role_cannot_write_into_another_client(db: TestDb) -> None:
    a, b = two_clients(db)
    with db.connect("soc_app") as c:
        c.execute("SELECT set_config('app.client_id', %s, false)", (a,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("INSERT INTO site (client_id, name) VALUES (%s, 'planted')", (b,))
        # an update that targets the other client's rows touches nothing
        cur = c.execute("UPDATE site SET name = 'renamed' WHERE client_id = %s", (b,))
        assert cur.rowcount == 0
        # moving an own row to the other client is refused
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE site SET client_id = %s WHERE client_id = %s", (b, a))
    with db.connect() as admin:
        row = admin.execute("SELECT count(*) FROM site WHERE name = 'renamed'").fetchone()
    assert row == (0,)


@pytest.mark.parametrize(
    ("table", "column", "parent"),
    [
        ("endpoint", "site_id", "site"),
        ("alert", "site_id", "site"),
        ("alert", "endpoint_id", "endpoint"),
        ("alert", "case_id", "soc_case"),
        ("case_event", "case_id", "soc_case"),
        ("notification", "case_id", "soc_case"),
    ],
)
def test_references_cannot_cross_clients(db: TestDb, table: str, column: str, parent: str) -> None:
    a, b = two_clients(db)
    with db.connect() as c:
        other = c.execute(f"SELECT id FROM {parent} WHERE client_id = %s", (b,)).fetchone()
        assert other is not None
        extra = {
            "endpoint": "sensor_id",
            "alert": "source_id, event_id, raw",
            "case_event": "actor, kind",
            "notification": "channel",
        }[table]
        values = {
            "endpoint": "'x'",
            "alert": "(SELECT id FROM source WHERE client_id = %(a)s), 'x', '{}'",
            "case_event": "'x', 'k'",
            "notification": "'ntfy'",
        }[table]
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            c.execute(
                f"INSERT INTO {table} (client_id, {column}, {extra}) "
                f"VALUES (%(a)s, %(other)s, {values})",
                {"a": a, "other": other[0]},
            )


def test_case_events_are_append_only(db: TestDb) -> None:
    a, _ = two_clients(db)
    with db.connect("soc_app") as c:
        c.execute("SELECT set_config('app.client_id', %s, false)", (a,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("UPDATE case_event SET body = 'rewritten'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("DELETE FROM case_event")


def test_app_role_cannot_delete_anything(db: TestDb) -> None:
    a, _ = two_clients(db)
    with db.connect("soc_app") as c:
        c.execute("SELECT set_config('app.client_id', %s, false)", (a,))
        for table in ALL_TABLES:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(f"DELETE FROM {table}")


# ---- the ingest role ----


@pytest.mark.parametrize("table", ALL_TABLES)
def test_ingest_role_cannot_read_any_table(db: TestDb, table: str) -> None:
    two_clients(db)
    with db.connect("soc_ingest") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute(f"SELECT * FROM {table}")


@pytest.mark.parametrize("table", ALL_TABLES)
def test_ingest_role_cannot_write_any_table_directly(db: TestDb, table: str) -> None:
    with db.connect("soc_ingest") as c:
        col = "id" if table == "client" else "client_id"
        for stmt in (f"INSERT INTO {table} DEFAULT VALUES", f"UPDATE {table} SET {col} = {col}"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(stmt)


def test_ingest_role_cannot_create_objects(db: TestDb) -> None:
    with db.connect("soc_ingest") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("CREATE TABLE public.planted (id int)")


def test_ingest_function_pins_search_path_and_is_not_public(db: TestDb) -> None:
    with db.connect() as c:
        row = c.execute(
            "SELECT prosecdef, proconfig, has_function_privilege('public', oid, 'EXECUTE') "
            "FROM pg_proc WHERE proname = 'ingest_alert'"
        ).fetchone()
    assert row is not None
    secdef, config, public_exec = row
    assert secdef is True
    assert config is not None and any(s.startswith("search_path=") for s in config)
    assert "pg_temp" in "".join(config)
    assert public_exec is False


def test_ingest_inserts_for_the_sources_client(db: TestDb) -> None:
    a, _ = two_clients(db)
    with db.connect("soc_ingest") as c:
        assert ingest(c, "src-a", "t-a", "evt-1", '{"k": "v"}') == "inserted"
    with db.connect() as admin:
        row = admin.execute(
            "SELECT client_id, rule, severity, raw FROM alert WHERE event_id = 'evt-1'"
        ).fetchone()
    assert row is not None
    assert str(row[0]) == a
    assert row[1:] == ("rule-x", "high", {"k": "v"})


def test_unknown_tenant_lands_in_unassigned_and_is_not_dropped(db: TestDb) -> None:
    two_clients(db)
    with db.connect("soc_ingest") as c:
        assert ingest(c, "src-a", "someone-else", "evt-2") == "inserted"
    with db.connect() as admin:
        row = admin.execute("SELECT client_id FROM alert WHERE event_id = 'evt-2'").fetchone()
    assert row is not None and str(row[0]) == UNASSIGNED


def test_unknown_or_disabled_source_stores_nothing(db: TestDb) -> None:
    two_clients(db)
    with db.connect() as admin:
        admin.execute("UPDATE source SET enabled = false WHERE slug = 'src-b'")
        before = count(admin, "alert")
    with db.connect("soc_ingest") as c:
        assert ingest(c, "nope", "t-a", "evt-3") == "unknown_source"
        assert ingest(c, "src-b", "t-b", "evt-3") == "unknown_source"
    with db.connect() as admin:
        assert count(admin, "alert") == before


def test_replayed_delivery_creates_exactly_one_row(db: TestDb) -> None:
    two_clients(db)
    with db.connect("soc_ingest") as c:
        assert ingest(c, "src-a", "t-a", "evt-4") == "inserted"
        assert ingest(c, "src-a", "t-a", "evt-4") == "duplicate"
        assert ingest(c, "src-a", "t-a", "evt-4") == "duplicate"
    with db.connect() as admin:
        row = admin.execute("SELECT count(*) FROM alert WHERE event_id = 'evt-4'").fetchone()
    assert row == (1,)


def test_same_event_id_from_two_sources_is_two_alerts(db: TestDb) -> None:
    two_clients(db)
    with db.connect("soc_ingest") as c:
        assert ingest(c, "src-a", "t-a", "shared") == "inserted"
        assert ingest(c, "src-b", "t-b", "shared") == "inserted"


def test_ingest_ignores_the_session_client_setting(db: TestDb) -> None:
    a, b = two_clients(db)
    with db.connect("soc_ingest") as c:
        c.execute("SELECT set_config('app.client_id', %s, false)", (b,))
        assert ingest(c, "src-a", "t-a", "evt-5") == "inserted"
    with db.connect() as admin:
        row = admin.execute("SELECT client_id FROM alert WHERE event_id = 'evt-5'").fetchone()
    assert row is not None and str(row[0]) == a


def test_ingest_truncates_long_text_and_rejects_bad_input(db: TestDb) -> None:
    two_clients(db)
    long_text = "x" * 5000
    with db.connect("soc_ingest") as c:
        out = c.execute(
            "SELECT ingest_alert('src-a', 't-a', 'evt-6', %s, 'bogus', %s, %s, %s, now(), '{}')",
            (long_text, long_text, long_text, long_text),
        ).fetchone()
        assert out == ("inserted",)
        assert ingest(c, "src-a", "t-a", "") == "invalid_event_id"
        assert ingest(c, "src-a", "t-a", "e" * 257) == "invalid_event_id"
        big = json.dumps({"pad": "p" * 300_000})
        assert ingest(c, "src-a", "t-a", "evt-7", big) == "invalid_payload"
    with db.connect() as admin:
        row = admin.execute(
            "SELECT char_length(rule), char_length(summary), char_length(actor), "
            "char_length(mitre_hint), severity FROM alert WHERE event_id = 'evt-6'"
        ).fetchone()
        assert row == (256, 2000, 512, 256, "medium")
        assert count(admin, "alert") == 3  # two seed alerts + evt-6


def test_table_checks_back_up_the_function(db: TestDb) -> None:
    """Even the owner cannot store an oversize field: the CHECK is the backstop."""
    two_clients(db)
    with db.connect() as admin:
        src = admin.execute("SELECT id, client_id FROM source WHERE slug = 'src-a'").fetchone()
        assert src is not None
        with pytest.raises(psycopg.errors.CheckViolation):
            admin.execute(
                "INSERT INTO alert (client_id, source_id, event_id, summary, raw) "
                "VALUES (%s, %s, %s, %s, '{}')",
                (src[1], src[0], str(uuid.uuid4()), "y" * 2001),
            )


# ---- who ingest_alert() runs as ----


def test_ingest_function_runs_as_a_least_privileged_role(db: TestDb) -> None:
    """The definer is soc_ingest_writer, never the (possibly superuser) owner."""
    with db.connect() as c:
        owner = c.execute(
            "SELECT r.rolname, r.rolsuper, r.rolbypassrls, r.rolcanlogin "
            "FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner WHERE p.proname = 'ingest_alert'"
        ).fetchone()
        owned = c.execute(
            "SELECT count(*) FROM pg_class WHERE relowner = 'soc_ingest_writer'::regrole"
        ).fetchone()
        privileges = {
            table: c.execute(
                "SELECT has_table_privilege('soc_ingest_writer', %s, 'SELECT'), "
                "has_table_privilege('soc_ingest_writer', %s, 'INSERT'), "
                "has_table_privilege('soc_ingest_writer', %s, 'UPDATE')",
                (table, table, table),
            ).fetchone()
            for table in ALL_TABLES
        }
    assert owner == ("soc_ingest_writer", False, False, False)
    assert owned == (0,)
    assert privileges.pop("source") == (True, False, False)
    assert privileges.pop("alert") == (False, True, False)
    assert all(p == (False, False, False) for p in privileges.values())


def test_ingest_writer_cannot_attribute_an_alert_to_another_client(db: TestDb) -> None:
    """The insert policy holds even if the function's attribution logic breaks."""
    _, b = two_clients(db)
    with db.connect() as c:
        src = c.execute("SELECT id FROM source WHERE slug = 'src-a'").fetchone()
        assert src is not None
        c.execute("SET ROLE soc_ingest_writer")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(
                "INSERT INTO alert (client_id, source_id, event_id, raw) "
                "VALUES (%s, %s, 'crossed', '{}')",
                (b, src[0]),
            )
        c.execute(
            "INSERT INTO alert (client_id, source_id, event_id, raw) "
            "VALUES (%s, %s, 'parked', '{}')",
            (UNASSIGNED, src[0]),
        )


# ---- migrations without a superuser ----

SERVICE_ROLES = ("soc_app", "soc_ingest", "soc_ingest_writer")


def _admin_params() -> dict[str, str]:
    url = os.environ.get("SOC_TEST_DATABASE_URL")
    if not url:
        if os.environ.get("SOC_REQUIRE_DB"):
            pytest.fail("SOC_REQUIRE_DB is set but SOC_TEST_DATABASE_URL is not")
        pytest.skip("SOC_TEST_DATABASE_URL not set")
    return {k: str(v) for k, v in conninfo_to_dict(url).items() if v is not None}


def test_migrations_run_as_a_non_superuser_owner() -> None:
    """The deploy owner needs CREATEROLE, not SUPERUSER, and ingest works after."""
    params = _admin_params()
    suffix = uuid.uuid4().hex[:12]
    owner, name = f"soc_owner_{suffix}", f"soc_test_{suffix}"
    admin_info = make_conninfo(**params)
    with psycopg.connect(admin_info, autocommit=True) as admin:
        for role in SERVICE_ROLES:  # exercise the create path, not the "already there" one
            admin.execute(f"DROP ROLE IF EXISTS {role}")
        admin.execute(
            f"CREATE ROLE {owner} LOGIN CREATEROLE NOSUPERUSER PASSWORD '{ROLE_PASSWORD}'"
        )
        admin.execute(f'CREATE DATABASE "{name}" OWNER {owner}')
    test_db = TestDb(name=name, params=params)
    url = test_db.sqlalchemy_url(owner, ROLE_PASSWORD)
    try:
        soc_db.upgrade(url)
        soc_db.downgrade(url, "base")
        soc_db.upgrade(url)
        with test_db.connect() as c:
            c.execute(
                "INSERT INTO source (client_id, slug, type) VALUES (%s, 's', 'edr')", (UNASSIGNED,)
            )
            c.execute(f"ALTER ROLE soc_ingest LOGIN PASSWORD '{ROLE_PASSWORD}'")
        with test_db.connect("soc_ingest") as c:
            assert ingest(c, "s", "t", "e") == "inserted"
            assert ingest(c, "s", "t", "e") == "duplicate"
    finally:
        with psycopg.connect(admin_info, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            for role in (*SERVICE_ROLES, owner):
                admin.execute(f"DROP ROLE IF EXISTS {role}")


@pytest.mark.parametrize("attribute", ["SUPERUSER", "BYPASSRLS", "CREATEROLE", "CREATEDB"])
@pytest.mark.parametrize("role", ["soc_app", "soc_ingest"])
def test_a_privileged_existing_role_stops_the_migration(
    db: TestDb, role: str, attribute: str
) -> None:
    """Roles outlive databases; a privileged leftover must not be reused silently."""
    params = _admin_params()
    name = f"soc_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(make_conninfo(**params), autocommit=True) as admin:
        admin.execute(f"ALTER ROLE {role} {attribute}")
        admin.execute(f'CREATE DATABASE "{name}"')
        try:
            with pytest.raises(sqlalchemy.exc.ProgrammingError, match="must not have"):
                soc_db.upgrade(TestDb(name=name, params=params).sqlalchemy_url())
        finally:
            admin.execute(f"ALTER ROLE {role} NO{attribute}")
            admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


def test_a_writer_role_that_can_log_in_stops_the_migration(db: TestDb) -> None:
    params = _admin_params()
    name = f"soc_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(make_conninfo(**params), autocommit=True) as admin:
        admin.execute("ALTER ROLE soc_ingest_writer LOGIN")
        admin.execute(f'CREATE DATABASE "{name}"')
        try:
            with pytest.raises(sqlalchemy.exc.ProgrammingError, match="must not have"):
                soc_db.upgrade(TestDb(name=name, params=params).sqlalchemy_url())
        finally:
            admin.execute("ALTER ROLE soc_ingest_writer NOLOGIN")
            admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
