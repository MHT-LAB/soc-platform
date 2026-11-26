"""Migration 0011: the database side of the posture collector, and its STALE signal.

Real Postgres, real soc_posture login. What matters: the login reaches nothing but two write
functions; the document is validated in SQL and an invalid one writes nothing; the current
state is replaced in one transaction and the series are pruned to 30 days; the worker and the
console learn how long the collector has been quiet, and a host that never ran it is never
flagged.
"""

import json
from typing import Any

import psycopg
import pytest
from conftest import TestDb
from test_schema import ALL_TABLES
from test_worker_db import WORKER_FUNCTIONS, Fixture

from soc_api import db as soc_db

POSTURE_FUNCTIONS = ["posture_record(jsonb)", "posture_fail(text)"]
POSTURE_TABLES = ["posture_run", "sensor_state", "sensor_count", "rule_inventory"]
LOGINS = ("soc_app", "soc_ingest", "soc_worker", "soc_console", "soc_reconcile")
SID = "aaaaaaaa-0000-4000-8000-00000000000"


def sensor(n: int = 1, **over: Any) -> dict[str, Any]:
    return {
        "sid": f"{SID}{n}",
        "hostname": f"host-{n}",
        "platform": "Linux",
        "version": "4.1.2",
        "online": True,
        "isolated": False,
        "tags": ["lab"],
        "last_seen_s": 1_700_000_000,
        **over,
    }


def doc(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "sensors": [sensor(1), sensor(2, online=False)],
        "rules": [{"namespace": "general", "name": "Rule One", "enabled": True}],
        "org_errors": {"count": 0, "newest": None},
    }
    return {**base, **over}


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def record(fx: Fixture, document: Any) -> None:
    with fx.db.connect("soc_posture") as c:
        c.execute("SELECT posture_record(%s::jsonb)", (json.dumps(document),))


def fail(fx: Fixture, code: str | None) -> None:
    with fx.db.connect("soc_posture") as c:
        c.execute("SELECT posture_fail(%s)", (code,))


def health(fx: Fixture) -> tuple[Any, ...]:
    with fx.worker() as w:
        row = w.execute("SELECT * FROM posture_health()").fetchone()
    assert row is not None
    return row


def runs(fx: Fixture) -> list[tuple[Any, ...]]:
    return fx.rows("SELECT ok, error, org_error_count, org_error_component FROM posture_run")


def age_runs(fx: Fixture, minutes: float, *, only_ok: bool | None = None) -> None:
    where = "" if only_ok is None else f"WHERE ok = {only_ok}"
    fx.run(
        f"UPDATE posture_run SET at = at - make_interval(secs => %s) {where}",  # noqa: S608
        (minutes * 60,),
    )


# ---- what the posture login can and cannot do ----


@pytest.mark.parametrize(
    "table", [*ALL_TABLES, "worker_state", "reconcile_cursor", *POSTURE_TABLES]
)
def test_the_posture_login_cannot_read_or_write_any_table(fx: Fixture, table: str) -> None:
    with fx.db.connect("soc_posture") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"SELECT * FROM {table}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"DELETE FROM {table}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"INSERT INTO {table} DEFAULT VALUES")


def test_the_posture_roles_hold_no_server_privileges(fx: Fixture) -> None:
    for role in ("soc_posture", "soc_posture_writer"):
        row = fx.one(
            "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles "
            "WHERE rolname = %s",
            (role,),
        )
        assert row == (False, False, False, False), role
    assert fx.one("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'soc_posture_writer'") == (
        False,
    )
    with fx.db.connect("soc_posture") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("CREATE TABLE t (x int)")


def test_the_posture_login_can_call_only_its_two_functions(fx: Fixture) -> None:
    rows = fx.rows(
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'public' AND p.prosecdef "
        "AND has_function_privilege('soc_posture', p.oid, 'EXECUTE')"
    )
    assert {r[0] for r in rows} == {"posture_record", "posture_fail"}
    for function in WORKER_FUNCTIONS:
        assert fx.one(
            "SELECT has_function_privilege('soc_posture', %s::regprocedure, 'EXECUTE')",
            (function,),
        ) == (False,), function


def test_nobody_else_can_call_the_posture_write_functions(fx: Fixture) -> None:
    for role in (*LOGINS, "public"):
        for function in POSTURE_FUNCTIONS:
            assert fx.one(
                "SELECT has_function_privilege(%s, %s::regprocedure, 'EXECUTE')", (role, function)
            ) == (False,), f"{role} can execute {function}"


def test_the_functions_pin_the_search_path_and_run_as_the_right_owner(fx: Fixture) -> None:
    for function, owner in (
        ("posture_record(jsonb)", "soc_posture_writer"),
        ("posture_fail(text)", "soc_posture_writer"),
        ("posture_health()", "soc_worker_writer"),
    ):
        row = fx.one(
            "SELECT p.prosecdef, p.proconfig, r.rolname, r.rolsuper, r.rolbypassrls, "
            "r.rolcanlogin FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
            "WHERE p.oid = %s::regprocedure",
            (function,),
        )
        assert row is not None, function
        definer, config, who, superuser, bypass, login = row
        assert definer and who == owner and not (superuser or bypass or login), function
        assert config and any(x.startswith("search_path=pg_catalog") for x in config)


def test_every_posture_table_has_row_level_security_and_the_writer_owns_nothing(
    fx: Fixture,
) -> None:
    for table in POSTURE_TABLES:
        assert fx.one("SELECT relrowsecurity FROM pg_class WHERE oid = %s::regclass", (table,)) == (
            True,
        ), table
    assert fx.one(
        "SELECT count(*) FROM pg_class WHERE relowner = 'soc_posture_writer'::regrole"
    ) == (0,)


def test_the_writers_hold_only_what_they_need(fx: Fixture) -> None:
    def table_rights(role: str, table: str) -> tuple[bool, ...]:
        return tuple(
            bool(fx.one("SELECT has_table_privilege(%s, %s, %s)", (role, table, p))[0])
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
        )

    assert table_rights("soc_posture_writer", "sensor_state") == (True, True, True, True)
    assert table_rights("soc_posture_writer", "rule_inventory") == (True, True, True, True)
    assert table_rights("soc_posture_writer", "sensor_count") == (True, True, False, True)
    assert table_rights("soc_posture_writer", "posture_run") == (True, True, False, True)
    # the worker's and the console's writers see two columns of the run table, nothing else
    # (the console's writer also reads the org error count, the fleet and the rule inventory
    # since 0012, for the Ops Overview, and nothing else: see test_ops_overview_db)
    for role in ("soc_worker_writer", "soc_console_writer"):
        tables = ("sensor_state", "sensor_count", "rule_inventory")
        for table in tables if role == "soc_worker_writer" else ("sensor_count",):
            assert table_rights(role, table) == (False,) * 4, (role, table)
        assert table_rights(role, "posture_run") == (False,) * 4  # table level: none
        for column, expected in (
            ("at", True),
            ("ok", True),
            ("error", False),
            ("org_error_count", role == "soc_console_writer"),
            ("org_error_component", False),
        ):
            assert fx.one(
                "SELECT has_column_privilege(%s, 'posture_run', %s, 'SELECT')", (role, column)
            ) == (expected,), (role, column)
    # and the writer cannot see the sources or any case data
    for table in ("source", "alert", "soc_case", "client"):
        assert table_rights("soc_posture_writer", table) == (False,) * 4, table


# ---- the write path ----


def test_a_good_document_replaces_the_current_state_and_adds_one_point(fx: Fixture) -> None:
    record(fx, doc())
    assert fx.rows(
        "SELECT hostname, online, isolated, tags, platform FROM sensor_state ORDER BY 1"
    ) == [
        ("host-1", True, False, ["lab"], "Linux"),
        ("host-2", False, False, ["lab"], "Linux"),
    ]
    assert fx.rows("SELECT online, offline, isolated FROM sensor_count") == [(1, 1, 0)]
    assert fx.rows("SELECT namespace, name, enabled FROM rule_inventory") == [
        ("general", "Rule One", True)
    ]
    assert runs(fx) == [(True, None, 0, None)]


def test_a_sensor_going_offline_changes_the_row_and_the_series(fx: Fixture) -> None:
    record(fx, doc())
    record(fx, doc(sensors=[sensor(1, online=False), sensor(2, online=False)]))
    assert fx.rows("SELECT hostname, online FROM sensor_state ORDER BY 1") == [
        ("host-1", False),
        ("host-2", False),
    ]
    assert fx.rows("SELECT online, offline FROM sensor_count ORDER BY at, online DESC") == [
        (1, 1),
        (0, 2),
    ]


def test_a_removed_sensor_and_a_removed_rule_disappear_from_the_current_state(
    fx: Fixture,
) -> None:
    record(fx, doc())
    record(fx, doc(sensors=[sensor(1)], rules=[]))
    assert fx.rows("SELECT hostname FROM sensor_state") == [("host-1",)]
    assert fx.rows("SELECT name FROM rule_inventory") == []
    assert fx.one("SELECT count(*) FROM sensor_count") == (2,)  # the series keeps its history


def test_the_counts_are_computed_from_the_list_not_taken_from_the_caller(fx: Fixture) -> None:
    record(fx, doc(sensors=[sensor(1, isolated=True), sensor(2), sensor(3, online=False)]))
    assert fx.rows("SELECT online, offline, isolated FROM sensor_count") == [(2, 1, 1)]


def test_org_errors_keep_a_count_and_one_component_name(fx: Fixture) -> None:
    record(fx, doc(org_errors={"count": 7, "newest": "dr-general.rule_x"}))
    assert runs(fx) == [(True, None, 7, "dr-general.rule_x")]


def test_an_empty_fleet_is_a_valid_snapshot(fx: Fixture) -> None:
    record(fx, doc(sensors=[], rules=[]))
    assert fx.rows("SELECT online, offline, isolated FROM sensor_count") == [(0, 0, 0)]


def sensor_without(key: str) -> dict[str, Any]:
    s = sensor()
    del s[key]
    return s


@pytest.mark.parametrize(
    "bad",
    [
        "not an object",
        [],
        {},
        doc(sensors="x"),
        doc(rules={}),
        doc(org_errors=[]),
        doc(sensors=[sensor(1), sensor(1)]),  # duplicate id
        doc(sensors=["x"]),
        doc(sensors=[sensor(1, sid="short")]),
        doc(sensors=[sensor(1, sid="bad id with spaces!")]),
        doc(sensors=[sensor(1, sid=5)]),
        doc(sensors=[sensor(1, hostname="h" * 254)]),
        doc(sensors=[sensor(1, hostname=None)]),
        doc(sensors=[sensor(1, platform="p" * 41)]),
        doc(sensors=[sensor(1, version="v" * 41)]),
        doc(sensors=[sensor(1, online="yes")]),
        doc(sensors=[sensor(1, isolated=None)]),
        doc(sensors=[sensor(1, tags="lab")]),
        doc(sensors=[sensor(1, tags=["t"] * 21)]),
        doc(sensors=[sensor(1, tags=[5])]),
        doc(sensors=[sensor(1, tags=["x" * 65])]),
        doc(sensors=[sensor(1, last_seen_s="soon")]),
        doc(sensors=[sensor(1, last_seen_s=-5)]),
        doc(sensors=[sensor_without("online")]),
        doc(rules=[{"namespace": "general", "name": "", "enabled": True}]),
        doc(rules=[{"namespace": "Bad NS", "name": "r", "enabled": True}]),
        doc(rules=[{"namespace": "general", "name": "r" * 256, "enabled": True}]),
        doc(rules=[{"namespace": "general", "name": "r", "enabled": "true"}]),
        doc(rules=[{"namespace": "general", "name": "r", "enabled": True}] * 2),
        doc(org_errors={"count": -1, "newest": None}),
        doc(org_errors={"count": "3", "newest": None}),
        doc(org_errors={"count": 1_000_000, "newest": None}),
        doc(org_errors={"count": 1, "newest": "has spaces and a long message text"}),
        doc(org_errors={"count": 1, "newest": "x" * 41}),
        doc(org_errors={"count": 1, "newest": 5}),
    ],
)
def test_an_invalid_document_is_refused_and_writes_nothing(fx: Fixture, bad: Any) -> None:
    record(fx, doc())  # something to keep
    before = {
        t: fx.rows(f"SELECT * FROM {t} ORDER BY 1, 2")  # noqa: S608 - fixed names
        for t in ("sensor_state", "rule_inventory", "sensor_count", "posture_run")
    }
    with pytest.raises(psycopg.errors.RaiseException):
        record(fx, bad)
    for table, rows in before.items():
        assert fx.rows(f"SELECT * FROM {table} ORDER BY 1, 2") == rows, table  # noqa: S608


def test_a_document_over_the_size_cap_is_refused(fx: Fixture) -> None:
    many = [sensor(1, sid=f"bbbbbbbb-0000-4000-8000-{n:012d}") for n in range(5001)]
    with pytest.raises(psycopg.errors.RaiseException):
        record(fx, doc(sensors=many))
    assert fx.one("SELECT count(*) FROM sensor_state") == (0,)


def test_a_half_bad_document_leaves_the_old_state_whole(fx: Fixture) -> None:
    record(fx, doc())
    with pytest.raises(psycopg.errors.RaiseException):
        record(fx, doc(sensors=[sensor(3), sensor(4, online="nope")], rules=[]))
    assert fx.rows("SELECT hostname FROM sensor_state ORDER BY 1") == [("host-1",), ("host-2",)]
    assert fx.one("SELECT count(*) FROM rule_inventory") == (1,)


def test_failures_are_recorded_as_short_clean_codes(fx: Fixture) -> None:
    fail(fx, "jwt_http_401")
    fail(fx, "a" * 80)
    fail(fx, "bad\x07text\nhere $(x)")
    fail(fx, None)
    fail(fx, "")
    assert [r[1] for r in runs(fx)] == [
        "jwt_http_401",
        "a" * 40,
        "bad?text?here ??x?",
        "unknown",
        "unknown",
    ]
    assert all(r[0] is False for r in runs(fx))
    assert fx.one("SELECT count(*) FROM sensor_state") == (0,)  # a failure touches nothing else


def test_a_failure_leaves_the_last_good_snapshot_in_place(fx: Fixture) -> None:
    record(fx, doc())
    fail(fx, "timeout")
    assert fx.one("SELECT count(*) FROM sensor_state") == (2,)
    assert fx.one("SELECT count(*) FROM sensor_count") == (1,)


def test_the_two_series_are_pruned_to_thirty_days_when_a_run_is_recorded(fx: Fixture) -> None:
    record(fx, doc())
    fx.run("UPDATE sensor_count SET at = now() - interval '31 days'")
    fx.run("UPDATE posture_run SET at = now() - interval '31 days'")
    fail(fx, "x")  # a failed run prunes too
    assert fx.one("SELECT count(*) FROM sensor_count") == (0,)
    assert fx.rows("SELECT error FROM posture_run") == [("x",)]
    record(fx, doc())
    fx.run("UPDATE sensor_count SET at = now() - interval '29 days' WHERE true")
    record(fx, doc())
    assert fx.one("SELECT count(*) FROM sensor_count") == (2,)  # 29 days old is kept


def test_current_state_is_not_pruned_by_age(fx: Fixture) -> None:
    record(fx, doc())
    fx.run("UPDATE sensor_state SET updated_at = now() - interval '90 days'")
    record(fx, doc(sensors=[sensor(1)], rules=[]))
    assert fx.one("SELECT count(*) FROM sensor_state") == (1,)


# ---- posture_health: what the pager worker sees ----


def test_with_no_run_at_all_nothing_is_reported_and_nothing_can_go_stale(fx: Fixture) -> None:
    assert health(fx) == (0, None)


def test_quiet_time_runs_from_the_last_good_run(fx: Fixture) -> None:
    record(fx, doc())
    age_runs(fx, 45)
    runs_, quiet = health(fx)
    assert runs_ == 1 and 2690 <= quiet <= 2720
    fail(fx, "timeout")  # a newer failure does not reset it
    assert 2690 <= health(fx)[1] <= 2720


def test_a_collector_that_only_ever_failed_is_quiet_since_its_first_attempt(fx: Fixture) -> None:
    fail(fx, "http_403")
    age_runs(fx, 90)
    fail(fx, "http_403")
    runs_, quiet = health(fx)
    assert runs_ == 2 and 5390 <= quiet <= 5420


def test_a_fresh_good_run_is_not_quiet(fx: Fixture) -> None:
    record(fx, doc())
    assert health(fx)[1] < 30


def test_health_reports_two_numbers_and_no_text(fx: Fixture) -> None:
    fail(fx, "secret-looking-text")
    with fx.worker() as w:
        cur = w.execute("SELECT * FROM posture_health()")
        names = [d.name for d in cur.description or []]
        rows = cur.fetchall()
    assert names == ["runs", "quiet_s"] and "secret-looking-text" not in repr(rows)


def test_only_the_worker_login_can_call_posture_health(fx: Fixture) -> None:
    for role in ("soc_app", "soc_ingest", "soc_console", "soc_reconcile", "soc_posture", "public"):
        assert fx.one(
            "SELECT has_function_privilege(%s, 'posture_health()'::regprocedure, 'EXECUTE')",
            (role,),
        ) == (False,), role
    with fx.db.connect("soc_posture") as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("SELECT * FROM posture_health()")


def test_the_worker_login_cannot_read_the_run_table(fx: Fixture) -> None:
    fail(fx, "x")
    with fx.worker() as w:
        for query in (
            "SELECT * FROM posture_run",
            "SELECT at FROM posture_run",
            "SELECT error FROM posture_run",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                w.execute(query)


# ---- console_health: the banner's numbers ----


def console_health(fx: Fixture) -> dict[str, Any]:
    with fx.db.connect("soc_console") as c:
        cur = c.execute("SELECT * FROM console_health()")
        names = [d.name for d in cur.description or []]
        row = cur.fetchone()
    assert row is not None
    return dict(zip(names, row, strict=True))


def test_console_health_keeps_its_columns_and_adds_four(fx: Fixture) -> None:
    names = list(console_health(fx))
    assert names == [
        "oldest_pending_page_s",
        "failed_last_24h",
        "oldest_unassigned_alert_s",
        "reconcile_sources",
        "reconcile_quiet_s",
        "backup_age_s",
        "posture_runs",
        "posture_quiet_s",
        "rules_drift",
        "reconcile_gap_s",
    ]


def test_console_health_sees_no_posture_run_until_there_is_one(fx: Fixture) -> None:
    h = console_health(fx)
    assert h["posture_runs"] == 0 and h["posture_quiet_s"] is None
    record(fx, doc())
    age_runs(fx, 50)
    h = console_health(fx)
    assert h["posture_runs"] == 1 and 2990 <= h["posture_quiet_s"] <= 3020


def test_the_console_login_cannot_read_the_run_table(fx: Fixture) -> None:
    fail(fx, "x")
    with fx.db.connect("soc_console") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM posture_run")


# ---- the migration itself ----


def definition(db: TestDb, function: str) -> str:
    with db.connect() as c:
        row = c.execute("SELECT pg_get_functiondef(%s::regprocedure)", (function,)).fetchone()
    assert row is not None
    return str(row[0])


def test_downgrading_restores_the_previous_console_health_and_removes_the_rest(
    db: TestDb, fx: Fixture
) -> None:
    record(fx, doc())
    url = db.sqlalchemy_url()
    soc_db.downgrade(url, "0010")
    with db.connect() as c:
        for table in POSTURE_TABLES:
            assert c.execute("SELECT to_regclass(%s)", (f"public.{table}",)).fetchone() == (None,)
        for function in (*POSTURE_FUNCTIONS, "posture_health()"):
            assert c.execute("SELECT to_regprocedure(%s)", (function,)).fetchone() == (None,)
        assert c.execute(
            "SELECT count(*) FROM pg_policies WHERE policyname IN "
            "('worker_posture_read') OR (policyname = 'console_health_read' "
            "AND tablename = 'posture_run')"
        ).fetchone() == (0,)
    after_downgrade = definition(db, "console_health()")
    assert "posture" not in after_downgrade
    with db.connect("soc_console") as c:
        row = c.execute("SELECT * FROM console_health()").fetchone()
        assert row is not None and len(row) == 6
    # ...and it is exactly what migration 0010 itself builds
    soc_db.downgrade(url, "0009")
    soc_db.upgrade(url, "0010")
    assert definition(db, "console_health()") == after_downgrade
    soc_db.upgrade(url)
    assert "posture_runs" in definition(db, "console_health()")
    with fx.db.connect("soc_posture") as c:
        c.execute("SELECT posture_fail('after the round trip')")


def test_an_unknown_error_count_is_stored_as_null_and_a_missing_one_is_still_refused(
    fx: Fixture,
) -> None:
    record(fx, doc(org_errors={"count": None, "newest": None}))
    assert runs(fx) == [(True, None, None, None)]
    for bad in ({"newest": None}, {"count": "3", "newest": None}, {"count": -1, "newest": None}):
        with pytest.raises(psycopg.errors.RaiseException):
            record(fx, doc(org_errors=bad))


def test_downgrading_0015_refuses_an_unknown_count_again(db: TestDb, fx: Fixture) -> None:
    url = db.sqlalchemy_url()
    soc_db.downgrade(url, "0014")
    try:
        with pytest.raises(psycopg.errors.RaiseException):
            record(fx, doc(org_errors={"count": None, "newest": None}))
        record(fx, doc())
    finally:
        soc_db.upgrade(url)
    record(fx, doc(org_errors={"count": None, "newest": None}))
