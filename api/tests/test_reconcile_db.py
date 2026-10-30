"""Reconcile (migration 0006): the database side of the catch-up worker.

Real Postgres, real reconcile login. What matters: the login reaches nothing but a few
functions; a detection delivered by the webhook and again by reconcile is stored once,
whichever came first; the cursor only moves forward, never into the future, and a
failure never moves it.
"""

import json
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from conftest import TestDb
from test_schema import ALL_TABLES, UNASSIGNED
from test_worker_db import WORKER_FUNCTIONS, Fixture

from soc_api import db as soc_db

RECONCILE_FUNCTIONS = [
    "reconcile_cursor_get(text)",
    "reconcile_cursor_advance(text, timestamptz)",
    "reconcile_cursor_fail(text, text)",
]
LOGINS = ("soc_app", "soc_ingest", "soc_worker", "soc_console")


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def ago(**kwargs: float) -> datetime:
    return datetime.now(UTC) - timedelta(**kwargs)


def deliver(fx: Fixture, role: str, event: str, source: str = "src-a", tenant: str = "t-a") -> Any:
    with fx.db.connect(role) as c:
        row = c.execute(
            "SELECT ingest_alert(%s, %s, %s, 'general.Rule', 'low', 's', 'a', NULL, now(), "
            "%s::jsonb)",
            (source, tenant, event, json.dumps({"cat": "CAT_ONE"})),
        ).fetchone()
    assert row is not None
    return row[0]


def get(fx: Fixture, source: str = "src-a") -> Any:
    with fx.db.connect("soc_reconcile") as c:
        row = c.execute("SELECT reconcile_cursor_get(%s)", (source,)).fetchone()
    assert row is not None
    return row[0]


def advance(fx: Fixture, when: datetime | None, source: str = "src-a") -> Any:
    with fx.db.connect("soc_reconcile") as c:
        row = c.execute("SELECT reconcile_cursor_advance(%s, %s)", (source, when)).fetchone()
    assert row is not None
    return row[0]


def fail(fx: Fixture, code: str | None, source: str = "src-a") -> None:
    with fx.db.connect("soc_reconcile") as c:
        c.execute("SELECT reconcile_cursor_fail(%s, %s)", (source, code))


def state(fx: Fixture, source: str = "src-a") -> tuple[Any, ...] | None:
    return fx.one(
        "SELECT c.window_end, c.last_success, c.last_error FROM reconcile_cursor c "
        "JOIN source s ON s.id = c.source_id WHERE s.slug = %s",
        (source,),
    )


def alerts(fx: Fixture) -> int:
    return int(fx.one("SELECT count(*) FROM alert")[0])


# ---- what the reconcile login can and cannot do ----


@pytest.mark.parametrize("table", [*ALL_TABLES, "worker_state", "reconcile_cursor"])
def test_the_reconcile_login_cannot_read_or_write_any_table(fx: Fixture, table: str) -> None:
    with fx.db.connect("soc_reconcile") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"SELECT * FROM {table}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"DELETE FROM {table}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"INSERT INTO {table} DEFAULT VALUES")


def test_the_reconcile_login_cannot_create_objects_or_change_roles(fx: Fixture) -> None:
    with fx.db.connect("soc_reconcile") as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("CREATE TABLE t (x int)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("ALTER ROLE soc_reconcile SUPERUSER")


def test_the_reconcile_roles_hold_no_server_privileges(fx: Fixture) -> None:
    for role in ("soc_reconcile", "soc_reconcile_writer"):
        row = fx.one(
            "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles "
            "WHERE rolname = %s",
            (role,),
        )
        assert row == (False, False, False, False), role
    assert fx.one("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'soc_reconcile_writer'") == (
        False,
    )


def test_the_reconcile_login_can_call_only_its_own_functions_and_the_webhooks(fx: Fixture) -> None:
    """Every SECURITY DEFINER function it may execute, by name; nothing else."""
    rows = fx.rows(
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'public' AND p.prosecdef "
        "AND has_function_privilege('soc_reconcile', p.oid, 'EXECUTE')"
    )
    assert {r[0] for r in rows} == {
        "ingest_alert",
        "reconcile_cursor_get",
        "reconcile_cursor_advance",
        "reconcile_cursor_fail",
    }


def test_nobody_else_can_call_the_reconcile_functions(fx: Fixture) -> None:
    for role in (*LOGINS, "public"):
        for function in RECONCILE_FUNCTIONS:
            allowed = fx.one(
                "SELECT has_function_privilege(%s, %s::regprocedure, 'EXECUTE')", (role, function)
            )
            assert allowed == (False,), f"{role} can execute {function}"
    with fx.db.connect("soc_reconcile") as c:
        for function in WORKER_FUNCTIONS:
            assert c.execute(
                "SELECT has_function_privilege('soc_reconcile', %s::regprocedure, 'EXECUTE')",
                (function,),
            ).fetchone() == (False,), function


def test_the_reconcile_functions_pin_the_search_path_and_run_as_the_writer(fx: Fixture) -> None:
    for function in RECONCILE_FUNCTIONS:
        row = fx.one(
            "SELECT p.prosecdef, p.proconfig, r.rolname, r.rolsuper, r.rolbypassrls, "
            "r.rolcanlogin FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
            "WHERE p.oid = %s::regprocedure",
            (function,),
        )
        assert row is not None, function
        definer, config, owner, superuser, bypass, login = row
        assert definer and owner == "soc_reconcile_writer", function
        assert not (superuser or bypass or login), function
        assert config and any(x.startswith("search_path=pg_catalog") for x in config)


def test_the_writer_owns_no_tables_and_holds_only_what_it_needs(fx: Fixture) -> None:
    def table_rights(table: str) -> tuple[bool, ...]:
        return tuple(
            bool(
                fx.one("SELECT has_table_privilege('soc_reconcile_writer', %s, %s)", (table, p))[0]
            )
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
        )

    def source_column(col: str) -> bool:
        return bool(
            fx.one(
                "SELECT has_column_privilege('soc_reconcile_writer', 'source', %s, 'SELECT')",
                (col,),
            )[0]
        )

    assert fx.one(
        "SELECT count(*) FROM pg_class WHERE relowner = 'soc_reconcile_writer'::regrole"
    ) == (0,)
    assert table_rights("reconcile_cursor") == (True, True, True, False)
    for table in [*ALL_TABLES, "worker_state"]:
        assert table_rights(table) == (False, False, False, False), table
    # a source can be found by its slug; nothing else about it can be read
    assert [source_column(c) for c in ("id", "slug", "enabled")] == [True, True, True]
    assert not any(source_column(c) for c in ("client_id", "type", "external_id", "secret_ref"))


# ---- the same insert as the webhook, so the two paths cannot double up ----


def test_a_detection_the_webhook_stored_is_a_duplicate_for_reconcile(fx: Fixture) -> None:
    assert deliver(fx, "soc_ingest", "ev-1") == "inserted"
    assert deliver(fx, "soc_reconcile", "ev-1") == "duplicate"
    assert alerts(fx) == 1


def test_a_detection_reconcile_stored_is_a_duplicate_for_the_webhook(fx: Fixture) -> None:
    assert deliver(fx, "soc_reconcile", "ev-1") == "inserted"
    assert deliver(fx, "soc_ingest", "ev-1") == "duplicate"
    assert deliver(fx, "soc_reconcile", "ev-1") == "duplicate"
    assert alerts(fx) == 1


def test_the_same_event_id_on_another_source_is_a_separate_alert(fx: Fixture) -> None:
    assert deliver(fx, "soc_reconcile", "ev-1", "src-a", "t-a") == "inserted"
    assert deliver(fx, "soc_reconcile", "ev-1", "src-b", "t-b") == "inserted"
    assert alerts(fx) == 2


def test_reconcile_attributes_an_alert_like_the_webhook_does(fx: Fixture) -> None:
    assert deliver(fx, "soc_reconcile", "ev-mine", "src-a", "t-a") == "inserted"
    assert deliver(fx, "soc_reconcile", "ev-other", "src-a", "t-somebody-else") == "inserted"
    clients = dict(fx.rows("SELECT event_id, client_id FROM alert"))
    assert str(clients["ev-mine"]) == fx.clients["a"]
    assert str(clients["ev-other"]) == UNASSIGNED


def test_reconcile_cannot_store_an_alert_for_an_unknown_source(fx: Fixture) -> None:
    assert deliver(fx, "soc_reconcile", "ev-1", "no-such-source") == "unknown_source"
    assert alerts(fx) == 0


# ---- the cursor ----


def test_there_is_no_cursor_until_the_first_good_run(fx: Fixture) -> None:
    assert get(fx) is None and get(fx, "src-b") is None and get(fx, "no-such-source") is None
    assert state(fx) is None


def test_advance_sets_the_cursor_and_the_success_time(fx: Fixture) -> None:
    when = ago(minutes=5)
    assert advance(fx, when) == when and get(fx) == when
    window_end, last_success, last_error = state(fx) or (None, None, "missing")
    assert window_end == when and last_success is not None and last_error is None


def test_advance_moves_forward(fx: Fixture) -> None:
    first, second = ago(minutes=10), ago(minutes=5)
    advance(fx, first)
    assert advance(fx, second) == second and get(fx) == second


def test_advance_never_moves_backwards(fx: Fixture) -> None:
    latest = ago(minutes=5)
    advance(fx, latest)
    assert advance(fx, ago(hours=3)) == latest  # a late or repeated call changes nothing
    assert advance(fx, latest) == latest
    assert get(fx) == latest


def test_advance_accepts_a_little_clock_skew_but_not_the_future(fx: Fixture) -> None:
    soon = datetime.now(UTC) + timedelta(seconds=30)
    assert advance(fx, soon) == soon
    with pytest.raises(psycopg.errors.RaiseException, match="bad window end"):
        advance(fx, datetime.now(UTC) + timedelta(hours=2), "src-b")
    assert get(fx, "src-b") is None and state(fx, "src-b") is None


def test_advance_refuses_a_missing_time(fx: Fixture) -> None:
    with pytest.raises(psycopg.errors.RaiseException, match="bad window end"):
        advance(fx, None)
    assert state(fx) is None


def test_advance_refuses_an_unknown_or_disabled_source(fx: Fixture) -> None:
    with pytest.raises(psycopg.errors.RaiseException, match="unknown source"):
        advance(fx, ago(minutes=1), "no-such-source")
    advance(fx, ago(minutes=1), "src-b")
    fx.run("UPDATE source SET enabled = false WHERE slug = 'src-b'")
    with pytest.raises(psycopg.errors.RaiseException, match="unknown source"):
        advance(fx, ago(minutes=1), "src-b")
    assert get(fx, "src-b") is None  # a disabled source has no cursor to read
    assert fx.one("SELECT count(*) FROM reconcile_cursor") == (1,)


def test_each_source_has_its_own_cursor(fx: Fixture) -> None:
    when = ago(minutes=5)
    advance(fx, when, "src-a")
    assert get(fx, "src-a") == when and get(fx, "src-b") is None
    other = ago(minutes=2)
    advance(fx, other, "src-b")
    assert get(fx, "src-a") == when and get(fx, "src-b") == other


def test_a_failure_is_recorded_without_moving_the_cursor(fx: Fixture) -> None:
    when = ago(minutes=5)
    advance(fx, when)
    success = (state(fx) or ())[1]
    fail(fx, "http_503")
    assert state(fx) == (when, success, "http_503")
    assert get(fx) == when


def test_a_later_good_run_clears_the_error(fx: Fixture) -> None:
    advance(fx, ago(minutes=10))
    fail(fx, "http_503")
    later = ago(minutes=1)
    advance(fx, later)
    window_end, _, last_error = state(fx) or (None, None, "missing")
    assert window_end == later and last_error is None


def test_a_failure_before_any_good_run_leaves_the_cursor_empty(fx: Fixture) -> None:
    fail(fx, "no_token")
    assert state(fx) == (None, None, "no_token")
    assert get(fx) is None
    when = ago(minutes=1)
    advance(fx, when)
    assert state(fx) is not None and get(fx) == when


def test_a_failure_for_an_unknown_source_is_refused(fx: Fixture) -> None:
    with pytest.raises(psycopg.errors.RaiseException, match="unknown source"):
        fail(fx, "http_503", "no-such-source")


@pytest.mark.parametrize(
    ("given", "stored"),
    [
        ("x" * 100, "x" * 40),
        ("bad\nline <b>", "bad?line ?b?"),
        ("", "unknown"),
        (None, "unknown"),
        ("http_503", "http_503"),
    ],
)
def test_the_failure_text_is_cleaned_and_cut(fx: Fixture, given: str | None, stored: str) -> None:
    fail(fx, given)
    assert (state(fx) or (None, None, "missing"))[2] == stored


def test_the_failure_text_never_keeps_control_or_bidi_characters(fx: Fixture) -> None:
    fail(fx, "a‮b⁦c\td\re")
    stored = (state(fx) or (None, None, ""))[2]
    assert stored == "a?b?c?d?e"


def test_concurrent_advances_end_at_the_latest_time(fx: Fixture) -> None:
    times = [ago(minutes=30 - n) for n in range(8)]
    errors: list[BaseException] = []

    def run(when: datetime) -> None:
        try:
            advance(fx, when)
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(t,)) for t in times]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert get(fx) == max(times)
    assert fx.one("SELECT count(*) FROM reconcile_cursor") == (1,)


# ---- the migration itself ----


def test_downgrading_removes_it_all_and_the_migration_applies_again(
    db: TestDb, fx: Fixture
) -> None:
    advance(fx, ago(minutes=1))
    soc_db.downgrade(db.sqlalchemy_url(), "0005")
    with db.connect() as c:
        assert c.execute("SELECT to_regclass('public.reconcile_cursor')").fetchone() == (None,)
        for function in RECONCILE_FUNCTIONS:
            assert c.execute("SELECT to_regprocedure(%s)", (function,)).fetchone() == (None,)
        assert c.execute(
            "SELECT has_function_privilege('soc_reconcile', 'ingest_alert'::regproc, 'EXECUTE')"
        ).fetchone() == (False,)
        assert c.execute(
            "SELECT count(*) FROM pg_policies WHERE policyname LIKE 'reconcile_%'"
        ).fetchone() == (0,)
        assert c.execute(
            "SELECT has_column_privilege('soc_reconcile_writer', 'source', 'slug', 'SELECT')"
        ).fetchone() == (False,)
    soc_db.upgrade(db.sqlalchemy_url())
    with db.connect("soc_reconcile") as c:
        assert c.execute("SELECT reconcile_cursor_get('src-a')").fetchone() == (None,)
