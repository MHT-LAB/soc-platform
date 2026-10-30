"""The console's database side (migration 0004): the case queue, one case, Ack and Close.

Real Postgres, real logins. soc_console has no table privileges; every behaviour here is
reached through its four functions. Cases and pages are made the way production makes
them: alerts through ingest_alert(), then assign_cases() as the worker calls it.
"""

import json
import threading
import time
from datetime import datetime
from typing import Any

import psycopg
import pytest
from conftest import TestDb
from test_schema import ALL_TABLES
from test_worker_db import Fixture

FUNCTIONS = [
    "list_cases(text, integer)",
    "get_case(uuid)",
    "ack_case(uuid, text)",
    "close_case(uuid, text, text)",
]
LOGIN = "operator@example.com"


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def console(fx: Fixture) -> psycopg.Connection:
    return fx.db.connect("soc_console")


def call(fx: Fixture, sql: str, *params: Any) -> Any:
    with console(fx) as c:
        row = c.execute(sql, params).fetchone()
    assert row is not None
    return row[0] if len(row) == 1 else row


def listing(fx: Fixture, *params: Any) -> list[dict[str, Any]]:
    with console(fx) as c, c.cursor() as cur:
        cur.execute("SELECT * FROM list_cases(%s, %s)", params or ("active", 100))
        names = [d.name for d in cur.description or []]
        return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]


def ack(fx: Fixture, case: Any, login: str | None = LOGIN) -> str:
    return str(call(fx, "SELECT ack_case(%s, %s)", case, login))


def close(
    fx: Fixture, case: Any, note: str | None = "my own test", login: str | None = LOGIN
) -> str:
    return str(call(fx, "SELECT close_case(%s, %s, %s)", case, login, note))


def case_ids(fx: Fixture) -> list[Any]:
    return [r[0] for r in fx.rows("SELECT id FROM soc_case ORDER BY opened_at, id")]


def one_case(fx: Fixture, **alert: Any) -> Any:
    fx.alert(**alert)
    fx.assign()
    return case_ids(fx)[-1]


def events(fx: Fixture, case: Any) -> list[tuple[Any, ...]]:
    return fx.rows(
        "SELECT actor, kind, body FROM case_event WHERE case_id = %s ORDER BY at, id", (case,)
    )


# ---- what the login can and cannot do ----


@pytest.mark.parametrize("table", [*ALL_TABLES, "worker_state", "reconcile_cursor"])
def test_the_console_login_cannot_read_or_write_any_table(fx: Fixture, table: str) -> None:
    one_case(fx)
    with console(fx) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"SELECT * FROM {table}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"DELETE FROM {table}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(f"INSERT INTO {table} DEFAULT VALUES")


def test_the_console_login_cannot_read_the_raw_payload_or_change_roles(fx: Fixture) -> None:
    one_case(fx)
    with console(fx) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT raw FROM alert")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("CREATE TABLE t (x int)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("ALTER ROLE soc_console SUPERUSER")


def test_only_the_console_can_call_the_console_functions(fx: Fixture) -> None:
    for role in ("soc_app", "soc_ingest", "soc_worker"):
        for function in FUNCTIONS:
            with fx.db.connect() as c:
                allowed = c.execute(
                    "SELECT has_function_privilege(%s, %s::regprocedure, 'EXECUTE')",
                    (role, function),
                ).fetchone()
            assert allowed == (False,), f"{role} can execute {function}"
    with fx.db.connect() as c:
        for function in FUNCTIONS:
            assert c.execute(
                "SELECT has_function_privilege('soc_console', %s::regprocedure, 'EXECUTE')",
                (function,),
            ).fetchone() == (True,)
        # and the console cannot call what belongs to the other services
        for function in ("assign_cases(integer, jsonb)", "claim_pages(integer)"):
            assert c.execute(
                "SELECT has_function_privilege('soc_console', %s::regprocedure, 'EXECUTE')",
                (function,),
            ).fetchone() == (False,)
        assert c.execute(
            "SELECT has_function_privilege('soc_console', "
            "'ingest_alert(text, text, text, text, text, text, text, text, timestamptz, jsonb)'"
            "::regprocedure, 'EXECUTE')"
        ).fetchone() == (False,)


def test_the_console_functions_pin_the_search_path_and_run_as_the_writer(fx: Fixture) -> None:
    with fx.db.connect() as c:
        for function in FUNCTIONS:
            row = c.execute(
                "SELECT p.prosecdef, p.proconfig, r.rolname, r.rolsuper, r.rolbypassrls, "
                "r.rolcanlogin FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
                "WHERE p.oid = %s::regprocedure",
                (function,),
            ).fetchone()
            assert row is not None, function
            definer, config, owner, superuser, bypass, login = row
            assert definer and owner == "soc_console_writer", function
            assert not (superuser or bypass or login), function
            assert config and any(x.startswith("search_path=pg_catalog") for x in config)


def test_the_assign_cases_function_kept_its_owner_and_settings(fx: Fixture) -> None:
    with fx.db.connect() as c:
        row = c.execute(
            "SELECT r.rolname, p.prosecdef, p.proconfig FROM pg_proc p "
            "JOIN pg_roles r ON r.oid = p.proowner WHERE p.proname = 'assign_cases'"
        ).fetchone()
        executors = c.execute(
            "SELECT has_function_privilege(%s, 'assign_cases(integer, jsonb)', 'EXECUTE'), "
            "has_function_privilege(%s, 'assign_cases(integer, jsonb)', 'EXECUTE'), "
            "has_function_privilege(%s, 'assign_cases(integer, jsonb)', 'EXECUTE')",
            ("soc_worker", "soc_console", "soc_ingest"),
        ).fetchone()
    assert row is not None and row[0] == "soc_worker_writer" and row[1] is True
    assert any(x.startswith("search_path=pg_catalog") for x in row[2])
    assert executors == (True, False, False)


def test_the_writer_holds_only_what_the_console_functions_need(fx: Fixture) -> None:
    def has(c: psycopg.Connection, sql: str, *args: str) -> bool:
        row = c.execute(sql, args).fetchone()
        assert row is not None
        return bool(row[0])

    with fx.db.connect() as c:
        owned = c.execute(
            "SELECT count(*) FROM pg_class WHERE relowner = 'soc_console_writer'::regrole"
        ).fetchone()
        grants = {
            t: tuple(
                has(c, "SELECT has_table_privilege('soc_console_writer', %s, %s)", t, p)
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
            )
            for t in [*ALL_TABLES, "worker_state", "reconcile_cursor"]
        }
        columns = {
            (t, col): has(
                c, "SELECT has_column_privilege('soc_console_writer', %s, %s, 'UPDATE')", t, col
            )
            for t, col in [
                ("soc_case", "status"),
                ("soc_case", "closed_at"),
                ("soc_case", "closing_note"),
                ("soc_case", "severity"),
                ("soc_case", "client_id"),
                ("soc_case", "opened_at"),
                ("notification", "acked_at"),
                ("notification", "status"),
                ("notification", "priority"),
                ("alert", "case_id"),
                ("alert", "raw"),
            ]
        }
    assert owned == (0,)
    select_only = (True, False, False, False)
    assert grants.pop("client") == select_only
    assert grants.pop("alert") == select_only
    # UPDATE shows as False here because it is granted by column only (checked below)
    assert grants.pop("soc_case") == select_only
    assert grants.pop("case_event") == (True, True, False, False)
    assert grants.pop("notification") == select_only
    assert all(g == (False, False, False, False) for g in grants.values())
    assert {k: v for k, v in columns.items() if v} == {
        ("soc_case", "status"): True,
        ("soc_case", "closed_at"): True,
        ("soc_case", "closing_note"): True,
        ("notification", "acked_at"): True,
    }


@pytest.mark.parametrize(
    "bad",
    [
        "INSERT INTO soc_case (client_id, severity, status) VALUES (%(c)s, 'low', 'archived')",
        "INSERT INTO soc_case (client_id, severity, status) VALUES (%(c)s, 'low', 'closed')",
        "INSERT INTO soc_case (client_id, severity, closed_at) VALUES (%(c)s, 'low', now())",
    ],
)
def test_the_case_table_refuses_unknown_states_and_a_close_time_without_closing(
    fx: Fixture, bad: str
) -> None:
    with fx.db.connect() as c, pytest.raises(psycopg.errors.CheckViolation):
        c.execute(bad, {"c": fx.clients["a"]})


# ---- the queue ----


def test_the_queue_shows_open_and_acknowledged_newest_first_and_not_closed(fx: Fixture) -> None:
    first = one_case(fx, host="h1", age_min=30)
    second = one_case(fx, host="h2", age_min=20)
    third = one_case(fx, host="h3", age_min=10)
    ack(fx, second)
    close(fx, third)
    got = listing(fx)
    assert [str(r["id"]) for r in got] == [str(second), str(first)]
    assert [r["status"] for r in got] == ["acknowledged", "open"]
    assert [str(r["id"]) for r in listing(fx, "closed", 100)] == [str(third)]
    assert [str(r["id"]) for r in listing(fx, "open", 100)] == [str(first)]
    assert [str(r["id"]) for r in listing(fx, "acknowledged", 100)] == [str(second)]
    assert {str(r["id"]) for r in listing(fx, "all", 100)} == {str(first), str(second), str(third)}


def test_the_queue_row_describes_the_case(fx: Fixture) -> None:
    fx.alert(rule="general.Rule One", host="host-1", age_min=20)
    fx.alert(rule="general.Rule One", host="host-1", age_min=5)
    fx.assign()
    case = case_ids(fx)[0]
    ack(fx, case, "Operator@Example.com")
    [row] = listing(fx)
    assert row["client_slug"] == "client-a" and row["severity"] == "low"
    assert row["alert_count"] == 2
    assert row["rule"] == "general.Rule One" and row["host"] == "host-1"
    assert row["acked_by"] == "operator@example.com"  # kept lower-case
    assert isinstance(row["acked_at"], datetime) and row["closed_at"] is None
    newest = fx.one("SELECT max(received_at) FROM alert")[0]
    assert row["last_alert_at"] == newest


def test_the_queue_spans_clients_because_the_console_is_a_staff_view(fx: Fixture) -> None:
    one_case(fx, source="a", host="h1")
    one_case(fx, source="b", host="h2")
    assert {r["client_slug"] for r in listing(fx)} == {"client-a", "client-b"}


def test_the_queue_limit_applies(fx: Fixture) -> None:
    for i in range(5):
        one_case(fx, host=f"h{i}", age_min=60 - i)
    assert len(listing(fx, "active", 3)) == 3


@pytest.mark.parametrize(
    "args",
    [("bogus", 10), (None, 10), ("active", 0), ("active", 501), ("active", None), ("active", -1)],
)
def test_the_queue_refuses_odd_arguments(fx: Fixture, args: tuple[Any, ...]) -> None:
    with console(fx) as c, pytest.raises(psycopg.errors.RaiseException):
        c.execute("SELECT * FROM list_cases(%s, %s)", args)


def test_an_empty_queue_is_an_empty_list(fx: Fixture) -> None:
    assert listing(fx) == []


# ---- one case ----


def get(fx: Fixture, case: Any) -> Any:
    return call(fx, "SELECT get_case(%s)", case)


def test_a_case_comes_with_its_alerts_newest_first_and_its_events(fx: Fixture) -> None:
    fx.alert(rule="general.Rule One", host="host-1", age_min=20, event="old")
    fx.alert(rule="general.Rule One", host="host-1", age_min=2, event="new")
    fx.assign()
    case = case_ids(fx)[0]
    ack(fx, case)
    doc = get(fx, case)
    assert doc["case"]["id"] == str(case) and doc["case"]["client_slug"] == "client-a"
    assert doc["case"]["status"] == "acknowledged" and doc["case"]["alert_count"] == 2
    assert [a["host"] for a in doc["alerts"]] == ["host-1", "host-1"]
    assert doc["alerts"][0]["received_at"] > doc["alerts"][1]["received_at"]
    assert doc["alerts"][0]["link"] and doc["alerts"][0]["rule"] == "general.Rule One"
    assert [e["kind"] for e in doc["events"]] == ["opened", "alert_attached", "acked"]
    assert doc["events"][-1]["actor"] == LOGIN


def test_every_case_event_has_its_own_timestamp_so_the_history_has_one_order(
    fx: Fixture,
) -> None:
    """now() is constant inside one transaction; the events of one assign_cases call
    would tie and the history could list them in any order."""
    fx.alert(age_min=20, event="one")
    fx.alert(age_min=10, event="two")
    fx.alert(age_min=5, event="three")
    fx.assign()
    case = case_ids(fx)[0]
    ack(fx, case)
    stamps = [r[0] for r in fx.rows("SELECT at FROM case_event WHERE case_id = %s", (case,))]
    assert len(stamps) == 4 and len(set(stamps)) == 4
    assert [e["kind"] for e in get(fx, case)["events"]] == [
        "opened",
        "alert_attached",
        "alert_attached",
        "acked",
    ]


def test_the_raw_payload_comes_back_as_text_and_is_never_interpreted(fx: Fixture) -> None:
    hostile = "<script>alert(1)</script> javascript:x ‮\x1b[31m"
    fx.alert(cat=hostile, host="<b>h</b>")
    fx.assign()
    doc = get(fx, case_ids(fx)[0])
    [alert] = doc["alerts"]
    assert isinstance(alert["raw"], str)  # a string to be escaped, not a structure
    assert json.loads(alert["raw"])["cat"] == hostile
    assert alert["host"] == "<b>h</b>" and alert["raw_truncated"] is False


def test_a_very_large_payload_is_cut_and_says_so(fx: Fixture) -> None:
    fx.alert(cat="x" * 50000)
    fx.assign()
    [alert] = get(fx, case_ids(fx)[0])["alerts"]
    assert len(alert["raw"]) == 20000 and alert["raw_truncated"] is True


def test_a_case_with_many_alerts_lists_the_newest_hundred_and_counts_all(fx: Fixture) -> None:
    for i in range(105):
        fx.alert(event=f"e{i}", age_min=200 - i * 0.1)
    fx.assign()  # one call takes at most 100 alerts
    fx.assign()
    doc = get(fx, case_ids(fx)[0])
    assert doc["case"]["alert_count"] == 105 and len(doc["alerts"]) == 100


def test_an_unknown_case_is_null(fx: Fixture) -> None:
    assert get(fx, "00000000-0000-4000-8000-0000000000ff") is None


# ---- acknowledge ----


def test_ack_acknowledges_marks_the_pages_and_leaves_an_audit_event(fx: Fixture) -> None:
    case = one_case(fx, severity="high")
    assert ack(fx, case, "Operator@Example.com") == "acked"
    assert fx.one("SELECT status, closed_at FROM soc_case WHERE id = %s", (case,)) == (
        "acknowledged",
        None,
    )
    assert fx.one("SELECT count(*), count(acked_at) FROM notification") == (1, 1)
    assert events(fx, case)[-1] == ("operator@example.com", "acked", None)


def test_ack_twice_changes_nothing_the_second_time(fx: Fixture) -> None:
    case = one_case(fx)
    assert ack(fx, case) == "acked"
    first = fx.one("SELECT acked_at FROM notification")[0]
    assert ack(fx, case, "someone.else@example.com") == "already"
    assert fx.one("SELECT acked_at FROM notification")[0] == first
    assert [e[1] for e in events(fx, case)].count("acked") == 1


def test_ack_leaves_other_cases_and_pages_alone(fx: Fixture) -> None:
    mine = one_case(fx, host="h1")
    other = one_case(fx, host="h2")
    ack(fx, mine)
    assert fx.one("SELECT status FROM soc_case WHERE id = %s", (other,)) == ("open",)
    assert fx.one("SELECT count(*) FROM notification WHERE acked_at IS NULL") == (1,)


def test_a_closed_case_cannot_be_acknowledged(fx: Fixture) -> None:
    case = one_case(fx)
    close(fx, case)
    assert ack(fx, case) == "closed"
    assert fx.one("SELECT status FROM soc_case WHERE id = %s", (case,)) == ("closed",)


def test_ack_of_an_unknown_case_says_so(fx: Fixture) -> None:
    assert ack(fx, "00000000-0000-4000-8000-0000000000ff") == "not_found"


BAD_LOGINS = [
    None,
    "",
    "nobody",
    "no-at-sign",
    "two@@example.com",
    "a@b c",
    "a b@example.com",
    "op\n@example.com",
    "op@example.com\n",
    "x'; DROP TABLE soc_case; --@example.com",
    "<script>@example.com",
    "@example.com",
    "op@",
    "a" * 65 + "@example.com",
    "op@" + "d" * 200,
    "op@exam_ple.com",
]


@pytest.mark.parametrize("login", BAD_LOGINS)
def test_a_login_that_is_not_shaped_like_one_never_reaches_the_audit_trail(
    fx: Fixture, login: str | None
) -> None:
    case = one_case(fx)
    before = events(fx, case)
    assert ack(fx, case, login) == "invalid_login"
    assert close(fx, case, "a note", login) == "invalid_login"
    assert events(fx, case) == before
    assert fx.one("SELECT status FROM soc_case WHERE id = %s", (case,)) == ("open",)


@pytest.mark.parametrize("login", ["o'brien@example.com", "first.last+tag@example.com"])
def test_ordinary_logins_are_accepted(fx: Fixture, login: str) -> None:
    case = one_case(fx)
    assert ack(fx, case, login) == "acked"
    assert events(fx, case)[-1][0] == login


def test_two_people_acknowledging_at_once_leave_one_acknowledgement(fx: Fixture) -> None:
    """B must wait for A's transaction, then see the case already acknowledged."""
    case = one_case(fx)
    a = console(fx)
    a.autocommit = False
    result: dict[str, Any] = {}
    try:
        assert a.execute("SELECT ack_case(%s, %s)", (case, LOGIN)).fetchone() == ("acked",)

        def run_b() -> None:
            with console(fx) as b:
                result["row"] = b.execute(
                    "SELECT ack_case(%s, %s)", (case, "second@example.com")
                ).fetchone()

        thread = threading.Thread(target=run_b)
        thread.start()
        time.sleep(0.7)
        assert thread.is_alive(), "the second acknowledgement should be waiting"
        a.commit()
        thread.join(10)
    finally:
        a.close()
    assert result["row"] == ("already",)
    assert [e[1] for e in events(fx, case)].count("acked") == 1


# ---- close ----


def test_close_needs_a_note_and_records_who_and_why(fx: Fixture) -> None:
    case = one_case(fx)
    assert close(fx, case, "  my own nmap test \n", "Operator@Example.com") == "closed"
    status, closed_at, note = fx.one(
        "SELECT status, closed_at, closing_note FROM soc_case WHERE id = %s", (case,)
    )
    assert status == "closed" and closed_at is not None and note == "my own nmap test"
    assert events(fx, case)[-1] == ("operator@example.com", "closed", "my own nmap test")
    assert fx.one("SELECT count(acked_at) FROM notification") == (1,)  # nothing left to re-send


def test_an_acknowledged_case_can_be_closed(fx: Fixture) -> None:
    case = one_case(fx)
    ack(fx, case)
    assert close(fx, case) == "closed"


@pytest.mark.parametrize("note", [None, "", "   ", "\n\t ", "has\x00nul"])
def test_close_without_a_usable_note_changes_nothing(fx: Fixture, note: str | None) -> None:
    case = one_case(fx)
    if note is not None and "\x00" in note:
        with console(fx) as c, pytest.raises((psycopg.errors.DataError, ValueError)):
            c.execute("SELECT close_case(%s, %s, %s)", (case, LOGIN, note))
        return
    assert close(fx, case, note) == "note_required"
    assert fx.one("SELECT status, closing_note FROM soc_case WHERE id = %s", (case,)) == (
        "open",
        None,
    )


def test_the_note_can_be_2000_characters_and_not_more(fx: Fixture) -> None:
    case = one_case(fx)
    assert close(fx, case, "x" * 2001) == "note_too_long"
    assert close(fx, case, "x" * 2000) == "closed"


def test_closing_twice_keeps_the_first_note(fx: Fixture) -> None:
    case = one_case(fx)
    close(fx, case, "first reason")
    assert close(fx, case, "second reason") == "already"
    assert fx.one("SELECT closing_note FROM soc_case WHERE id = %s", (case,)) == ("first reason",)
    assert [e[1] for e in events(fx, case)].count("closed") == 1


def test_close_of_an_unknown_case_says_so(fx: Fixture) -> None:
    assert close(fx, "00000000-0000-4000-8000-0000000000ff") == "not_found"


# ---- the worker's grouping after Ack and Close ----


def pages(fx: Fixture) -> int:
    return int(fx.one("SELECT count(*) FROM notification")[0])


def test_an_alert_after_ack_joins_the_acknowledged_case_without_a_new_page(fx: Fixture) -> None:
    case = one_case(fx, age_min=20)
    ack(fx, case)
    fx.alert(age_min=1)
    assert fx.assign() == (1, 0, 0)
    assert pages(fx) == 1 and len(case_ids(fx)) == 1
    assert fx.one("SELECT status FROM soc_case WHERE id = %s", (case,)) == ("acknowledged",)
    assert events(fx, case)[-1][1] == "alert_attached"


def test_an_alert_after_close_opens_a_new_case_and_a_new_page(fx: Fixture) -> None:
    case = one_case(fx, age_min=20)
    close(fx, case)
    fx.alert(age_min=1)
    assert fx.assign() == (1, 1, 1)
    assert pages(fx) == 2 and len(case_ids(fx)) == 2


# ---- the database stays consistent ----


def test_a_page_cannot_be_acked_into_another_clients_case(fx: Fixture) -> None:
    """Only the function writes acked_at, and only for the case's own client."""
    mine = one_case(fx, source="a", host="h1")
    other = one_case(fx, source="b", host="h2")
    ack(fx, mine)
    rows = fx.rows("SELECT client_id, case_id, acked_at IS NOT NULL FROM notification")
    assert {(str(r[0]), str(r[1])): r[2] for r in rows} == {
        (fx.clients["a"], str(mine)): True,
        (fx.clients["b"], str(other)): False,
    }


def test_downgrade_removes_the_console_pieces_and_restores_grouping(fx: Fixture) -> None:
    from soc_api import db as soc_db

    url = fx.db.sqlalchemy_url()
    soc_db.downgrade(url, "0003")
    with fx.db.connect() as c:
        funcs = {
            r[0]
            for r in c.execute(
                "SELECT proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace"
            )
        }
        constraints = {
            r[0]
            for r in c.execute(
                "SELECT conname FROM pg_constraint WHERE conrelid = 'soc_case'::regclass"
            )
        }
        definition = c.execute(
            "SELECT pg_get_functiondef('assign_cases(integer, jsonb)'::regprocedure)"
        ).fetchone()
    assert not funcs & {"list_cases", "get_case", "ack_case", "close_case"}
    assert "assign_cases" in funcs
    assert not constraints & {"soc_case_status_check", "soc_case_closed_check"}
    assert definition is not None and "c.status = 'open'" in definition[0]
    soc_db.upgrade(url)
    with console(fx) as c:
        assert c.execute("SELECT count(*) FROM list_cases('all', 10)").fetchone() == (0,)
