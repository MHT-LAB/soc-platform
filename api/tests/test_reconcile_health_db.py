"""Migration 0007: what the pager worker may see of the catch-up worker, and how late a page is.

Real Postgres, real logins. The worker learns two numbers (how many sources have a cursor,
how long the quietest has gone without a good run) and nothing else about the cursor; a
claimed page says how many seconds passed between detection and receipt.
"""

from typing import Any

import psycopg
import pytest
from conftest import TestDb
from test_worker_db import Fixture, claim

from soc_api import db as soc_db


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def health(fx: Fixture) -> tuple[Any, ...]:
    with fx.worker() as w:
        row = w.execute("SELECT * FROM reconcile_health()").fetchone()
    assert row is not None
    return row


def cursor(
    fx: Fixture,
    source: str = "src-a",
    *,
    last_success: float | None,
    started_at: float = 0.0,
) -> None:
    """Insert a cursor row as the owner, with the times set that many minutes back."""
    fx.run(
        "INSERT INTO reconcile_cursor (source_id, window_end, last_success, started_at) "
        "SELECT id, now(), now() - make_interval(secs => %s::float8 * 60), "
        "now() - make_interval(secs => %s::float8 * 60) FROM source WHERE slug = %s",
        (last_success, started_at, source),
    )


# ---- reconcile_health ----


def test_with_no_cursor_nothing_is_reported_and_nothing_can_go_stale(fx: Fixture) -> None:
    assert health(fx) == (0, None)


def test_a_source_that_just_succeeded_is_not_quiet(fx: Fixture) -> None:
    cursor(fx, last_success=0.1, started_at=60)
    sources, quiet = health(fx)
    assert sources == 1 and 0 <= quiet < 60


def test_quiet_time_runs_from_the_last_success(fx: Fixture) -> None:
    cursor(fx, last_success=45, started_at=600)
    sources, quiet = health(fx)
    assert sources == 1 and 2690 <= quiet <= 2720


def test_a_source_that_never_succeeded_is_quiet_since_its_cursor_began(fx: Fixture) -> None:
    cursor(fx, last_success=None, started_at=90)
    sources, quiet = health(fx)
    assert sources == 1 and 5390 <= quiet <= 5420


def test_the_quietest_source_decides(fx: Fixture) -> None:
    cursor(fx, "src-a", last_success=2, started_at=100)
    cursor(fx, "src-b", last_success=50, started_at=100)
    sources, quiet = health(fx)
    assert sources == 2 and 2990 <= quiet <= 3020


def test_a_real_run_through_the_cursor_functions_is_reported(fx: Fixture) -> None:
    with fx.db.connect("soc_reconcile") as c:
        c.execute("SELECT reconcile_cursor_fail('src-a', 'http_503')")
    sources, quiet = health(fx)
    assert sources == 1 and quiet is not None and quiet < 30  # failing since just now
    with fx.db.connect("soc_reconcile") as c:
        c.execute("SELECT reconcile_cursor_advance('src-a', now())")
    assert health(fx)[0] == 1


def test_it_reports_two_numbers_and_no_names_or_errors(fx: Fixture) -> None:
    cursor(fx, last_success=5, started_at=10)
    fx.run("UPDATE reconcile_cursor SET last_error = 'secret-looking-text'")
    with fx.worker() as w:
        cur = w.execute("SELECT * FROM reconcile_health()")
        names = [d.name for d in cur.description or []]
        rows = cur.fetchall()
    assert names == ["sources", "quiet_s"]
    assert len(rows) == 1 and "secret-looking-text" not in repr(rows)


# ---- who may do what ----


def test_the_worker_login_cannot_read_the_cursor_table(fx: Fixture) -> None:
    cursor(fx, last_success=1, started_at=2)
    with fx.worker() as w:
        for query in (
            "SELECT * FROM reconcile_cursor",
            "SELECT window_end FROM reconcile_cursor",
            "SELECT last_error FROM reconcile_cursor",
            "SELECT source_id FROM reconcile_cursor",
            "SELECT last_success FROM reconcile_cursor",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                w.execute(query)


def test_the_worker_writer_reads_two_cursor_columns_and_nothing_else(fx: Fixture) -> None:
    def rights(table: str, column: str, privilege: str) -> bool:
        return bool(
            fx.one(
                "SELECT has_column_privilege('soc_worker_writer', %s, %s, %s)",
                (table, column, privilege),
            )[0]
        )

    assert rights("reconcile_cursor", "last_success", "SELECT")
    assert rights("reconcile_cursor", "started_at", "SELECT")
    for column in ("window_end", "last_error", "source_id", "updated_at"):
        assert not rights("reconcile_cursor", column, "SELECT"), column
    for column in ("last_success", "started_at", "window_end", "last_error"):
        for privilege in ("INSERT", "UPDATE"):
            assert not rights("reconcile_cursor", column, privilege), (column, privilege)
    for column in ("id", "slug", "enabled", "client_id", "secret_ref"):
        assert not rights("source", column, "SELECT"), column  # it still cannot see sources


def test_only_the_worker_login_can_call_reconcile_health(fx: Fixture) -> None:
    for role in ("soc_app", "soc_ingest", "soc_console", "soc_reconcile", "public"):
        allowed = fx.one(
            "SELECT has_function_privilege(%s, 'reconcile_health()'::regprocedure, 'EXECUTE')",
            (role,),
        )
        assert allowed == (False,), role
    row = fx.one(
        "SELECT p.prosecdef, p.proconfig, r.rolname FROM pg_proc p "
        "JOIN pg_roles r ON r.oid = p.proowner WHERE p.proname = 'reconcile_health'"
    )
    assert row is not None and row[0] is True and row[2] == "soc_worker_writer"
    assert row[1] and any(x.startswith("search_path=pg_catalog") for x in row[1])


# ---- how late a page is ----


def late_s(fx: Fixture, minutes_before_receipt: float | None, **alert: Any) -> Any:
    fx.alert(**alert)
    if minutes_before_receipt is None:
        fx.run("UPDATE alert SET detected_at = NULL")
    else:
        fx.run(
            "UPDATE alert SET detected_at = received_at - make_interval(secs => %s)",
            (minutes_before_receipt * 60,),
        )
    fx.assign()
    [page] = claim(fx)
    return page["late_s"]


def test_a_page_says_how_long_after_detection_its_alert_arrived(fx: Fixture) -> None:
    assert 1199 <= late_s(fx, 20) <= 1201


def test_an_alert_that_arrived_at_once_is_not_late(fx: Fixture) -> None:
    assert -1 <= late_s(fx, 0) <= 1


def test_an_unknown_detection_time_is_unknown_lateness(fx: Fixture) -> None:
    assert late_s(fx, None) is None


def test_a_detection_time_in_the_future_is_negative_not_late(fx: Fixture) -> None:
    assert late_s(fx, -30) < 0


def test_the_first_alert_of_the_case_decides(fx: Fixture) -> None:
    fx.alert(event="first", age_min=10)
    fx.alert(event="second", age_min=1)
    fx.run(
        "UPDATE alert SET detected_at = received_at - interval '2 hours' WHERE event_id = 'first'"
    )
    fx.run("UPDATE alert SET detected_at = received_at WHERE event_id = 'second'")
    fx.assign()
    [page] = claim(fx)
    assert 7199 <= page["late_s"] <= 7201


# ---- the migration itself ----


def definition(db: TestDb, function: str) -> str:
    with db.connect() as c:
        row = c.execute("SELECT pg_get_functiondef(%s::regprocedure)", (function,)).fetchone()
    assert row is not None
    return str(row[0])


def test_downgrading_restores_the_previous_claim_and_removes_the_rest(
    db: TestDb, fx: Fixture
) -> None:
    url = db.sqlalchemy_url()
    soc_db.downgrade(url, "0006")
    with db.connect() as c:
        assert c.execute("SELECT to_regprocedure('reconcile_health()')").fetchone() == (None,)
        assert c.execute(
            "SELECT count(*) FROM pg_policies WHERE policyname = 'worker_reconcile_read'"
        ).fetchone() == (0,)
        assert c.execute(
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_name = 'reconcile_cursor' AND column_name = 'started_at'"
        ).fetchone() == (0,)
    after_downgrade = definition(db, "claim_pages(integer)")
    assert "late_s" not in after_downgrade
    # ...and it is exactly what migration 0005 itself builds.
    soc_db.downgrade(url, "0004")
    soc_db.upgrade(url, "0006")
    assert definition(db, "claim_pages(integer)") == after_downgrade
    soc_db.upgrade(url)  # and forward again
    assert "late_s" in definition(db, "claim_pages(integer)")
    with fx.worker() as w:
        assert w.execute("SELECT * FROM reconcile_health()").fetchone() == (0, None)
