"""Re-paging (migration 0005): an urgent page nobody acknowledged is sent again, twice.

Real Postgres, real worker login. The rules: only sent priority-5 pages on cases that are
still open; the second re-send waits for the first to have gone out; an Ack or a Close
stops everything not yet sent; each re-send exists once however often the queue is run.
"""

import threading
import time
from typing import Any

import psycopg
import pytest
from conftest import TestDb
from test_worker_db import Fixture, claim, finish, make_pages

FIRST = "15 minutes"
SECOND = "60 minutes"


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def queue(fx: Fixture, first: str = FIRST, second: str = SECOND) -> int:
    with fx.worker() as w:
        row = w.execute(
            "SELECT queue_repages(%s::interval, %s::interval)", (first, second)
        ).fetchone()
    assert row is not None
    return int(row[0])


def urgent_sent(fx: Fixture, minutes_ago: int = 20, priority: int = 5) -> tuple[str, str]:
    """One case with one page of `priority`, sent `minutes_ago` minutes ago."""
    [page_id] = make_pages(fx, [priority])
    claim(fx)
    finish(fx, page_id, "sent")
    fx.run(
        "UPDATE notification SET sent_at = now() - make_interval(mins => %s) WHERE id = %s",
        (minutes_ago, page_id),
    )
    case = str(fx.one("SELECT case_id FROM notification WHERE id = %s", (page_id,))[0])
    return page_id, case


def kinds(fx: Fixture, case: str) -> list[tuple[Any, ...]]:
    return fx.rows(
        "SELECT kind, status, priority FROM notification WHERE case_id = %s ORDER BY kind", (case,)
    )


def send_repage(fx: Fixture, case: str) -> None:
    fx.run(
        "UPDATE notification SET next_attempt_at = now() - interval '1 second' WHERE case_id = %s",
        (case,),
    )
    for page in claim(fx):
        finish(fx, str(page["id"]), "sent")


# ---- when a re-send is due ----


def test_nothing_is_queued_before_the_first_interval(fx: Fixture) -> None:
    _, case = urgent_sent(fx, minutes_ago=14)
    assert queue(fx) == 0 and kinds(fx, case) == [("page", "sent", 5)]


def test_the_first_resend_is_queued_once_after_the_first_interval(fx: Fixture) -> None:
    _, case = urgent_sent(fx, minutes_ago=16)
    assert queue(fx) == 1
    assert kinds(fx, case) == [("page", "sent", 5), ("repage1", "pending", 5)]
    assert queue(fx) == 0 and queue(fx) == 0  # however often it runs
    assert len(kinds(fx, case)) == 2


def test_the_second_resend_waits_for_the_first_to_have_gone_out(fx: Fixture) -> None:
    page, case = urgent_sent(fx, minutes_ago=90)
    assert queue(fx) == 1  # only the first: the worker has not sent it yet
    assert [k[0] for k in kinds(fx, case)] == ["page", "repage1"]
    assert queue(fx) == 0
    send_repage(fx, case)
    assert queue(fx) == 1
    assert kinds(fx, case) == [
        ("page", "sent", 5),
        ("repage1", "sent", 5),
        ("repage2", "pending", 5),
    ]
    assert queue(fx) == 0


def test_the_second_resend_is_not_due_before_the_second_interval(fx: Fixture) -> None:
    _, case = urgent_sent(fx, minutes_ago=30)
    queue(fx)
    send_repage(fx, case)
    assert queue(fx) == 0
    assert [k[0] for k in kinds(fx, case)] == ["page", "repage1"]


@pytest.mark.parametrize("priority", [4, 3, 2])
def test_pages_below_urgent_are_never_resent(fx: Fixture, priority: int) -> None:
    _, case = urgent_sent(fx, minutes_ago=300, priority=priority)
    assert queue(fx) == 0 and len(kinds(fx, case)) == 1


@pytest.mark.parametrize("state", ["pending", "failed"])
def test_a_page_that_never_went_out_is_not_resent(fx: Fixture, state: str) -> None:
    [page] = make_pages(fx, [5])
    fx.run("UPDATE notification SET status = %s, created_at = now() - interval '5 hours'", (state,))
    case = str(fx.one("SELECT case_id FROM notification")[0])
    assert queue(fx) == 0 and len(kinds(fx, case)) == 1 and page


# ---- Ack and Close stop it ----


def test_an_acknowledged_case_gets_no_resend(fx: Fixture) -> None:
    _, case = urgent_sent(fx, minutes_ago=30)
    fx.one("SELECT ack_case(%s, 'operator@example.com')", (case,))
    assert queue(fx) == 0 and len(kinds(fx, case)) == 1


def test_a_closed_case_gets_no_resend(fx: Fixture) -> None:
    _, case = urgent_sent(fx, minutes_ago=30)
    fx.one("SELECT close_case(%s, 'operator@example.com', 'done')", (case,))
    assert queue(fx) == 0 and len(kinds(fx, case)) == 1


@pytest.mark.parametrize("how", ["ack", "close"])
def test_a_queued_resend_is_skipped_when_the_case_is_dealt_with(fx: Fixture, how: str) -> None:
    _, case = urgent_sent(fx, minutes_ago=30)
    assert queue(fx) == 1
    if how == "ack":
        fx.one("SELECT ack_case(%s, 'operator@example.com')", (case,))
    else:
        fx.one("SELECT close_case(%s, 'operator@example.com', 'done')", (case,))
    fx.run("UPDATE notification SET acked_at = NULL WHERE kind = 'repage1'")  # as if queued after
    assert claim(fx) == []  # not handed out even before the next queue pass
    queue(fx)
    assert [k[:2] for k in kinds(fx, case)] == [("page", "sent"), ("repage1", "skipped")]
    with fx.worker() as w:
        assert w.execute("SELECT due_page_count()").fetchone() == (0,)


def test_an_open_case_hands_its_resend_out_like_any_page(fx: Fixture) -> None:
    _, case = urgent_sent(fx, minutes_ago=30)
    queue(fx)
    [page] = claim(fx)
    assert page["kind"] == "repage1" and str(page["case_id"]) == case and page["priority"] == 5
    assert page["rule"] and page["host"] and page["client_slug"] == "client-a"


def test_an_acknowledged_case_still_gets_its_original_page_handed_out(fx: Fixture) -> None:
    """The filter is for re-sends only: a first page is never withheld."""
    [page_id] = make_pages(fx, [5])
    case = str(fx.one("SELECT case_id FROM notification WHERE id = %s", (page_id,))[0])
    fx.one("SELECT ack_case(%s, 'operator@example.com')", (case,))
    fx.run("UPDATE notification SET acked_at = NULL")
    assert [str(p["id"]) for p in claim(fx)] == [page_id]


# ---- arguments, constraints, roles ----


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (None, "60 minutes"),
        ("15 minutes", None),
        ("0 seconds", "60 minutes"),
        ("-5 minutes", "60 minutes"),
        ("60 minutes", "60 minutes"),
        ("60 minutes", "15 minutes"),
        ("1 hour", "8 days"),
    ],
)
def test_odd_intervals_are_refused(fx: Fixture, first: str | None, second: str | None) -> None:
    with fx.worker() as w, pytest.raises(psycopg.errors.RaiseException, match="intervals"):
        w.execute("SELECT queue_repages(%s::interval, %s::interval)", (first, second))


def test_a_case_has_each_kind_once_and_only_known_kinds(fx: Fixture) -> None:
    _, case = urgent_sent(fx, minutes_ago=30)
    queue(fx)
    client = fx.clients["a"]
    with fx.db.connect() as c:
        with pytest.raises(psycopg.errors.UniqueViolation):
            c.execute(
                "INSERT INTO notification (client_id, case_id, channel, priority, kind) "
                "VALUES (%s, %s, 'ntfy', 5, 'repage1')",
                (client, case),
            )
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(
                "INSERT INTO notification (client_id, case_id, channel, priority, kind) "
                "VALUES (%s, %s, 'ntfy', 5, 'other')",
                (client, case),
            )


def test_only_the_worker_may_queue_resends(fx: Fixture) -> None:
    with fx.db.connect() as c:
        for role, allowed in (
            ("soc_worker", True),
            ("soc_console", False),
            ("soc_ingest", False),
            ("soc_app", False),
        ):
            got = c.execute(
                "SELECT has_function_privilege(%s, 'queue_repages(interval, interval)', 'EXECUTE')",
                (role,),
            ).fetchone()
            assert got == (allowed,), role
        row = c.execute(
            "SELECT r.rolname, p.prosecdef, p.proconfig FROM pg_proc p "
            "JOIN pg_roles r ON r.oid = p.proowner "
            "WHERE p.proname IN ('queue_repages', 'claim_pages')"
        ).fetchall()
    assert {r[0] for r in row} == {"soc_worker_writer"} and all(r[1] for r in row)
    assert all(any(x.startswith("search_path=pg_catalog") for x in r[2]) for r in row)


def test_two_workers_queueing_at_once_still_make_one_resend(fx: Fixture) -> None:
    _, case = urgent_sent(fx, minutes_ago=30)
    a = fx.worker()
    a.autocommit = False
    done: dict[str, Any] = {}
    try:
        assert a.execute("SELECT queue_repages('15 minutes', '60 minutes')").fetchone() == (1,)

        def run_b() -> None:
            with fx.worker() as b:
                done["n"] = b.execute("SELECT queue_repages('15 minutes', '60 minutes')").fetchone()

        t = threading.Thread(target=run_b)
        t.start()
        time.sleep(0.7)
        assert t.is_alive()  # B waits on A's uncommitted row
        a.commit()
        t.join(10)
    finally:
        a.close()
    assert done["n"] == (0,) and [k[0] for k in kinds(fx, case)] == ["page", "repage1"]


def test_downgrade_restores_the_previous_claim_and_drops_the_kind(fx: Fixture) -> None:
    from soc_api import db as soc_db

    url = fx.db.sqlalchemy_url()
    soc_db.downgrade(url, "0004")
    with fx.db.connect() as c:
        cols = {
            r[0]
            for r in c.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'notification'"
            )
        }
        funcs = {
            r[0]
            for r in c.execute(
                "SELECT proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace"
            )
        }
    assert "kind" not in cols and "queue_repages" not in funcs and "claim_pages" in funcs
    with fx.worker() as w, w.cursor() as cur:
        cur.execute("SELECT * FROM claim_pages(1)")
        assert [d.name for d in cur.description or []][-1] == "detected_at"
    soc_db.upgrade(url)
    with fx.worker() as w:
        assert w.execute("SELECT queue_repages('1 minute', '2 minutes')").fetchone() == (0,)
