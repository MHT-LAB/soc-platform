"""The pager worker's database side: cases, the outbox, heartbeat counters, role limits.

Real Postgres, real logins (see conftest.db). The worker role has no table privileges;
every behaviour here is reached through the functions it is allowed to call.
"""

import json
import threading
import time
import uuid
from typing import Any

import psycopg
import pytest
from conftest import TestDb
from test_schema import ALL_TABLES, UNASSIGNED

LINK = "https://app.limacharlie.io/orgs/o/sensors/s/timeline?time=1"
WORKER_FUNCTIONS = [
    "assign_cases(integer, jsonb)",
    "claim_pages(integer)",
    "finish_page(uuid, text, text)",
    "heartbeat_counts(timestamptz)",
    "worker_state_get(text)",
    "worker_state_set(text, text)",
    "due_page_count()",
    "queue_repages(interval, interval)",
]


class Fixture:
    """Two clients (a, b), one source each, plus the Unassigned client."""

    def __init__(self, db: TestDb) -> None:
        self.db = db
        self.clients: dict[str, str] = {}
        with db.connect() as c:
            for tag in ("a", "b"):
                row = c.execute(
                    "INSERT INTO client (slug, name) VALUES (%s, %s) RETURNING id",
                    (f"client-{tag}", f"Client {tag}"),
                ).fetchone()
                assert row is not None
                self.clients[tag] = str(row[0])
                c.execute(
                    "INSERT INTO source (client_id, slug, type, external_id) "
                    "VALUES (%s, %s, 'edr', %s)",
                    (row[0], f"src-{tag}", f"t-{tag}"),
                )
        self._n = 0

    def alert(
        self,
        source: str = "a",
        *,
        rule: str | None = "general.Rule One",
        host: str | None = "host-1",
        cat: str = "CAT_ONE",
        severity: str = "low",
        age_min: float = 0,
        tenant: str | None = None,
        link: str | None = LINK,
        event: str | None = None,
    ) -> str:
        """Insert an alert the way ingest does, then back-date it by `age_min` minutes."""
        self._n += 1
        event = event or f"ev-{self._n}"
        raw: dict[str, Any] = {"cat": cat, "routing": {"hostname": host}}
        if link:
            raw["link"] = link
        with self.db.connect() as c:
            result = c.execute(
                "SELECT ingest_alert(%s, %s, %s, %s, %s, 'summary', 'actor', NULL, now(), "
                "%s::jsonb)",
                (f"src-{source}", tenant or f"t-{source}", event, rule, severity, json.dumps(raw)),
            ).fetchone()
            assert result is not None
            assert result[0] in ("inserted", "duplicate")
            if age_min:
                c.execute(
                    "UPDATE alert SET received_at = now() - make_interval(secs => %s) "
                    "WHERE event_id = %s",
                    (age_min * 60, event),
                )
        return event

    def worker(self) -> psycopg.Connection:
        return self.db.connect("soc_worker")

    def assign(self, batch: int = 100, policy: dict[str, Any] | None = None) -> tuple[int, ...]:
        with self.worker() as w:
            row = w.execute(
                "SELECT * FROM assign_cases(%s, %s::jsonb)", (batch, json.dumps(policy or {}))
            ).fetchone()
        assert row is not None
        return tuple(row)

    def run(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self.db.connect() as c:
            c.execute(sql, params)

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        with self.db.connect() as c:
            return c.execute(sql, params).fetchone()

    def rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        with self.db.connect() as c:
            return c.execute(sql, params).fetchall()


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def count(fx: Fixture, table: str) -> int:
    return int(fx.one(f"SELECT count(*) FROM {table}")[0])


# ---- cases and grouping ----


def test_an_alert_gets_a_case_a_case_event_and_one_page(fx: Fixture) -> None:
    fx.alert()
    assert fx.assign() == (1, 1, 1)
    case = fx.one("SELECT id, client_id, severity, status FROM soc_case")
    assert str(case[1]) == fx.clients["a"] and case[2:] == ("low", "open")
    assert fx.one("SELECT case_id FROM alert")[0] == case[0]
    assert fx.one("SELECT actor, kind FROM case_event") == ("system", "opened")
    page = fx.one("SELECT channel, priority, status, attempts, case_id FROM notification")
    assert page == ("ntfy", 3, "pending", 0, case[0])
    assert fx.assign() == (0, 0, 0)  # nothing left to do


def test_the_same_rule_and_host_within_an_hour_is_one_case_and_one_page(fx: Fixture) -> None:
    for minutes_ago in (50, 30, 5):
        fx.alert(age_min=minutes_ago)
    assert fx.assign() == (3, 1, 1)
    assert count(fx, "soc_case") == 1 and count(fx, "notification") == 1
    assert fx.one("SELECT count(DISTINCT case_id) FROM alert")[0] == 1
    kinds = [r[0] for r in fx.rows("SELECT kind FROM case_event ORDER BY at, kind")]
    assert sorted(kinds) == ["alert_attached", "alert_attached", "opened"]


def test_a_gap_over_an_hour_starts_a_new_case(fx: Fixture) -> None:
    fx.alert(age_min=125)
    fx.alert(age_min=61)  # 64 min after the first: new case
    fx.alert(age_min=2)  # 59 min after the second: same case as the second
    assert fx.assign() == (3, 2, 2)
    cases = fx.rows("SELECT case_id FROM alert ORDER BY received_at")
    assert cases[1] == cases[2] and cases[0] != cases[1]


def test_the_window_slides_with_each_alert(fx: Fixture) -> None:
    for minutes_ago in (170, 115, 60, 5):  # each 55 min after the last: one case
        fx.alert(age_min=minutes_ago)
    assert fx.assign() == (4, 1, 1)


def test_backlog_groups_by_alert_time_not_by_when_the_worker_runs(fx: Fixture) -> None:
    fx.alert(age_min=300)
    fx.alert(age_min=290)  # ten minutes after the first, long before now
    fx.alert(age_min=100)
    assert fx.assign() == (3, 2, 2)
    cases = fx.rows("SELECT case_id FROM alert ORDER BY received_at")
    assert cases[0] == cases[1] and cases[1] != cases[2]


@pytest.mark.parametrize(
    "other",
    [
        {"host": "host-2"},
        {"rule": "general.Rule Two"},
        {"source": "b"},
    ],
)
def test_another_host_rule_or_client_is_another_case(fx: Fixture, other: dict[str, Any]) -> None:
    fx.alert()
    fx.alert(**other)
    assert fx.assign() == (2, 2, 2)
    clients = {str(r[0]) for r in fx.rows("SELECT client_id FROM soc_case")}
    assert clients == (
        {fx.clients["a"], fx.clients["b"]} if "source" in other else {fx.clients["a"]}
    )


def test_missing_host_and_rule_still_group_with_each_other(fx: Fixture) -> None:
    fx.alert(host=None, rule=None, age_min=10)
    fx.alert(host=None, rule=None)
    assert fx.assign() == (2, 1, 1)


def test_a_closed_case_is_not_reused(fx: Fixture) -> None:
    fx.alert(age_min=10)
    fx.assign()
    fx.run("UPDATE soc_case SET status = 'closed', closed_at = now()")
    fx.alert()
    assert fx.assign() == (1, 1, 1)
    assert count(fx, "soc_case") == 2


def test_a_replayed_delivery_makes_one_alert_and_one_case(fx: Fixture) -> None:
    fx.alert(event="same")
    fx.alert(event="same")
    assert count(fx, "alert") == 1
    assert fx.assign() == (1, 1, 1)
    assert fx.assign() == (0, 0, 0)
    assert count(fx, "soc_case") == 1 and count(fx, "notification") == 1


def test_batch_size_limits_one_call(fx: Fixture) -> None:
    for i in range(3):
        fx.alert(host=f"h{i}", age_min=10 - i)
    assert fx.assign(batch=2) == (2, 2, 2)
    assert fx.assign(batch=2) == (1, 1, 1)


@pytest.mark.parametrize("batch", [0, -1, 1001, None])
def test_a_bad_batch_size_is_refused(fx: Fixture, batch: int | None) -> None:
    with fx.worker() as w, pytest.raises(psycopg.errors.RaiseException, match="batch"):
        w.execute("SELECT * FROM assign_cases(%s, '{}')", (batch,))


def test_two_callers_never_open_two_cases_for_one_group(fx: Fixture) -> None:
    """With batch 1 both callers would pick the same alert; the lock makes B wait for A."""
    fx.alert(age_min=20)
    fx.alert(age_min=10)
    a = fx.worker()
    a.autocommit = False
    result: dict[str, Any] = {}
    try:
        a_row = a.execute("SELECT * FROM assign_cases(1, '{}')").fetchone()
        assert a_row == (1, 1, 1)

        def run_b() -> None:
            with fx.worker() as b:
                result["row"] = b.execute("SELECT * FROM assign_cases(1, '{}')").fetchone()

        thread = threading.Thread(target=run_b)
        thread.start()
        time.sleep(0.7)
        assert thread.is_alive(), "the second caller should be waiting for the first"
        a.commit()
        thread.join(10)
    finally:
        a.close()
    assert result["row"] == (1, 0, 0)  # B got the second alert and attached it
    assert count(fx, "soc_case") == 1 and count(fx, "notification") == 1
    assert fx.one("SELECT count(DISTINCT case_id), count(case_id) FROM alert") == (1, 2)


# ---- who gets paged, and how loudly ----


@pytest.mark.parametrize(
    ("severity", "priority"),
    [("info", None), ("low", 3), ("medium", 4), ("high", 5), ("critical", 5)],
)
def test_without_a_policy_the_page_priority_follows_severity(
    fx: Fixture, severity: str, priority: int | None
) -> None:
    fx.alert(severity=severity)
    fx.assign()
    rows = fx.rows("SELECT priority FROM notification")
    assert rows == ([] if priority is None else [(priority,)])
    assert count(fx, "soc_case") == 1  # a case opens either way


def test_the_policy_sets_the_priority_per_category(fx: Fixture) -> None:
    fx.alert(cat="LOUD", host="h1")
    fx.alert(cat="QUIET", host="h2")
    fx.alert(cat="OTHER", host="h3")
    assert fx.assign(policy={"LOUD": 5, "QUIET": 2}) == (3, 3, 3)
    got = {
        r[0]: r[1]
        for r in fx.rows(
            "SELECT a.raw->>'cat', n.priority FROM notification n "
            "JOIN alert a ON a.case_id = n.case_id"
        )
    }
    assert got == {"LOUD": 5, "QUIET": 2, "OTHER": 3}


def test_priority_zero_opens_a_case_but_sends_no_page(fx: Fixture) -> None:
    fx.alert(cat="QUIET", severity="high")
    assert fx.assign(policy={"QUIET": 0}) == (1, 1, 0)
    assert count(fx, "soc_case") == 1 and count(fx, "notification") == 0


@pytest.mark.parametrize("bad", ["5", 9, -1, 2.5, None, True, [5], {"a": 1}])
def test_a_bad_policy_value_falls_back_to_severity(fx: Fixture, bad: Any) -> None:
    fx.alert(cat="X", severity="medium")
    fx.assign(policy={"X": bad})
    assert fx.rows("SELECT priority FROM notification") == [(4,)]


def test_a_non_object_policy_is_ignored(fx: Fixture) -> None:
    fx.alert(severity="medium")
    with fx.worker() as w:
        row = w.execute("SELECT * FROM assign_cases(10, '[1,2]'::jsonb)").fetchone()
    assert row == (1, 1, 1)


def test_unassigned_alerts_become_at_least_medium_and_always_page_loudly(fx: Fixture) -> None:
    fx.alert(tenant="some-other-tenant", severity="low", cat="QUIET")
    assert fx.assign(policy={"QUIET": 0}) == (1, 1, 1)
    assert fx.one("SELECT client_id, severity FROM soc_case") == (
        fx.one("SELECT %s::uuid", (UNASSIGNED,))[0],
        "medium",
    )
    assert fx.one("SELECT priority FROM notification")[0] == 4
    fx.alert(tenant="some-other-tenant", severity="high", cat="OTHER", host="h9")
    fx.assign()
    assert fx.rows("SELECT priority FROM notification ORDER BY priority") == [(4,), (5,)]


# ---- claiming pages ----


def make_pages(fx: Fixture, priorities: list[int]) -> list[str]:
    for i, _ in enumerate(priorities):
        fx.alert(host=f"h{i}", cat=f"C{i}", age_min=len(priorities) - i)
    fx.assign(policy={f"C{i}": p for i, p in enumerate(priorities)})
    return [str(r[0]) for r in fx.rows("SELECT id FROM notification ORDER BY priority DESC")]


def claim(fx: Fixture, batch: int = 10) -> list[dict[str, Any]]:
    with fx.worker() as w, w.cursor() as cur:
        cur.execute("SELECT * FROM claim_pages(%s)", (batch,))
        names = [d.name for d in cur.description or []]
        return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]


def test_claim_returns_only_what_a_push_needs(fx: Fixture) -> None:
    fx.alert(rule="general.DEMO - Rule", host="ws-demo-01", cat="C0", severity="high")
    fx.assign(policy={"C0": 5})
    [page] = claim(fx)
    case_id = fx.one("SELECT id FROM soc_case")[0]
    assert set(page) == {
        "id",
        "priority",
        "attempts",
        "client_slug",
        "rule",
        "host",
        "link",
        "case_short",
        "detected_at",
        "case_id",
        "kind",
    }
    assert page["client_slug"] == "client-a" and page["rule"] == "general.DEMO - Rule"
    assert page["host"] == "ws-demo-01" and page["link"] == LINK and page["priority"] == 5
    assert page["case_short"] == str(case_id)[:8] and page["attempts"] == 1
    assert str(page["case_id"]) == str(case_id) and page["kind"] == "page"


@pytest.mark.parametrize(
    "link",
    [
        "http://app.limacharlie.io/x",
        "https://evil.example/https://app.limacharlie.io/",
        "https://app.limacharlie.io.evil.example/x",
        "javascript:alert(1)",
        "",
    ],
)
def test_only_a_limacharlie_https_link_is_passed_on(fx: Fixture, link: str) -> None:
    fx.alert(link=link or None)
    fx.assign()
    [page] = claim(fx)
    assert page["link"] is None


def test_the_host_is_cut_to_64_characters(fx: Fixture) -> None:
    fx.alert(host="h" * 300)
    fx.assign()
    [page] = claim(fx)
    assert page["host"] == "h" * 64


def test_the_first_alert_of_the_case_is_the_one_described(fx: Fixture) -> None:
    fx.alert(age_min=10, link=LINK + "&first=1")
    fx.alert(age_min=1, link=LINK + "&second=1")
    fx.assign()
    [page] = claim(fx)
    assert page["link"].endswith("first=1")


def test_a_claim_takes_a_lease_so_a_second_claim_finds_nothing(fx: Fixture) -> None:
    make_pages(fx, [5, 4])
    first = claim(fx)
    assert len(first) == 2 and all(p["attempts"] == 1 for p in first)
    assert claim(fx) == []
    lease = fx.one("SELECT min(next_attempt_at) - now() FROM notification")[0]
    assert 100 < lease.total_seconds() <= 120


def test_a_lost_claim_comes_back_after_the_lease(fx: Fixture) -> None:
    make_pages(fx, [5])
    claim(fx)
    fx.run("UPDATE notification SET next_attempt_at = now() - interval '1 second'")
    [again] = claim(fx)
    assert again["attempts"] == 2


def test_claim_goes_by_priority_and_respects_the_batch(fx: Fixture) -> None:
    make_pages(fx, [2, 5, 3])
    assert [p["priority"] for p in claim(fx, batch=2)] == [5, 3]
    assert [p["priority"] for p in claim(fx, batch=2)] == [2]


def test_only_pending_pages_that_are_due_are_claimed(fx: Fixture) -> None:
    ids = make_pages(fx, [5, 4, 3])
    fx.run("UPDATE notification SET status = 'sent' WHERE id = %s", (ids[0],))
    fx.run(
        "UPDATE notification SET next_attempt_at = now() + interval '1 hour' WHERE id = %s",
        (ids[1],),
    )
    assert [str(p["id"]) for p in claim(fx)] == [ids[2]]


@pytest.mark.parametrize("batch", [0, 101, None])
def test_a_bad_claim_size_is_refused(fx: Fixture, batch: int | None) -> None:
    with fx.worker() as w, pytest.raises(psycopg.errors.RaiseException, match="batch"):
        w.execute("SELECT * FROM claim_pages(%s)", (batch,))


def test_two_workers_claiming_at_once_never_get_the_same_page(fx: Fixture) -> None:
    """A holds a claim open; B must skip A's row, not wait for it."""
    ids = make_pages(fx, [5, 4])
    a = fx.worker()
    a.autocommit = False
    try:
        got_a = a.execute("SELECT id FROM claim_pages(1)").fetchall()
        with fx.worker() as b:
            b.execute("SET lock_timeout = '3s'")
            got_b = b.execute("SELECT id FROM claim_pages(1)").fetchall()
        a.commit()
    finally:
        a.close()
    assert [str(r[0]) for r in got_a] == [ids[0]]
    assert [str(r[0]) for r in got_b] == [ids[1]]


def test_many_workers_claiming_together_share_the_pages_without_overlap(fx: Fixture) -> None:
    make_pages(fx, [3] * 12)
    taken: list[list[str]] = []
    barrier = threading.Barrier(4)

    def run() -> None:
        barrier.wait()
        taken.append([str(p["id"]) for p in claim(fx, batch=5)])

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    flat = [i for part in taken for i in part]
    assert len(flat) == len(set(flat)) == 12


def test_due_page_count_counts_only_pending_pages_that_are_due(fx: Fixture) -> None:
    ids = make_pages(fx, [5, 4, 3, 2])
    with fx.worker() as w:
        assert w.execute("SELECT due_page_count()").fetchone() == (4,)
    fx.run("UPDATE notification SET status = 'sent' WHERE id = %s", (ids[0],))
    fx.run("UPDATE notification SET status = 'failed' WHERE id = %s", (ids[1],))
    fx.run(
        "UPDATE notification SET next_attempt_at = now() + interval '1 hour' WHERE id = %s",
        (ids[2],),
    )
    with fx.worker() as w:
        assert w.execute("SELECT due_page_count()").fetchone() == (1,)
    claim(fx)  # a claim takes the lease, so the page is no longer due
    with fx.worker() as w:
        assert w.execute("SELECT due_page_count()").fetchone() == (0,)


# ---- recording the outcome ----


def pending_page(fx: Fixture, attempts: int = 1, age: str = "1 minute") -> str:
    with fx.db.connect() as c:
        case = c.execute(
            "INSERT INTO soc_case (client_id, severity) VALUES (%s, 'high') RETURNING id",
            (fx.clients["a"],),
        ).fetchone()
        assert case is not None
        row = c.execute(
            "INSERT INTO notification "
            "(client_id, case_id, channel, priority, attempts, created_at) "
            "VALUES (%s, %s, 'ntfy', 5, %s, now() - %s::interval) RETURNING id",
            (fx.clients["a"], case[0], attempts, age),
        ).fetchone()
    assert row is not None
    return str(row[0])


def finish(fx: Fixture, page: str, outcome: str, error: str | None = None) -> str:
    with fx.worker() as w:
        row = w.execute("SELECT finish_page(%s, %s, %s)", (page, outcome, error)).fetchone()
    assert row is not None
    return str(row[0])


def test_sent_closes_the_page(fx: Fixture) -> None:
    page = pending_page(fx)
    assert finish(fx, page, "sent") == "sent"
    status, sent_at, error = fx.one("SELECT status, sent_at, last_error FROM notification")
    assert status == "sent" and sent_at is not None and error is None


@pytest.mark.parametrize(
    ("attempts", "seconds"),
    [(0, 10), (1, 10), (2, 30), (3, 120), (4, 300), (5, 900), (6, 900), (40, 900)],
)
def test_retry_backs_off_on_the_schedule(fx: Fixture, attempts: int, seconds: int) -> None:
    page = pending_page(fx, attempts=attempts)
    assert finish(fx, page, "retry", "http_503") == "retry"
    status, wait, error = fx.one(
        "SELECT status, extract(epoch FROM next_attempt_at - now()), last_error FROM notification"
    )
    assert status == "pending" and error == "http_503"
    assert seconds - 3 <= float(wait) <= seconds


def test_a_page_a_day_old_gives_up(fx: Fixture) -> None:
    page = pending_page(fx, attempts=9, age="25 hours")
    assert finish(fx, page, "retry", "timeout") == "failed"
    assert fx.one("SELECT status, last_error FROM notification") == ("failed", "gave_up")


def test_a_client_error_fails_at_once(fx: Fixture) -> None:
    page = pending_page(fx)
    assert finish(fx, page, "fail", "http_400") == "failed"
    assert fx.one("SELECT status, last_error FROM notification") == ("failed", "http_400")


@pytest.mark.parametrize("error", ["Bad Stuff!", "x" * 41, "a b", "<script>", "HTTP_400", ""])
def test_an_error_text_that_is_not_a_short_code_is_replaced(fx: Fixture, error: str) -> None:
    page = pending_page(fx)
    finish(fx, page, "retry", error)
    assert fx.one("SELECT last_error FROM notification")[0] == "error"


def test_a_finished_page_cannot_be_finished_again(fx: Fixture) -> None:
    page = pending_page(fx)
    finish(fx, page, "sent")
    assert finish(fx, page, "fail", "http_400") == "not_pending"
    assert finish(fx, str(uuid.uuid4()), "sent") == "not_pending"
    assert fx.one("SELECT status FROM notification")[0] == "sent"


def test_an_unknown_outcome_is_refused(fx: Fixture) -> None:
    page = pending_page(fx)
    with pytest.raises(psycopg.errors.RaiseException, match="outcome"):
        finish(fx, page, "delivered")


# ---- heartbeat ----


def test_heartbeat_counts(fx: Fixture) -> None:
    fx.alert(age_min=60 * 24 * 9)  # older than the week
    fx.alert(host="h2", age_min=30)
    fx.alert(host="h3", age_min=5)
    fx.assign()
    pages = [str(r[0]) for r in fx.rows("SELECT id FROM notification ORDER BY created_at, id")]
    finish_ok, finish_bad = pages[0], pages[1]
    fx.run("UPDATE notification SET attempts = 1 WHERE id = %s", (finish_ok,))
    finish(fx, finish_ok, "sent")
    finish(fx, finish_bad, "fail", "http_400")
    fx.alert(host="h4", age_min=3)  # arrives after the caser ran: unassigned backlog
    fx.run(
        "UPDATE notification SET created_at = now() - interval '12 minutes' "
        "WHERE status = 'pending'"
    )
    with fx.worker() as w:
        row = w.execute("SELECT * FROM heartbeat_counts(now() - interval '7 days')").fetchone()
    assert row is not None
    received, opened, sent, failed, failed_24h, oldest_page, oldest_alert = row
    assert (received, opened, sent, failed, failed_24h) == (3, 3, 1, 1, 1)
    assert 11 * 60 <= oldest_page <= 13 * 60
    assert 2 * 60 <= oldest_alert <= 4 * 60


def test_heartbeat_with_nothing_pending(fx: Fixture) -> None:
    with fx.worker() as w:
        row = w.execute("SELECT * FROM heartbeat_counts(now() - interval '7 days')").fetchone()
    assert row == (0, 0, 0, 0, 0, None, None)


# ---- state ----


def test_worker_state_round_trip(fx: Fixture) -> None:
    with fx.worker() as w:
        assert w.execute("SELECT worker_state_get('weekly_ok')").fetchone() == (None,)
        w.execute("SELECT worker_state_set('weekly_ok', '2026-11-01T22:00:00Z')")
        w.execute("SELECT worker_state_set('weekly_ok', '2026-11-08T22:00:00Z')")
        assert w.execute("SELECT worker_state_get('weekly_ok')").fetchone() == (
            "2026-11-08T22:00:00Z",
        )
    assert fx.one("SELECT count(*) FROM worker_state")[0] == 1


@pytest.mark.parametrize("key", ["", "UPPER", "a b", "x" * 65, "semi;colon"])
def test_worker_state_rejects_odd_keys(fx: Fixture, key: str) -> None:
    with fx.worker() as w, pytest.raises(psycopg.errors.CheckViolation):
        w.execute("SELECT worker_state_set(%s, 'v')", (key,))


def test_worker_state_rejects_a_huge_value(fx: Fixture) -> None:
    with fx.worker() as w, pytest.raises(psycopg.errors.CheckViolation):
        w.execute("SELECT worker_state_set('k', %s)", ("v" * 1001,))


# ---- what the worker role can and cannot do ----


@pytest.mark.parametrize("table", [*ALL_TABLES, "worker_state"])
def test_the_worker_login_cannot_read_or_write_any_table(fx: Fixture, table: str) -> None:
    fx.alert()
    fx.assign()
    with fx.worker() as w:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            w.execute(f"SELECT * FROM {table}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            w.execute(f"DELETE FROM {table}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            w.execute(f"INSERT INTO {table} DEFAULT VALUES")


def test_the_worker_login_cannot_read_the_raw_payload(fx: Fixture) -> None:
    fx.alert()
    fx.assign()
    with fx.worker() as w, pytest.raises(psycopg.errors.InsufficientPrivilege):
        w.execute("SELECT raw FROM alert")


def test_the_worker_login_cannot_create_objects_or_change_roles(fx: Fixture) -> None:
    with fx.worker() as w:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            w.execute("CREATE TABLE t (x int)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            w.execute("ALTER ROLE soc_worker SUPERUSER")


def test_only_the_worker_can_call_the_worker_functions(fx: Fixture) -> None:
    for role in ("soc_app", "soc_ingest"):
        with fx.db.connect(role) as c:
            for function in WORKER_FUNCTIONS:
                allowed = c.execute(
                    "SELECT has_function_privilege(%s, %s::regprocedure, 'EXECUTE')",
                    (role, function),
                ).fetchone()
                assert allowed == (False,), f"{role} can execute {function}"
    with fx.worker() as w:
        for function in WORKER_FUNCTIONS:
            assert w.execute(
                "SELECT has_function_privilege('soc_worker', %s::regprocedure, 'EXECUTE')",
                (function,),
            ).fetchone() == (True,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            w.execute("SELECT ingest_alert('s', 't', 'e', 'r', 'low', 's', 'a', NULL, now(), '{}')")


def test_the_worker_functions_pin_the_search_path_and_run_as_the_writer(fx: Fixture) -> None:
    with fx.db.connect() as c:
        for function in WORKER_FUNCTIONS:
            row = c.execute(
                "SELECT p.prosecdef, p.proconfig, r.rolname, r.rolsuper, r.rolbypassrls, "
                "r.rolcanlogin FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
                "WHERE p.oid = %s::regprocedure",
                (function,),
            ).fetchone()
            assert row is not None, function
            definer, config, owner, superuser, bypass, login = row
            assert definer and owner == "soc_worker_writer", function
            assert not (superuser or bypass or login), function
            assert config and any(x.startswith("search_path=pg_catalog") for x in config)


def test_the_writer_role_owns_no_tables_and_holds_only_what_it_needs(fx: Fixture) -> None:
    with fx.db.connect() as c:
        owned = c.execute(
            "SELECT count(*) FROM pg_class WHERE relowner = 'soc_worker_writer'::regrole"
        ).fetchone()
        grants = {
            t: tuple(
                bool(
                    c.execute(
                        "SELECT has_table_privilege('soc_worker_writer', %s, %s)", (t, p)
                    ).fetchone()[0]  # type: ignore[index]
                )
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
            )
            for t in [*ALL_TABLES, "worker_state"]
        }
        alert_cols = {
            col: bool(
                c.execute(
                    "SELECT has_column_privilege('soc_worker_writer', 'alert', %s, 'UPDATE')",
                    (col,),
                ).fetchone()[0]  # type: ignore[index]
            )
            for col in ("case_id", "raw", "rule", "severity", "client_id")
        }
    assert owned == (0,)
    assert grants.pop("client") == (True, False, False, False)
    assert grants.pop("alert") == (True, False, False, False)  # + UPDATE (case_id) only
    assert grants.pop("soc_case") == (True, True, False, False)
    assert grants.pop("case_event") == (False, True, False, False)
    assert grants.pop("notification") == (True, True, True, False)
    assert grants.pop("worker_state") == (True, True, True, False)
    assert all(g == (False, False, False, False) for g in grants.values())
    assert alert_cols == {
        "case_id": True,
        "raw": False,
        "rule": False,
        "severity": False,
        "client_id": False,
    }


def test_a_case_cannot_be_attached_across_clients(fx: Fixture) -> None:
    """The composite foreign key, not just the function, keeps clients apart."""
    fx.alert("a")
    fx.assign()
    case_a = fx.one("SELECT id FROM soc_case")[0]
    fx.alert("b", host="elsewhere")
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        fx.one(
            "UPDATE alert SET case_id = %s WHERE client_id = %s RETURNING id",
            (case_a, fx.clients["b"]),
        )


def test_downgrade_removes_the_worker_pieces_and_upgrade_restores_them(fx: Fixture) -> None:
    from soc_api import db as soc_db

    url = fx.db.sqlalchemy_url()
    soc_db.downgrade(url, "0001")
    with fx.db.connect() as c:
        tables = {
            r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")
        }
        funcs = {
            r[0]
            for r in c.execute(
                "SELECT proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace"
            )
        }
        columns = {
            r[0]
            for r in c.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'notification'"
            )
        }
    assert "worker_state" not in tables
    assert funcs == {"app_client_id", "ingest_alert"}
    assert "status" not in columns and "priority" not in columns
    soc_db.upgrade(url)
    with fx.worker() as w:
        assert w.execute("SELECT * FROM assign_cases(1, '{}')").fetchone() == (0, 0, 0)
