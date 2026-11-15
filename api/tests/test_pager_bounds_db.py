"""Pager bounds (migration 0017): acknowledged cases are bounded (R3 / D1), a flood cannot
starve the rest of the claim order (R2), and cases group on the sensor id (R4).

Real Postgres, real worker login. Every time-dependent rule is tested against fixed
timestamps written into the rows (T0 plus minutes), never against the clock, so a test
cannot depend on the day or hour it runs.
"""

from typing import Any

import pytest
from conftest import TestDb
from test_worker_db import Fixture, claim

from soc_api import db as soc_db

T0 = "2026-03-10 12:00:00+00"


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def at(minutes: float) -> tuple[str, float]:
    return (T0, minutes)


def place(fx: Fixture, event: str, minutes: float) -> None:
    """Pin an alert's receive time to T0 + minutes."""
    fx.run(
        "UPDATE alert SET received_at = %s::timestamptz + make_interval(secs => %s) "
        "WHERE event_id = %s",
        (T0, minutes * 60, event),
    )


def open_case(fx: Fixture, *, status: str = "open", **alert: Any) -> str:
    """One case opened by one alert received at T0. `acknowledged` also writes the ack event
    at T0; `closed` closes it at T0."""
    event = fx.alert(**alert)
    place(fx, event, 0)
    assert fx.assign()[1] == 1
    case = str(fx.one("SELECT id FROM soc_case")[0])
    fx.run("UPDATE soc_case SET opened_at = %s::timestamptz", (T0,))
    fx.run("UPDATE case_event SET at = %s::timestamptz", (T0,))
    if status == "acknowledged":
        fx.run("UPDATE soc_case SET status = 'acknowledged'")
        fx.run(
            "INSERT INTO case_event (at, client_id, case_id, actor, kind) "
            "SELECT %s::timestamptz, client_id, id, 'alex@example.com', 'acked' FROM soc_case",
            (T0,),
        )
    elif status == "closed":
        fx.run("UPDATE soc_case SET status = 'closed', closed_at = %s::timestamptz", (T0,))
    fx.run("DELETE FROM notification")  # the first page is not what these tests look at
    return case


def alert_at(fx: Fixture, minutes: float, **kw: Any) -> str:
    event = fx.alert(**kw)
    place(fx, event, minutes)
    return event


def plant(fx: Fixture, case: str, minutes: float, **kw: Any) -> None:
    """An alert already attached to `case`, so the grouping window has a recent alert."""
    event = fx.alert(**kw)
    place(fx, event, minutes)
    fx.run("UPDATE alert SET case_id = %s WHERE event_id = %s", (case, event))


def pushes(fx: Fixture) -> list[tuple[Any, ...]]:
    return fx.rows("SELECT kind, priority, status FROM notification ORDER BY created_at, kind")


# ---- R3 (a): an acknowledged case gains alerts an hour after the acknowledgement ----


@pytest.mark.parametrize(
    ("minutes", "pushed"), [(59, False), (59.99, False), (60, True), (61, True), (600, True)]
)
def test_an_acknowledged_case_is_pushed_again_at_sixty_minutes(
    fx: Fixture, minutes: float, pushed: bool
) -> None:
    case = open_case(fx, status="acknowledged")
    plant(fx, case, minutes - 1)
    new = alert_at(fx, minutes)
    result = fx.assign()
    assert result == (1, 0, 1 if pushed else 0)
    assert pushes(fx) == ([("reopen", 3, "pending")] if pushed else [])
    assert str(fx.one("SELECT case_id FROM alert WHERE event_id = %s", (new,))[0]) == case
    events = [r[0] for r in fx.rows("SELECT kind FROM case_event WHERE kind = 'repushed'")]
    assert events == (["repushed"] if pushed else [])


def test_the_reopen_push_clock_restarts_from_that_push(fx: Fixture) -> None:
    case = open_case(fx, status="acknowledged")
    plant(fx, case, 59)
    for minutes in (60, 100, 119, 120, 150):
        alert_at(fx, minutes)
    assert fx.assign() == (5, 0, 2)  # one at 60, the next at 120: never inside the hour
    assert pushes(fx) == [("reopen", 3, "pending"), ("reopen", 3, "pending")]
    stamps = fx.rows(
        "SELECT extract(epoch FROM at - %s::timestamptz) / 60 "
        "FROM case_event WHERE kind = 'repushed' ORDER BY at",
        (T0,),
    )
    assert [float(r[0]) for r in stamps] == [60.0, 120.0]


def test_an_open_case_is_not_pushed_again_for_new_alerts(fx: Fixture) -> None:
    case = open_case(fx)
    plant(fx, case, 599)
    alert_at(fx, 600)
    assert fx.assign() == (1, 0, 0) and pushes(fx) == []


def test_a_closed_case_is_never_reopened_a_new_case_opens(fx: Fixture) -> None:
    case = open_case(fx, status="closed")
    plant(fx, case, 599)
    new = alert_at(fx, 600)
    assert fx.assign() == (1, 1, 1)
    assert pushes(fx) == [("page", 3, "pending")]
    new_case = str(fx.one("SELECT case_id FROM alert WHERE event_id = %s", (new,))[0])
    assert new_case != case
    assert fx.one("SELECT status FROM soc_case WHERE id = %s", (case,)) == ("closed",)


def test_the_reopen_push_follows_the_policy_and_the_case_severity(fx: Fixture) -> None:
    case = open_case(fx, status="acknowledged", severity="high")
    plant(fx, case, 99)
    alert_at(fx, 100, cat="QUIET")
    alert_at(fx, 101, cat="LOUD")
    with fx.worker() as w:
        w.execute(
            "SELECT * FROM assign_cases(10, %s::jsonb)", ('{"QUIET": 0, "LOUD": 2}',)
        ).fetchall()
    # the quiet one is console-only and sends nothing; the next alert is an hour from nothing,
    # so it pushes at the priority the policy gives its category
    assert pushes(fx) == [("reopen", 2, "pending")]


def test_the_reopen_push_defaults_to_the_severity_of_the_case(fx: Fixture) -> None:
    case = open_case(fx, status="acknowledged", severity="high")
    plant(fx, case, 99)
    alert_at(fx, 100, severity="low")
    fx.assign()
    assert pushes(fx) == [("reopen", 5, "pending")]


def test_an_unassigned_client_reopens_loudly(fx: Fixture) -> None:
    case = open_case(fx, status="acknowledged", tenant="some-other-tenant", severity="low")
    plant(fx, case, 99, tenant="some-other-tenant")
    alert_at(fx, 100, tenant="some-other-tenant", severity="low", cat="QUIET")
    fx.assign(policy={"QUIET": 1})
    assert pushes(fx) == [("reopen", 4, "pending")]


# ---- R3 (b): a case stops collecting after 24 hours ----

DAY = 24 * 60


@pytest.mark.parametrize(
    ("minutes", "same_case"),
    [(DAY - 1, True), (DAY - 0.01, True), (DAY, False), (DAY + 1, False)],
)
def test_a_case_stops_collecting_after_twenty_four_hours(
    fx: Fixture, minutes: float, same_case: bool
) -> None:
    case = open_case(fx)
    plant(fx, case, minutes - 1)
    new = alert_at(fx, minutes)
    result = fx.assign()
    assert result == ((1, 0, 0) if same_case else (1, 1, 1))
    got = str(fx.one("SELECT case_id FROM alert WHERE event_id = %s", (new,))[0])
    assert (got == case) is same_case
    assert pushes(fx) == ([] if same_case else [("page", 3, "pending")])


def test_the_new_case_after_the_limit_collects_what_follows(fx: Fixture) -> None:
    case = open_case(fx)
    plant(fx, case, DAY + 9)
    first = alert_at(fx, DAY + 10)
    second = alert_at(fx, DAY + 20)
    assert fx.assign() == (2, 1, 1)
    cases = {
        str(r[0])
        for r in fx.rows("SELECT case_id FROM alert WHERE event_id IN (%s, %s)", (first, second))
    }
    assert len(cases) == 1 and case not in cases


def test_an_acknowledged_case_also_stops_at_twenty_four_hours(fx: Fixture) -> None:
    case = open_case(fx, status="acknowledged")
    plant(fx, case, DAY - 2)
    alert_at(fx, DAY - 1)
    alert_at(fx, DAY)
    assert fx.assign() == (2, 1, 2)  # a reopen push, then a first page for the new case
    assert sorted(pushes(fx)) == [("page", 3, "pending"), ("reopen", 3, "pending")]


# ---- R3 (c): a higher severity raises the case and pages ----


@pytest.mark.parametrize(
    ("first", "second", "raised"),
    [
        ("low", "low", False),
        ("high", "high", False),
        ("high", "low", False),
        ("critical", "info", False),
        ("low", "medium", True),
        ("medium", "high", True),
        ("high", "critical", True),
        ("info", "critical", True),
    ],
)
def test_only_a_higher_severity_raises_the_case_and_pushes(
    fx: Fixture, first: str, second: str, raised: bool
) -> None:
    case = open_case(fx, severity=first)
    plant(fx, case, 4)
    alert_at(fx, 5, severity=second)
    assert fx.assign() == (1, 0, 1 if raised else 0)
    assert fx.one("SELECT severity FROM soc_case WHERE id = %s", (case,)) == (
        (second,) if raised else (first,)
    )
    events = fx.rows("SELECT body FROM case_event WHERE kind = 'severity_raised'")
    assert events == ([(f"{first} to {second}",)] if raised else [])
    assert [p[0] for p in pushes(fx)] == (["raised"] if raised else [])


def test_a_raise_pushes_once_even_when_acknowledged_and_an_hour_has_passed(fx: Fixture) -> None:
    case = open_case(fx, status="acknowledged", severity="low")
    plant(fx, case, 99)
    alert_at(fx, 100, severity="critical")
    assert fx.assign() == (1, 0, 1)
    assert pushes(fx) == [("raised", 5, "pending")]


def test_raises_can_repeat_and_each_one_pushes(fx: Fixture) -> None:
    case = open_case(fx, severity="low")
    plant(fx, case, 4)
    alert_at(fx, 5, severity="medium")
    alert_at(fx, 6, severity="high")
    assert fx.assign() == (2, 0, 2)
    assert [p[0] for p in pushes(fx)] == ["raised", "raised"]
    assert fx.one("SELECT severity FROM soc_case") == ("high",)


def test_a_raise_on_a_closed_case_opens_a_new_case_instead(fx: Fixture) -> None:
    case = open_case(fx, status="closed", severity="low")
    plant(fx, case, 4)
    alert_at(fx, 5, severity="critical")
    assert fx.assign() == (1, 1, 1)
    assert fx.one("SELECT severity FROM soc_case WHERE id = %s", (case,)) == ("low",)


def test_the_new_notification_kinds_may_repeat_but_the_old_ones_stay_unique(fx: Fixture) -> None:
    import psycopg

    case = open_case(fx, severity="low")
    for kind in ("raised", "raised", "reopen", "reopen"):
        fx.run(
            "INSERT INTO notification (client_id, case_id, channel, priority, kind) "
            "SELECT client_id, id, 'ntfy', 3, %s FROM soc_case",
            (kind,),
        )
    fx.run(
        "INSERT INTO notification (client_id, case_id, channel, priority) "
        "SELECT client_id, id, 'ntfy', 3 FROM soc_case"
    )
    with pytest.raises(psycopg.errors.UniqueViolation):
        fx.run(
            "INSERT INTO notification (client_id, case_id, channel, priority) "
            "SELECT client_id, id, 'ntfy', 3 FROM soc_case"
        )
    assert case


# ---- the repage queue still works with the new index ----


def test_resends_still_queue_once_each(fx: Fixture) -> None:
    case = open_case(fx, severity="high")
    fx.run(
        "INSERT INTO notification (client_id, case_id, channel, priority, status, sent_at) "
        "SELECT client_id, id, 'ntfy', 5, 'sent', now() - interval '90 minutes' FROM soc_case"
    )
    with fx.worker() as w:
        first = w.execute("SELECT queue_repages('15 minutes', '60 minutes')").fetchone()
        again = w.execute("SELECT queue_repages('15 minutes', '60 minutes')").fetchone()
    assert first == (1,) and again == (0,) and case


# ---- R4: group on the sensor id ----

SID_A = "11111111-1111-4111-8111-111111111111"
SID_B = "22222222-2222-4222-8222-222222222222"


def test_one_sensor_is_one_case_whatever_the_host_is_called(fx: Fixture) -> None:
    fx.alert(sid=SID_A, host="ws-01", age_min=10)
    fx.alert(sid=SID_A, host="renamed-box", age_min=5)
    fx.alert(sid=SID_A, host=None)
    assert fx.assign() == (3, 1, 1)


def test_two_sensors_with_one_host_name_are_two_cases(fx: Fixture) -> None:
    fx.alert(sid=SID_A, host="ws-01", age_min=10)
    fx.alert(sid=SID_B, host="ws-01", age_min=5)
    assert fx.assign() == (2, 2, 2)


def test_without_a_sensor_id_the_host_name_still_groups(fx: Fixture) -> None:
    fx.alert(host="ws-01", age_min=10)
    fx.alert(host="ws-01", age_min=5)
    fx.alert(host="ws-02")
    assert fx.assign() == (3, 2, 2)


def test_an_empty_sensor_id_counts_as_none(fx: Fixture) -> None:
    fx.alert(sid="", host="ws-01", age_min=10)
    fx.alert(host="ws-01", age_min=5)
    assert fx.assign() == (2, 1, 1)


@pytest.mark.parametrize(
    "kw",
    [
        {"host": None},
        {"host": ""},
        {"host": None, "sid": ""},
    ],
)
def test_alerts_with_no_sensor_and_no_host_group_by_rule(fx: Fixture, kw: dict[str, Any]) -> None:
    # Org-level and synthetic detections: one case per rule, not one page per alert.
    fx.alert(age_min=10, **kw)
    fx.alert(age_min=5, **kw)
    fx.alert(**kw)
    assert fx.assign() == (3, 1, 1)


def test_a_hostless_alert_never_joins_a_case_with_a_sensor(fx: Fixture) -> None:
    fx.alert(sid=SID_A, age_min=10)
    fx.alert(host=None)
    assert fx.assign() == (2, 2, 2)


def test_alerts_with_no_rule_are_never_grouped_even_with_a_sensor(fx: Fixture) -> None:
    fx.alert(rule=None, sid=SID_A, age_min=10)
    fx.alert(rule=None, sid=SID_A)
    assert fx.assign() == (2, 2, 2)


def test_a_sensor_id_never_equals_a_host_name(fx: Fixture) -> None:
    fx.alert(sid=SID_A, host="x", age_min=10)
    fx.alert(host=SID_A)  # a host that happens to be called like a sensor id
    assert fx.assign() == (2, 2, 2)


def test_the_grouping_index_is_on_the_sensor_key(fx: Fixture) -> None:
    [definition] = fx.one("SELECT indexdef FROM pg_indexes WHERE indexname = 'alert_case_group'")
    assert "sid" in definition and "hostname" in definition
    assert "WHERE (case_id IS NOT NULL)" in definition


# ---- R2: fairness in the claim order ----


def noisy_and_quiet(fx: Fixture, noisy: int = 12) -> None:
    """`noisy` urgent pages for one host (a rule each, all older), one low page for another."""
    for i in range(noisy):
        fx.alert(host="noisy-host", rule=f"general.Noisy {i}", cat=f"N{i}", age_min=100 - i)
    fx.alert(host="quiet-host", rule="general.Quiet", cat="Q", age_min=1)
    fx.assign(policy={f"N{i}": 5 for i in range(noisy)} | {"Q": 3})


def test_one_noisy_host_cannot_starve_the_other_host(fx: Fixture) -> None:
    noisy_and_quiet(fx)
    first = claim(fx, batch=4)
    hosts = {p["host"] for p in first}
    assert "quiet-host" in hosts and "noisy-host" in hosts
    # ...although every noisy page is older and more urgent
    quiet = next(p for p in first if p["host"] == "quiet-host")
    assert quiet["priority"] == 3


def test_a_batch_big_enough_for_everything_sends_everything(fx: Fixture) -> None:
    noisy_and_quiet(fx)
    assert len(claim(fx, batch=13)) == 13


def test_more_pages_for_the_same_host_and_rule_wait_behind_the_other_groups(fx: Fixture) -> None:
    # host-1 / Rule One: three cases an hour and a bit apart (a page each), then two other groups
    for minutes_ago in (400, 300, 200):
        fx.alert(host="host-1", rule="general.Rule One", cat="REPEAT", age_min=minutes_ago)
    fx.alert(host="host-2", rule="general.Rule One", cat="OTHER", age_min=1)
    fx.alert(host="host-1", rule="general.Rule Two", cat="OTHER", age_min=1)
    fx.assign(policy={"REPEAT": 5, "OTHER": 3})
    first = claim(fx, batch=3)
    assert sorted((p["host"], p["rule"]) for p in first) == [
        ("host-1", "general.Rule One"),
        ("host-1", "general.Rule Two"),
        ("host-2", "general.Rule One"),
    ]
    rest = claim(fx, batch=10)
    assert [(p["host"], p["rule"]) for p in rest] == [("host-1", "general.Rule One")] * 2


def test_a_group_pushed_inside_the_window_goes_after_a_fresh_one(fx: Fixture) -> None:
    fx.alert(host="host-1", rule="general.Rule One", cat="A", age_min=300)
    fx.assign(policy={"A": 3})
    fx.run("UPDATE notification SET status = 'sent', sent_at = now() - interval '2 minutes'")
    fx.alert(host="host-1", rule="general.Rule One", cat="A", age_min=1)  # a new case, same group
    fx.run("UPDATE soc_case SET opened_at = opened_at")  # keep the first case's age out of it
    fx.alert(host="host-3", rule="general.Rule Three", cat="B", age_min=0.5)
    fx.assign(policy={"A": 5, "B": 3})
    [first] = claim(fx, batch=1)
    assert first["host"] == "host-3"  # lower priority, but nothing was pushed about it lately


def test_a_push_older_than_the_window_does_not_count(fx: Fixture) -> None:
    fx.alert(host="host-1", rule="general.Rule One", cat="A", age_min=300)
    fx.assign(policy={"A": 3})
    fx.run("UPDATE notification SET status = 'sent', sent_at = now() - interval '11 minutes'")
    fx.alert(host="host-1", rule="general.Rule One", cat="A", age_min=1)
    fx.alert(host="host-3", rule="general.Rule Three", cat="B", age_min=0.5)
    fx.assign(policy={"A": 5, "B": 3})
    [first] = claim(fx, batch=1)
    assert first["host"] == "host-1"  # priority decides again


def test_the_fairness_window_is_an_argument(fx: Fixture) -> None:
    fx.alert(host="host-1", rule="general.Rule One", cat="A", age_min=300)
    fx.assign(policy={"A": 3})
    fx.run("UPDATE notification SET status = 'sent', sent_at = now() - interval '11 minutes'")
    fx.alert(host="host-1", rule="general.Rule One", cat="A", age_min=1)
    fx.alert(host="host-3", rule="general.Rule Three", cat="B", age_min=0.5)
    fx.assign(policy={"A": 5, "B": 3})
    with fx.worker() as w:
        [row] = w.execute("SELECT host FROM claim_pages(1, '15 minutes')").fetchall()
    assert row == ("host-3",)


@pytest.mark.parametrize("window", [None, "0 seconds", "8 days"])
def test_a_bad_fairness_window_is_refused(fx: Fixture, window: str | None) -> None:
    import psycopg

    with fx.worker() as w, pytest.raises(psycopg.errors.RaiseException, match="window"):
        w.execute("SELECT * FROM claim_pages(5, %s::interval)", (window,))


def test_the_old_one_argument_call_still_works(fx: Fixture) -> None:
    fx.alert()
    fx.assign()
    assert len(claim(fx)) == 1


# ---- the held notice's numbers ----


def test_held_summary_counts_pages_hosts_and_the_highest_severity(fx: Fixture) -> None:
    fx.alert(host="h1", rule="general.A", severity="low", age_min=5)
    fx.alert(host="h1", rule="general.B", severity="high", age_min=4)
    fx.alert(host="h2", rule="general.A", severity="medium", age_min=3)
    fx.alert(sid=SID_A, host="h1", rule="general.C", severity="low", age_min=2)
    fx.assign()
    with fx.worker() as w:
        assert w.execute("SELECT * FROM held_summary()").fetchone() == (4, 3, "high")


def test_held_summary_with_nothing_waiting(fx: Fixture) -> None:
    with fx.worker() as w:
        assert w.execute("SELECT * FROM held_summary()").fetchone() == (0, 0, None)


def test_held_summary_ignores_pages_not_due_and_resends_of_acknowledged_cases(
    fx: Fixture,
) -> None:
    fx.alert(host="h1", severity="critical")
    fx.alert(host="h2", rule="general.B", severity="low")
    fx.assign()
    fx.run("UPDATE notification SET next_attempt_at = now() + interval '1 hour' WHERE priority = 5")
    with fx.worker() as w:
        assert w.execute("SELECT * FROM held_summary()").fetchone() == (1, 1, "low")


# ---- grants, owner, and the way back ----


def test_owners_and_callers_of_the_changed_functions(fx: Fixture) -> None:
    rows = fx.rows(
        "SELECT p.proname, r.rolname, p.prosecdef FROM pg_proc p "
        "JOIN pg_roles r ON r.oid = p.proowner "
        "WHERE p.proname IN ('assign_cases', 'claim_pages', 'held_summary') ORDER BY 1"
    )
    assert rows == [
        ("assign_cases", "soc_worker_writer", True),
        ("claim_pages", "soc_worker_writer", True),
        ("held_summary", "soc_worker_writer", True),
    ]
    for function in (
        "assign_cases(integer, jsonb)",
        "claim_pages(integer, interval)",
        "held_summary()",
    ):
        for role, allowed in (
            ("soc_worker", True),
            ("soc_console", False),
            ("soc_ingest", False),
            ("soc_app", False),
            ("public", False),
        ):
            got = fx.one(
                "SELECT has_function_privilege(%s, %s::regprocedure, 'EXECUTE')",
                (role, function),
            )
            assert got == (allowed,), f"{role} on {function}"


def test_the_writer_gained_only_the_two_narrow_rights(fx: Fixture) -> None:
    def col(table: str, column: str, privilege: str) -> Any:
        return fx.one(
            "SELECT has_column_privilege('soc_worker_writer', %s, %s, %s)",
            (table, column, privilege),
        )[0]

    assert col("soc_case", "severity", "UPDATE") is True
    for column in ("status", "closed_at", "closing_note", "client_id", "id"):
        assert col("soc_case", column, "UPDATE") is False
    for column in ("client_id", "case_id", "at", "kind"):
        assert col("case_event", column, "SELECT") is True
    for column in ("actor", "body", "id"):
        assert col("case_event", column, "SELECT") is False
    assert fx.one("SELECT has_table_privilege('soc_worker_writer', 'case_event', 'SELECT')") == (
        False,
    )


def snapshot(fx: Fixture) -> dict[str, Any]:
    functions = {
        name: fx.one("SELECT pg_get_functiondef(%s::regprocedure)", (name,))[0]
        for name in (
            "assign_cases(integer, jsonb)",
            "queue_repages(interval, interval)",
        )
    }
    claim_def = fx.one(
        "SELECT pg_get_functiondef(p.oid) FROM pg_proc p WHERE p.proname = 'claim_pages'"
    )[0]
    return {
        "functions": functions,
        "claim": claim_def,
        "claim_count": fx.one("SELECT count(*) FROM pg_proc WHERE proname = 'claim_pages'")[0],
        "indexes": fx.rows(
            "SELECT indexname, indexdef FROM pg_indexes "
            "WHERE indexname IN ('alert_case_group', 'notification_case_kind') ORDER BY 1"
        ),
        "constraint": fx.rows(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'notification_kind_check'"
        ),
        "acl": fx.rows(
            "SELECT proname, proacl::text, proowner::regrole::text, prosecdef, proconfig::text "
            "FROM pg_proc WHERE proname IN ('assign_cases', 'claim_pages', 'queue_repages') "
            "ORDER BY 1"
        ),
        "policies": fx.rows(
            "SELECT tablename, policyname FROM pg_policies "
            "WHERE roles = '{soc_worker_writer}' ORDER BY 1, 2"
        ),
        "colprivs": fx.rows(
            "SELECT table_name, column_name, privilege_type "
            "FROM information_schema.column_privileges "
            "WHERE grantee = 'soc_worker_writer' AND table_name IN ('soc_case', 'case_event') "
            "ORDER BY 1, 2, 3"
        ),
        "held": fx.one("SELECT to_regprocedure('held_summary()')")[0],
    }


def test_downgrade_restores_the_previous_definitions_exactly(fx: Fixture) -> None:
    url = fx.db.sqlalchemy_url()
    head = snapshot(fx)
    assert head["held"] == "held_summary()"
    soc_db.downgrade(url, "0016")
    after_down = snapshot(fx)
    assert after_down["held"] is None
    assert after_down["claim_count"] == 1
    assert after_down != head
    # the previous definitions are what the previous migrations themselves build
    soc_db.downgrade(url, "0004")
    soc_db.upgrade(url, "0016")
    assert snapshot(fx) == after_down
    # and forward again gives the new ones back, byte for byte
    soc_db.upgrade(url)
    assert snapshot(fx) == head


def test_downgrade_drops_the_new_notification_kinds_and_keeps_the_history(fx: Fixture) -> None:
    case = open_case(fx, status="acknowledged")
    plant(fx, case, 99)
    alert_at(fx, 100)
    fx.assign()
    assert pushes(fx) == [("reopen", 3, "pending")]
    soc_db.downgrade(fx.db.sqlalchemy_url(), "0016")
    assert fx.rows("SELECT kind FROM notification") == []
    assert fx.one("SELECT count(*) FROM case_event WHERE kind = 'repushed'") == (1,)
    soc_db.upgrade(fx.db.sqlalchemy_url())
