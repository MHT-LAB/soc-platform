"""Pager bounds (migration 0017), the worker and console side: the words of the new pushes,
the held notice, the claim order through a real tick, and the case history.

The worker's own clock is fixed to a Wednesday so no test can cross the weekly OK push.
"""

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from conftest import ROLE_PASSWORD, TestDb
from test_pager_bounds_db import T0, open_case, place, plant, pushes
from test_worker import (  # noqa: F401
    Clock,
    FakeNtfy,
    fresh_settings,
    make_worker,
)
from test_worker_db import Fixture

from soc_api import worker as w

WEDNESDAY = datetime(2026, 3, 11, 15, 0, tzinfo=UTC)


@pytest.fixture
def ntfy_server() -> Iterator[FakeNtfy]:
    fake = FakeNtfy()
    yield fake
    fake.server.shutdown()
    fake.server.server_close()


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def fixed_clock() -> Clock:
    clock = Clock()
    clock.now = WEDNESDAY
    return clock


def page(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "client_slug": "client-a",
        "rule": "general.Rule One",
        "host": "host-1",
        "detected_at": WEDNESDAY,
        "case_short": "abcd1234",
        "priority": 4,
        "kind": "page",
    }
    return base | kw


# ---- the words ----


@pytest.mark.parametrize(
    ("kind", "title"),
    [
        ("page", "client-a: Rule One"),
        ("repage1", "REPEAT: client-a: Rule One"),
        ("repage2", "REPEAT: client-a: Rule One"),
        ("reopen", "NEW ALERTS: client-a: Rule One"),
        ("raised", "RAISED: client-a: Rule One"),
    ],
)
def test_the_title_says_what_kind_of_push_it_is(kind: str, title: str) -> None:
    assert w.push_text(page(kind=kind))[0] == title


@pytest.mark.parametrize("kind", ["reopen", "raised"])
def test_a_new_alerts_push_is_never_marked_late(kind: str) -> None:
    title = w.push_text(page(kind=kind, late_s=99999.0))[0]
    assert "LATE" not in title


def test_an_unknown_kind_gets_no_prefix_from_the_database() -> None:
    assert w.push_text(page(kind="<script>"))[0] == "client-a: Rule One"


def test_held_text_is_counts_and_a_fixed_word() -> None:
    assert w.held_text(5, 3, "high", 10, 10) == (
        "5 more pages are waiting (3 hosts, highest severity high; limit 10 per 10 min). "
        "Check the detection email."
    )
    assert "1 host," in w.held_text(2, 1, "low", 10, 10)
    assert "severity" not in w.held_text(2, 1, None, 10, 10)


def test_held_text_refuses_any_severity_word_it_does_not_know() -> None:
    assert "evil" not in w.held_text(2, 1, "evil", 10, 10)


@pytest.mark.parametrize(
    ("kind", "words"),
    [
        ("opened", "Case opened"),
        ("alert_attached", "Another alert added"),
        ("acked", "Acknowledged"),
        ("closed", "Closed"),
        ("severity_raised", "Severity raised"),
        ("repushed", "Pushed again"),
        ("something_new", "something_new"),
        (None, ""),
    ],
)
def test_the_case_history_uses_plain_words(kind: Any, words: str) -> None:
    from soc_api.console import event_label

    assert event_label(kind) == words


# ---- through a real tick ----


def titles(fake: FakeNtfy) -> list[str]:
    return [t for t in fake.titles() if t != "SOC: pages held"]


def test_an_acknowledged_case_gets_one_new_alerts_push_then_the_clock_restarts(
    fx: Fixture, ntfy_server: FakeNtfy
) -> None:
    case = open_case(fx, status="acknowledged")
    plant(fx, case, 99)
    worker = make_worker(fx, ntfy_server, clock=fixed_clock())
    worker.tick()
    assert titles(ntfy_server) == []  # nothing new yet
    for minutes in (100, 101, 130):
        place(fx, fx.alert(), minutes)
    worker.tick()
    assert titles(ntfy_server) == ["NEW ALERTS: client-a: Rule One"]
    worker.tick()
    assert titles(ntfy_server) == ["NEW ALERTS: client-a: Rule One"]  # not sent twice
    assert [p[0] for p in pushes(fx)] == ["reopen"]
    assert fx.one("SELECT status FROM notification") == ("sent",)


def test_a_raise_sends_a_raised_push(fx: Fixture, ntfy_server: FakeNtfy) -> None:
    case = open_case(fx, severity="low")
    plant(fx, case, 4)
    place(fx, fx.alert(severity="critical"), 5)
    worker = make_worker(fx, ntfy_server, clock=fixed_clock())
    worker.tick()
    [push] = ntfy_server.pushes
    assert push["title"] == "RAISED: client-a: Rule One" and push["priority"] == 5


def test_a_flood_from_one_host_does_not_hold_back_the_other_host(
    fx: Fixture, ntfy_server: FakeNtfy
) -> None:
    for i in range(15):
        fx.alert(host="noisy-host", rule=f"general.Noisy {i}", cat=f"N{i}", age_min=100 - i)
    fx.alert(host="quiet-host", rule="general.Quiet One", cat="Q", age_min=1)
    policy = {f"N{i}": 5 for i in range(15)} | {"Q": 3}
    worker = make_worker(
        fx, ntfy_server, policy=policy, clock=fixed_clock(), limits=w.Limits(page_cap=5)
    )
    worker.tick()
    sent = titles(ntfy_server)
    assert len(sent) == 5
    assert "client-a: Quiet One" in sent  # in the first window, behind none of the noisy ones


def test_the_held_notice_says_how_many_from_how_many_hosts_and_how_bad(
    fx: Fixture, ntfy_server: FakeNtfy
) -> None:
    for i in range(14):
        fx.alert(
            host=f"secret-host-{i % 4}",
            rule=f"general.R{i}",
            severity="high" if i == 3 else "low",
            age_min=20 - i * 0.1,
        )
    worker = make_worker(
        fx, ntfy_server, clock=fixed_clock(), limits=w.Limits(page_cap=10, cap_window_s=600)
    )
    worker.tick()
    [held] = [p for p in ntfy_server.pushes if p["title"] == "SOC: pages held"]
    assert held["message"].startswith("4 more pages are waiting (")
    assert re.search(
        r"\(\d hosts?, highest severity (low|high); limit 10 per 10 min\)", held["message"]
    )
    for private in ("secret-host", "client-a", "general.R", "Rule"):
        assert private not in held["message"]


def test_the_held_notice_names_the_highest_severity_waiting(
    fx: Fixture, ntfy_server: FakeNtfy
) -> None:
    for i in range(3):
        fx.alert(host="h", rule=f"general.R{i}", severity="low", age_min=10 - i)
    fx.alert(host="h2", rule="general.Big", severity="critical", age_min=0.1)
    worker = make_worker(
        fx, ntfy_server, clock=fixed_clock(), limits=w.Limits(page_cap=1, cap_window_s=600)
    )
    worker.tick()
    [held] = [p for p in ntfy_server.pushes if p["title"] == "SOC: pages held"]
    assert held["message"] == (
        "3 more pages are waiting (1 host, highest severity low; limit 1 per 10 min). "
        "Check the detection email."
    )


# ---- the case page ----


def test_the_case_page_shows_the_new_events_in_plain_words(fx: Fixture) -> None:
    from test_console_cases import get_headers, make_client

    case = open_case(fx, status="acknowledged", severity="low")
    plant(fx, case, 99)
    place(fx, fx.alert(severity="high"), 100)
    fx.assign()
    text = make_client(fx).get(f"/console/case/{case}", headers=get_headers()).text
    for words in (
        "Case opened",
        "Acknowledged",
        "Another alert added",
        "Severity raised",
        "Pushed again",
    ):
        assert words in text
    assert "low to high" in text and "higher severity" in text
    assert ">repushed<" not in text and ">alert_attached<" not in text
    assert ROLE_PASSWORD not in text and T0
