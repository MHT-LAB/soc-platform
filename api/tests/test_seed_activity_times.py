"""The demo activity must look the same whatever time of day it is seeded.

The seed's random generator is fixed, but how many draws the times take depends on the hour
(busy hours accept more often), so a shared stream laid out a different set of cases on every
run and the demo's figures moved with the clock. The times now have their own stream and every
other draw is made whatever a case's age is: the same seed makes the same cases at any hour.
The queue and the funnel also need open cases in the last week at every hour.
"""

import json
import random
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from conftest import SEED_FILE

from soc_api import seed as soc_seed


class _Recorder:
    """Stands in for the connection: keeps the cases the seed would insert."""

    def __init__(self) -> None:
        self.cases: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.pages: list[dict[str, Any]] = []

    def execute(self, statement: Any, params: Any = None) -> None:
        sql = str(statement)
        if "INSERT INTO soc_case" in sql:
            self.cases = list(params)
        elif "INSERT INTO alert" in sql:
            self.alerts = list(params)
        elif "INSERT INTO notification" in sql:
            self.pages = list(params)


def _laid_out_at(now: datetime) -> _Recorder:
    spec = json.loads(SEED_FILE.read_text())["activity"]
    conn = _Recorder()
    soc_seed._activity_cases(  # noqa: SLF001 - the case layout is what is under test
        conn,  # type: ignore[arg-type]
        1,
        defaultdict(int),
        spec,
        random.Random(spec["seed"]),  # noqa: S311 - synthetic demo data
        now,
    )
    return conn


def _cases_at(now: datetime) -> list[dict[str, Any]]:
    return _laid_out_at(now).cases


def test_the_demo_has_open_and_acknowledged_cases_this_week_at_every_time_of_day() -> None:
    day = datetime(2026, 11, 16, tzinfo=UTC)
    missing = []
    for minutes in range(0, 24 * 60, 10):
        now = day + timedelta(minutes=minutes)
        week = [c for c in _cases_at(now) if c["opened"] >= now - timedelta(days=7)]
        statuses = {c["status"] for c in week}
        if not {"open", "acknowledged"} <= statuses:
            missing.append(f"{now:%H:%M} {sorted(statuses)}")
    assert missing == []


def _what_happened(now: datetime) -> dict[str, Any]:
    """Everything the seed decides apart from when: the ids, rules, hosts, how many alerts."""
    laid = _laid_out_at(now)
    return {
        "cases": [(c["id"], c["sev"], c["lane"]) for c in laid.cases],
        "alerts": [(a["id"], a["case"], a["ev"], a["rule"], a["summary"]) for a in laid.alerts],
        "paged": [p["case"] for p in laid.pages],
    }


def test_the_same_seed_makes_the_same_cases_at_any_hour_and_on_any_day() -> None:
    base = _what_happened(datetime(2026, 11, 16, 0, 0, tzinfo=UTC))
    assert len(base["cases"]) == 260 and base["alerts"]
    for when in (
        datetime(2026, 11, 16, 3, 30, tzinfo=UTC),
        datetime(2026, 11, 16, 9, 0, tzinfo=UTC),
        datetime(2026, 11, 16, 14, 45, tzinfo=UTC),
        datetime(2026, 11, 16, 21, 10, tzinfo=UTC),
        datetime(2026, 12, 3, 11, 0, tzinfo=UTC),
    ):
        assert _what_happened(when) == base, when


def test_only_the_times_differ_between_two_runs_and_a_rerun_is_identical() -> None:
    a, b = datetime(2026, 11, 16, 4, 0, tzinfo=UTC), datetime(2026, 11, 16, 15, 0, tzinfo=UTC)
    assert _cases_at(a) == _cases_at(a)
    assert [c["opened"] for c in _cases_at(a)] != [c["opened"] for c in _cases_at(b)]
