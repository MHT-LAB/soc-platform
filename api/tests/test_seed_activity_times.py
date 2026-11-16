"""The demo activity must look the same whatever time of day it is seeded.

The seed's random generator is fixed, but how many draws it takes depends on the hour, so
each run lays out a different set of cases. The queue and the funnel need open cases in
the last week at every hour, not just most of them.
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

    def execute(self, statement: Any, params: Any = None) -> None:
        if "INSERT INTO soc_case" in str(statement):
            self.cases = list(params)


def _cases_at(now: datetime) -> list[dict[str, Any]]:
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
    return conn.cases


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
