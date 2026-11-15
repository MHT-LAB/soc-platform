"""The header clock shows UTC and local time, with a hint for turning local time into UTC."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from soc_api import overview as ov
from soc_api.config import Settings
from soc_api.main import create_console_app


def epoch(*args: int) -> float:
    return datetime(*args, tzinfo=UTC).timestamp()


def test_winter_eastern_is_utc_minus_five_and_the_hint_says_add_five() -> None:
    c = ov.clock(epoch(2026, 1, 15, 14, 5, 0), "America/New_York")
    assert c["time"] == "14:05:00"
    assert c["local"] == "9:05 AM EST"
    assert "EST = UTC − 5 hours" in c["hint"] and "add 5 hours to EST" in c["hint"]


def test_summer_eastern_is_utc_minus_four() -> None:
    c = ov.clock(epoch(2026, 7, 15, 14, 5, 0), "America/New_York")
    assert c["local"] == "10:05 AM EDT"
    assert "add 4 hours to EDT" in c["hint"]


def test_zones_ahead_of_utc_and_half_hours_and_utc_itself() -> None:
    assert "subtract 1 hour from CET" in ov.clock(epoch(2026, 1, 15, 14), "Europe/Berlin")["hint"]
    assert "5:30" in ov.clock(epoch(2026, 1, 15, 14), "Asia/Kolkata")["hint"]
    assert "same as UTC" in ov.clock(epoch(2026, 1, 15, 14), "UTC")["hint"]


def test_every_console_page_header_shows_both_clocks() -> None:
    app = create_console_app(Settings(env="dev", version="edge", git_sha="a" * 40))
    headers = {"Tailscale-User-Login": "alex@example.com"}
    text = TestClient(app).get("/console", headers=headers).text
    assert 'id="utc-clock"' in text and 'id="local-clock"' in text
    assert 'data-tz="America/New_York"' in text and "To get UTC" in text


def test_an_unknown_time_zone_refuses_to_start() -> None:
    with pytest.raises(ValueError, match="SOC_CONSOLE_TIMEZONE"):
        create_console_app(
            Settings(env="dev", version="edge", git_sha="a" * 40, console_timezone="Mars/Olympus")
        )
