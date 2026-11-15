"""The signal flow as the console serves it, on the seeded demo tenant."""

import re
from datetime import UTC, datetime

import pytest
from conftest import SEED_FILE, TestDb
from fastapi.testclient import TestClient
from test_ops_overview_pages import PAGES, SLUGS, client, get, sql

from soc_api import console
from soc_api import seed as soc_seed


@pytest.fixture
def demo(db: TestDb) -> TestClient:
    soc_seed.seed(db.sqlalchemy_url(), SEED_FILE)
    soc_seed.seed_activity(db.sqlalchemy_url(), SEED_FILE, now=datetime.now(UTC))
    return client(db)


def svg(c: TestClient, path: str = "/console/overview") -> str:
    text: str = get(c, path).text
    m = re.search(r'<svg class="flowsvg".*?</svg[^>]*>', text, re.S | re.I)
    assert m, "no signal flow"
    return m.group(0)


def test_the_flow_shows_all_three_groups_with_one_offline_and_one_quiet(demo: TestClient) -> None:
    s = svg(demo)
    for name in ("Endpoints", "Network sensors", "Vendor feeds"):
        assert f">{name}<" in s
    assert "12 endpoints · 1 offline" in s
    assert "2 network sensors · 1 quiet" in s and "1 vendor feed" in s
    assert "13 of 15 reporting" in s
    assert s.count("M3 3h12v12H3z") >= 12 and "M9 1l8 8-8 8-8-8z" in s and "M9 2l8 14H1z" in s
    assert "quiet · last message 3d ago" in s and "offline · last seen 3h 00m ago" in s
    assert s.count('class="ficon off"') == 2


def test_the_flow_numbers_are_the_database_numbers(demo: TestClient) -> None:
    page = get(demo, "/console/overview").text
    found = re.search(r"([\d,]+) alerts in, ([\d,]+) pages", page)
    assert found
    s = svg(demo)
    assert f">{found.group(1)}<" in s and "every source, 7 days" in s
    for title in ("ALERTS IN", "CASES", "PAGED", "QUIET LANE"):
        assert f">{title}<" in s
    assert "every source, today" in svg(demo, "/console/overview?period=1")
    assert "every source, 30 days" in svg(demo, "/console/overview?period=30")


def test_the_flow_moves_only_by_css_and_stops_for_reduced_motion(demo: TestClient) -> None:
    css = (console.HERE / "static" / "console.css").read_text()
    assert "@keyframes fdash" in css and "animation: fdash" in css
    reduced = re.search(r"@media \(prefers-reduced-motion: reduce\) \{([^}]*)\}", css)
    assert reduced and ".ffeed" in reduced.group(1) and "animation: none" in reduced.group(1)
    s = svg(demo)
    assert not re.search(r"<(animate|animateMotion|animateTransform|set|script)\b", s, re.I)
    assert " style=" not in s.lower() and "<style" not in s.lower()
    assert not re.search(r"\son[a-z]+=", s, re.I) and "javascript:" not in s.lower()


def test_a_quiet_source_is_amber_everywhere_and_an_endpoint_stays_red(demo: TestClient) -> None:
    text = get(demo, "/console/overview").text
    assert "Syslog and feed sources" in text and "1 of 3 quiet" in text
    assert "1 of 3 sources quiet" in text
    assert 'class="sdot down"' not in text  # nothing red: the quiet source is amber
    fleet = get(demo, "/console/fleet").text
    assert re.search(r'chip warn">quiet · last message 3d ago<', fleet)
    assert re.search(r'chip down">offline<', fleet)


def test_a_silent_endpoint_is_offline_but_a_silent_adapter_never_is(
    demo: TestClient, db: TestDb
) -> None:
    sql(db, "UPDATE sensor_state SET online = false")
    s = svg(demo)
    assert "12 endpoints · 12 offline" in s and "2 network sensors · 2 quiet" in s
    assert "1 vendor feed · 1 quiet" in s
    fleet = get(demo, "/console/fleet").text
    assert fleet.count('chip down">offline<') == 12 and fleet.count("quiet · last message") == 3
    text = get(demo, "/console/overview").text
    assert "0/12" in text and "3 of 3 sources quiet" in text


def test_hostnames_in_the_flow_are_escaped_and_no_slug_is_anywhere(
    demo: TestClient, db: TestDb
) -> None:
    sql(
        db,
        "UPDATE sensor_state SET hostname = '<img src=x onerror=alert(1)>' "
        "WHERE hostname = 'ws-demo-01'",
    )
    for path in PAGES:
        text = get(demo, path).text
        assert "<img src=x" not in text, path
        for slug in SLUGS:
            assert slug not in text, (path, slug)
    assert "&lt;img src=x onerror=alert(1)&gt;" in svg(demo)


def test_the_flow_scrolls_inside_its_own_box_on_a_phone() -> None:
    css = (console.HERE / "static" / "console.css").read_text()
    assert re.search(r"\.flowsvg \{[^}]*min-width: \d+px", css)
    assert re.search(r"\.scroll \{[^}]*overflow-x: auto", css)
