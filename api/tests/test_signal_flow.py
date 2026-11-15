"""The living signal flow and the quiet-source states, worked out from the database's
document (no database here); the rendered page is checked in test_signal_flow_pages.py."""

import copy
import re
from typing import Any

import pytest
from test_ops_overview_unit import doc

from soc_api import overview as ov
from soc_api import signalflow as sf


def sensor(host: str, platform: str, online: bool, age: int = 40, **over: Any) -> dict[str, Any]:
    return {
        "hostname": host,
        "platform": platform,
        "version": "1.0",
        "online": online,
        "isolated": False,
        "last_seen_age_s": age,
        "updated_age_s": 30,
        **over,
    }


FLEET = [
    sensor("ws-1", "Windows", True),
    sensor("ws-2", "windows", False, 10800),
    sensor("srv-1", "Linux", True),
    sensor("mac-1", "macOS", True),
    sensor("gw-1", "Syslog (CEF)", True),
    sensor("gw-2", "Syslog (text)", False, 259200),
    sensor("mail-1", "Email adapter", True),
]


def flow_doc(**over: Any) -> dict[str, Any]:
    d = doc(
        period_days=7,
        fleet=copy.deepcopy(FLEET),
        funnel=[
            {"lane": "paged", "status": "open", "n": 60},
            {"lane": "paged", "status": "closed", "n": 20},
            {"lane": "quiet", "status": "closed", "n": 322},
        ],
    )
    d["health"].update(sensors_total=7, sensors_online=5)
    d.update(over)
    return d


def heights(drawing: dict[str, Any]) -> list[float]:
    return [float(b["h"]) for b in drawing["bars"]]


def test_a_platform_name_sorts_into_a_group() -> None:
    kinds = {
        p: sf.kind_of(p)
        for p in (
            "Windows",
            "linux",
            "macOS",
            "ChromeOS",
            "Unknown",
            "Syslog (CEF)",
            "Syslog (text)",
            "VPN",
            "Email adapter",
            "JSON adapter",
            "Adapter 0x0000002A",
        )
    }
    assert kinds == {
        "Windows": "endpoint",
        "linux": "endpoint",
        "macOS": "endpoint",
        "ChromeOS": "endpoint",
        "Unknown": "endpoint",  # no platform sent: keeps the strict (red) rule
        "Syslog (CEF)": "network",
        "Syslog (text)": "network",
        "VPN": "network",
        "Email adapter": "feed",
        "JSON adapter": "feed",
        "Adapter 0x0000002A": "feed",
    }


def test_an_endpoint_that_stops_is_down_and_a_silent_source_is_only_quiet() -> None:
    state = {s["hostname"]: s["state"] for s in sf.sensors(flow_doc())}
    assert state["ws-2"] == "down"
    assert state["gw-2"] == "quiet"
    assert state["ws-1"] == state["gw-1"] == state["mail-1"] == "up"
    words = {s["hostname"]: s["words"] for s in sf.sensors(flow_doc())}
    assert words["gw-2"] == "quiet · last message 3d ago"
    assert words["ws-2"] == "offline · last seen 3h 00m ago"
    assert sf.sensors(flow_doc())[0]["state"] != "up"  # problems come first


def test_the_summary_counts_endpoints_apart_from_sources() -> None:
    s = sf.summary(flow_doc())
    assert (s["endpoints"], s["endpoints_online"]) == (4, 3)
    assert (s["sources"], s["sources_quiet"], s["longest_quiet_s"]) == (3, 1, 259200)


def test_a_document_without_a_fleet_list_falls_back_to_the_plain_counts() -> None:
    s = sf.summary(doc())
    assert (s["endpoints"], s["endpoints_online"], s["sources"]) == (4, 4, 0)


def test_the_tile_and_health_say_which_is_which() -> None:
    d = flow_doc()
    tile = next(t for t in ov.status_tiles(d) if t["label"] == "Endpoints online")
    assert tile["value"] == "3/4" and "1 of 3 sources quiet" in tile["note"]
    assert tile["cls"] == "warn"
    rows = {r["name"]: r for r in ov.health(d)}
    assert rows["Endpoint sensors"]["state"] == "warn"
    assert rows["Endpoint sensors"]["detail"] == "1 of 4 endpoints offline"
    assert rows["Syslog and feed sources"]["state"] == "warn"  # amber, not red
    assert rows["Syslog and feed sources"]["detail"] == "1 of 3 quiet · longest quiet 3d"
    # all endpoints up and only a source quiet: the endpoint row stays green
    d2 = flow_doc()
    d2["fleet"][1]["online"] = True
    rows2 = {r["name"]: r for r in ov.health(d2)}
    assert rows2["Endpoint sensors"]["state"] == "up"
    assert rows2["Syslog and feed sources"]["state"] == "warn"
    assert all(r["state"] != "down" for r in rows2.values())


def test_the_fleet_tab_rows_are_amber_for_a_quiet_source_and_red_for_an_endpoint() -> None:
    rows = {r["hostname"]: r for r in ov.fleet(flow_doc())}
    assert (rows["ws-2"]["state"], rows["ws-2"]["label"]) == ("down", "offline")
    assert (rows["gw-2"]["state"], rows["gw-2"]["label"]) == (
        "warn",
        "quiet · last message 3d ago",
    )
    assert rows["ws-1"]["state"] == "up"


def test_the_groups_count_by_kind_with_the_problem_named() -> None:
    drawing = sf.build(flow_doc())
    counts = {g["kind"]: g["count"] for g in drawing["groups"]}
    assert counts == {
        "endpoint": "4 endpoints · 1 offline",
        "network": "2 network sensors · 1 quiet",
        "feed": "1 vendor feed",
    }
    assert drawing["reporting"] == "5 of 7 reporting"
    shapes = {g["kind"]: {i["d"] for i in g["icons"]} for g in drawing["groups"]}
    assert shapes == {
        "endpoint": {"M3 3h12v12H3z"},
        "network": {"M9 1l8 8-8 8-8-8z"},
        "feed": {"M9 2l8 14H1z"},
    }
    ws2 = next(i for g in drawing["groups"] for i in g["icons"] if i["host"] == "ws-2")
    assert not ws2["on"] and "offline" in ws2["title"]
    assert [i["on"] for i in drawing["groups"][0]["icons"]] == [False, True, True, True]


def test_a_big_group_is_capped_with_a_count_of_the_rest() -> None:
    many = [sensor(f"ws-{n}", "Linux", n % 2 == 0) for n in range(45)]
    g = sf.build(flow_doc(fleet=many))["groups"][0]
    assert len(g["icons"]) == sf.ICONS_PER_GROUP and g["more"] == "+25 more"
    assert not g["icons"][0]["on"]  # the capped view keeps the problems


def test_the_bands_follow_the_counts_for_the_period() -> None:
    d = sf.build(flow_doc())
    labels = {lab["title"]: lab for lab in d["labels"]}
    assert labels["ALERTS IN"]["num"] == "1,512" and "7 days" in labels["ALERTS IN"]["sub"]
    assert labels["CASES"]["num"] == "402"
    assert labels["PAGED"]["num"] == "80" and "p95 3.1 s" in labels["PAGED"]["sub"]
    assert labels["QUIET LANE"]["num"] == "322"
    alerts, cases, paged, quiet = heights(d)
    scale = sf.MAX_BAR / 1512
    assert alerts == pytest.approx(1512 * scale, abs=0.1)
    assert cases == pytest.approx(402 * scale, abs=0.1)
    assert paged == pytest.approx(80 * scale, abs=0.1)
    assert quiet == pytest.approx(322 * scale, abs=0.1)
    assert paged + quiet == pytest.approx(cases, abs=0.2)
    assert [b["cls"] for b in d["bands"]] == ["alerts", "paged", "quiet"]


def test_a_tiny_count_is_still_visible_and_a_period_of_one_day_says_today() -> None:
    d = sf.build(
        flow_doc(
            period_days=1,
            totals={"alerts_in": 100000, "pages": 1, "cases": 400},
            funnel=[
                {"lane": "paged", "status": "open", "n": 1},
                {"lane": "quiet", "status": "open", "n": 399},
            ],
        )
    )
    assert min(heights(d)) >= sf.MIN_BAR
    assert next(lab for lab in d["labels"] if lab["title"] == "ALERTS IN")["sub"].endswith("today")
    assert max(heights(d)) <= sf.MAX_BAR + 0.1


def test_with_no_alerts_nothing_moves_and_nothing_is_invented() -> None:
    d = sf.build(flow_doc(totals={"alerts_in": 0, "pages": 0, "cases": 0}, funnel=[], fleet=[]))
    nums = {lab["title"]: lab["num"] for lab in d["labels"]}
    assert nums["ALERTS IN"] == "0" and nums["CASES"] == "0" and nums["PAGED"] == "0"
    assert all(b["still"] for b in d["bands"])
    assert d["reporting"] == "no sensor data yet" and d["groups"][0]["count"] == "none enrolled"


def test_incidents_are_drawn_as_not_built() -> None:
    d = sf.build(flow_doc())
    assert d["incident_label"]["title"] == "INCIDENTS" and "Sprint 5" in d["incident_label"]["sub"]


def test_no_number_in_an_attribute_comes_from_text() -> None:
    d = sf.build(flow_doc(fleet=[sensor('<b>"x"</b>', "Linux", True)]))
    for key in ("bars", "bands", "feeds"):
        for item in d[key]:
            for name in ("x", "y", "h", "d"):
                if name in item:
                    assert re.fullmatch(r"[0-9A-Za-z .,\-]+", str(item[name])), (key, item)
