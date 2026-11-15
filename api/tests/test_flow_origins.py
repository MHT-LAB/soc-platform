"""O11: where alerts come from (migration 0016), the curves sized by it, and the auto-refresh."""

import importlib.util
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from conftest import SEED_FILE, TestDb
from fastapi.testclient import TestClient
from test_ops_overview_db import can_execute, overview
from test_ops_overview_pages import PAGES, SLUGS, client, get
from test_signal_flow import flow_doc
from test_worker_db import Fixture

from soc_api import console
from soc_api import db as soc_db
from soc_api import seed as soc_seed
from soc_api import signalflow as sf
from soc_api.status import PLATFORMS

WINDOWS, LINUX, VPN, CEF, EMAIL = 0x10000000, 0x20000000, 0x70000000, 0x0A000000, 0x1A000000
VERSIONS = Path(__file__).resolve().parents[1] / "src" / "soc_api" / "migrations" / "versions"


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def with_plat(fx: Fixture, plat: Any, *, source: str = "a", age_min: float = 0) -> str:
    """One alert whose routing carries `plat` (the key is left out for the string 'absent')."""
    event = fx.alert(source, age_min=age_min)
    value = json.dumps(plat)
    with fx.db.connect() as c:
        if plat == "absent":
            c.execute(
                "UPDATE alert SET raw = raw #- '{routing,plat}' WHERE event_id = %s", (event,)
            )
        else:
            c.execute(
                "UPDATE alert SET raw = jsonb_set(raw, '{routing,plat}', %s::jsonb) "
                "WHERE event_id = %s",
                (value, event),
            )
    return event


# ---- the database side ----


def test_alerts_are_counted_by_kind_and_the_kinds_add_up(fx: Fixture) -> None:
    for plat in (WINDOWS, WINDOWS, LINUX):
        with_plat(fx, plat)
    for plat in (CEF, VPN):
        with_plat(fx, plat)
    for plat in (EMAIL, 0x90000000, 0x1B000000):  # email, JSON adapter, a code nobody lists
        with_plat(fx, plat)
    for plat in ("absent", None, "abc", 1.5, True, 99999999999):
        with_plat(fx, plat)
    doc = overview(fx)
    assert doc["origins"] == {"endpoint": 3, "network": 2, "feed": 3, "unknown": 6}
    assert sum(doc["origins"].values()) == doc["totals"]["alerts_in"] == 14


def test_origins_follow_the_period_and_the_client(fx: Fixture) -> None:
    with_plat(fx, WINDOWS)
    with_plat(fx, CEF, age_min=3 * 24 * 60)
    with_plat(fx, EMAIL, source="b")
    assert overview(fx, 1)["origins"] == {"endpoint": 1, "network": 0, "feed": 1, "unknown": 0}
    assert overview(fx, 7)["origins"] == {"endpoint": 1, "network": 1, "feed": 1, "unknown": 0}
    assert overview(fx, 7, "client-a")["origins"] == {
        "endpoint": 1,
        "network": 1,
        "feed": 0,
        "unknown": 0,
    }
    assert overview(fx, 7)["totals"]["alerts_in"] == 3


def test_no_slug_or_sensor_id_in_the_document(fx: Fixture) -> None:
    with_plat(fx, WINDOWS)
    with fx.db.connect() as c:
        c.execute(
            "INSERT INTO sensor_state "
            "(sid, hostname, platform, online, isolated, last_seen, updated_at) "
            "VALUES ('11111111-2222-4333-8444-555555555555', 'h', 'Windows', true, false, "
            "now(), now())"
        )
    text = json.dumps(overview(fx))
    assert "src-a" not in text and "src-b" not in text
    assert "11111111-2222" not in text


def test_the_sql_and_python_platform_mappings_agree(fx: Fixture) -> None:
    codes: list[Any] = [*PLATFORMS, 0, 1, 0x1B000000, 0xFFFFFFFF, 9999999999, 10000000000]
    codes += [-5, 1.5, True, False, None, "268435456", "0x10", "", "7", " 7"]
    seen: dict[str, int] = {}
    for code in codes:
        event = with_plat(fx, code)
        got = overview(fx)["origins"]
        assert sum(got.values()) == 1, code
        (kind,) = [k for k, n in got.items() if n]
        assert kind == sf.origin_kind(code), code
        seen[kind] = seen.get(kind, 0) + 1
        with fx.db.connect() as c:  # one alert at a time
            c.execute("DELETE FROM alert WHERE event_id = %s", (event,))
    assert set(seen) == set(sf.ORIGIN_KINDS)


def test_the_python_table_has_every_listed_platform_in_its_kind() -> None:
    assert {sf.origin_kind(c) for c in (0x10000000, 0x60000000)} == {"endpoint"}
    assert {sf.origin_kind(c) for c in (0x70000000, 0x80000000, 0x0A000000)} == {"network"}
    assert {sf.origin_kind(c) for c in (0x90000000, 0x1A000000, 0x123)} == {"feed"}


def function_def(db: TestDb) -> str:
    with db.connect() as c:
        row = c.execute(
            "SELECT pg_get_functiondef('ops_overview(integer, text)'::regprocedure)"
        ).fetchone()
    assert row is not None
    return str(row[0])


def test_downgrade_restores_the_0012_function_exactly(db: TestDb) -> None:
    head = function_def(db)
    assert "'origins'" in head
    soc_db.downgrade(db.sqlalchemy_url(), "0015")
    old = function_def(db)
    assert "origins" not in old
    spec = importlib.util.spec_from_file_location("m0012", VERSIONS / "0012_ops_overview.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    body = mod.OPS_OVERVIEW.split("AS $$", 1)[1].rsplit("$$", 1)[0]
    assert body.strip() in old
    soc_db.upgrade(db.sqlalchemy_url())
    assert function_def(db) == head


def test_owner_and_grants_survive_the_migration_and_a_round_trip(db: TestDb) -> None:
    fx = Fixture(db)

    def state() -> tuple[Any, ...]:
        row = fx.one(
            "SELECT r.rolname, p.prosecdef, p.provolatile, p.proconfig, p.proacl::text "
            "FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner WHERE p.proname = 'ops_overview'"
        )
        return tuple(row)

    before = state()
    assert before[0] == "soc_console_writer" and before[1] is True
    soc_db.downgrade(db.sqlalchemy_url(), "0015")
    soc_db.upgrade(db.sqlalchemy_url())
    assert state() == before
    for role in ("soc_app", "soc_ingest", "soc_reconcile", "soc_worker", "soc_posture", "public"):
        assert not can_execute(fx, role, "ops_overview(integer, text)"), role
    assert can_execute(fx, "soc_console", "ops_overview(integer, text)")


# ---- the drawing ----


def drawing(origins: dict[str, int] | None, alerts: int | None = None) -> dict[str, Any]:
    d = flow_doc()
    if origins is not None:
        d["origins"] = origins
        d["totals"]["alerts_in"] = alerts if alerts is not None else sum(origins.values())
    return sf.build(d)


def curves(d: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["kind"]: f for f in d["feeds"]}


def test_curve_widths_follow_each_groups_share() -> None:
    d = drawing({"endpoint": 600, "network": 300, "feed": 100, "unknown": 0}, 1000)
    f = curves(d)
    ha = float(d["bars"][0]["h"])
    assert [float(f[k]["w"]) for k in ("endpoint", "network", "feed")] == pytest.approx(
        [ha * 0.6, ha * 0.3, ha * 0.1], abs=0.1
    )
    assert "unknown" not in f and d["other"] is None


def test_a_tiny_share_is_still_visible_and_none_is_a_dashed_hairline() -> None:
    d = drawing({"endpoint": 9990, "network": 10, "feed": 0, "unknown": 0})
    f = curves(d)
    assert float(f["network"]["w"]) == sf.MIN_FEED
    assert f["feed"]["zero"] is True and "w" not in f["feed"] and not f["feed"].get("mid")
    labels = {g["kind"]: (g["origin"], g["origin_zero"]) for g in d["groups"]}
    assert labels["feed"] == ("0 from vendor feeds", True)
    assert labels["network"] == ("10 from network", False)
    assert labels["endpoint"] == ("9,990 from endpoints", False)


def test_unknown_origin_is_a_small_grey_curve_labelled_other_only_when_there_is_any() -> None:
    d = drawing({"endpoint": 80, "network": 10, "feed": 5, "unknown": 5})
    assert curves(d)["unknown"]["w"] and d["other"]["text"] == "5 from other"
    assert "5 from other" in d["aria"]
    assert drawing({"endpoint": 5, "network": 0, "feed": 0, "unknown": 0})["other"] is None


def test_the_alerts_in_total_is_the_sum_of_the_origins() -> None:
    o = {"endpoint": 600, "network": 300, "feed": 100, "unknown": 7}
    d = drawing(o)
    assert d["labels"][0]["num"] == f"{sum(o.values()):,}"
    assert f"{sum(o.values()):,} alerts in" in d["aria"]


def test_a_document_without_origins_still_draws_the_plain_curves() -> None:
    d = drawing(None)
    assert d["other"] is None and len(d["feeds"]) == 3
    assert all(f.get("mid") is None for f in d["feeds"])


def test_no_alerts_at_all_is_three_hairlines() -> None:
    d = drawing({"endpoint": 0, "network": 0, "feed": 0, "unknown": 0})
    assert all(f["zero"] for f in d["feeds"]) and len(d["feeds"]) == 3


# ---- the pages ----


@pytest.fixture
def demo(db: TestDb) -> TestClient:
    soc_seed.seed(db.sqlalchemy_url(), SEED_FILE)
    soc_seed.seed_activity(db.sqlalchemy_url(), SEED_FILE, now=datetime.now(UTC))
    return client(db)


def flow_svg(c: TestClient) -> str:
    m = re.search(r'<svg class="flowsvg".*?</svg>', get(c, "/console/overview").text, re.S)
    assert m
    return m.group(0)


def test_the_demo_shows_all_three_kinds_with_different_curves(demo: TestClient) -> None:
    s = flow_svg(demo)
    found = {k: int(n.replace(",", "")) for n, k in re.findall(r">([\d,]+) from (\w+)", s)}
    assert set(found) == {"endpoints", "network", "vendor"}
    assert all(n > 0 for n in found.values()) and len(set(found.values())) == 3
    total = re.search(r'class="num lg"[^>]*>([\d,]+)</text><text class="ttl"[^>]*>ALERTS IN', s)
    assert total and int(total.group(1).replace(",", "")) == sum(found.values())
    assert "from other" not in s
    assert len(re.findall(r'class="ffband ', s)) == 3
    assert not any(slug in s for slug in SLUGS)


@pytest.mark.parametrize("path", PAGES)
def test_every_overview_page_says_it_updates_every_minute_and_has_no_inline_script(
    demo: TestClient, path: str
) -> None:
    text = get(demo, path).text
    assert "updates every minute" in text
    assert 'http-equiv="refresh"' not in text
    assert '<script src="/console/overview.js"' in text
    assert not re.search(r"<script(?![^>]*\bsrc=)", text, re.I)
    assert " style=" not in text.lower() and "<style" not in text.lower()
    assert not re.search(r"\son\w+=", text, re.I)


def test_the_script_refreshes_every_minute_only_when_the_tab_is_visible() -> None:
    js = (console.HERE / "static" / "overview.js").read_text()
    assert "setInterval(due, EVERY)" in js and "var EVERY = 60000" in js
    assert 'document.visibilityState !== "visible"' in js and "location.reload()" in js
    assert "details[open]" in js and "getSelection" in js
    assert "visibilitychange" in js
    assert "location.href" not in js and "location.search" not in js  # the address is kept
