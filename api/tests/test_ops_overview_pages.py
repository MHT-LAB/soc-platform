"""The Ops Overview pages: access, headers, filters, what each panel shows.

The demo tenant (fixtures/acme-demo with its synthetic activity) fills a real database; the
pages are fetched through the real console app. Source slugs are secret webhook paths: the
demo's slugs are distinctive on purpose so a leak anywhere shows.
"""

import re
from datetime import UTC, datetime
from typing import Any

import pytest
from conftest import ROLE_PASSWORD, SEED_FILE, TestDb
from fastapi.testclient import TestClient
from test_worker_db import Fixture

from soc_api import console
from soc_api import seed as soc_seed
from soc_api.config import Settings
from soc_api.main import create_console_app

ANALYST = "analyst@example.com"
VIEWER = "viewer@example.com"
USERS = f"{ANALYST}:analyst,{VIEWER}:viewer"
HEAD = {"Tailscale-User-Login": VIEWER}
PAGES = ("/console/overview", "/console/fleet", "/console/sources", "/console/rules")
SLUGS = ("acme-lc", "acme-ids-7f3a", "acme-vendor-9c21")


def client(db: TestDb, **over: Any) -> TestClient:
    base: dict[str, Any] = {
        "env": "prod",
        "console_users": USERS,
        "version": "edge",
        "git_sha": "a" * 40,
        "console_database_url": db.sqlalchemy_url("soc_console", ROLE_PASSWORD),
    }
    return TestClient(create_console_app(Settings(**{**base, **over})))


@pytest.fixture
def demo(db: TestDb) -> TestClient:
    soc_seed.seed(db.sqlalchemy_url(), SEED_FILE)
    soc_seed.seed_activity(db.sqlalchemy_url(), SEED_FILE, now=datetime.now(UTC))
    return client(db)


def sql(db: TestDb, query: str) -> None:
    with db.connect() as c:
        c.execute(query)


def get(c: TestClient, path: str, **kw: Any) -> Any:
    return c.get(path, headers=kw.pop("headers", HEAD), **kw)


# ---- access and headers ----


def test_a_viewer_opens_every_new_page(demo: TestClient) -> None:
    for path in PAGES:
        r = get(demo, path)
        assert r.status_code == 200, path
        assert "· read-only" in r.text  # the viewer's header
        assert "All systems nominal" in r.text


def test_the_new_pages_need_a_tailnet_identity_and_the_allowlist(demo: TestClient) -> None:
    for path in (*PAGES, "/console/overview.js"):
        assert demo.get(path).status_code == 403, path
        r = demo.get(path, headers={"Tailscale-User-Login": "stranger@example.com"})
        assert r.status_code == 403, path


def test_the_new_pages_are_not_on_the_public_app() -> None:
    from soc_api.main import create_app

    public = TestClient(create_app(Settings(version="edge", git_sha="a" * 40)))
    for path in PAGES:
        assert public.get(path, headers=HEAD).status_code == 404


def test_every_new_route_sends_the_csp_with_script_self_only(demo: TestClient) -> None:
    for path in PAGES:
        csp = get(demo, path).headers["content-security-policy"]
        assert csp == console.OVERVIEW_CSP, path
        assert "script-src 'self'" in csp and "default-src 'none'" in csp
        assert "unsafe" not in csp and "form-action 'none'" in csp
        assert "frame-ancestors 'none'" in csp
    # a filtered page and the 503 notice keep a policy too
    assert (
        "script-src 'self'"
        in get(demo, "/console/fleet?period=30").headers["content-security-policy"]
    )
    # the only change from the old policy is that one directive
    assert console.OVERVIEW_CSP.replace(" script-src 'self';", "") == console.CONSOLE_CSP
    assert "script-src" not in console.CONSOLE_CSP and "script-src" not in console.CASES_CSP


def test_the_other_security_headers_hold_on_the_new_routes(demo: TestClient) -> None:
    for path in (*PAGES, "/console/overview.js"):
        h = get(demo, path).headers
        assert h["x-content-type-options"] == "nosniff", path
        assert h["cache-control"] == "no-store" and h["x-frame-options"] == "DENY", path
        assert h["referrer-policy"] == "no-referrer", path
        assert "set-cookie" not in h, path


def test_no_inline_script_or_style_and_the_one_script_is_ours(demo: TestClient) -> None:
    for path in PAGES:
        text = get(demo, path).text
        scripts = re.findall(r"<script\b[^>]*>(.*?)</script[^>]*>", text, re.S | re.I)
        assert scripts == [""], path  # exactly one, and empty: it has a src
        assert text.count('<script src="/console/overview.js" defer></script>') == 1, path
        assert "<style" not in text.lower() and " style=" not in text.lower(), path
        assert not re.search(r"\son[a-z]+=", text), path
        assert "javascript:" not in text.lower() and "<form" not in text.lower(), path
        assert "<input" not in text.lower() and "<button" not in text.lower(), path


def test_the_script_only_ticks_the_clock() -> None:
    js = (console.HERE / "static" / "overview.js").read_text()
    for banned in ("fetch(", "XMLHttpRequest", "eval(", "innerHTML", "document.write", "WebSocket"):
        assert banned not in js
    assert "utc-clock" in js


def test_the_script_is_served_as_javascript(demo: TestClient) -> None:
    r = get(demo, "/console/overview.js")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/javascript")


def test_the_old_operations_page_is_still_reachable_as_system(demo: TestClient) -> None:
    r = get(demo, "/console")
    assert r.status_code == 200 and "<h1>System</h1>" in r.text
    assert 'class="on" href="/console">System' in r.text
    assert "script-src" not in r.headers["content-security-policy"]


def test_the_tabs_link_every_view_and_mark_the_current_one(demo: TestClient) -> None:
    text = get(demo, "/console/rules?period=30").text
    for href in (
        "/console/overview",
        "/console/cases",
        "/console/fleet",
        "/console/sources",
        "/console",
    ):
        assert f'href="{href}' in text
    assert 'class="on" href="/console/rules?period=30">Rules' in text
    assert "Ask the analyst" not in text and "Costs</a>" not in text


# ---- filters ----


@pytest.mark.parametrize("path", PAGES)
@pytest.mark.parametrize(
    "query",
    [
        "period=2",
        "period=0",
        "period=-1",
        "period=7;DROP",
        "period=",
        "client=Nobody",
        "client=nobody",
        "client=a'b",
        "client=" + "a" * 65,
        "client=%00",
        "client=;select",
        "client=",
    ],
)
def test_a_bad_period_or_client_is_a_400_and_never_reaches_sql(
    demo: TestClient, path: str, query: str
) -> None:
    r = get(demo, f"{path}?{query}")
    assert r.status_code in (400, 422), (path, query)
    assert "DROP" not in r.text or "unknown" in r.text


def test_good_filters_work_and_carry_across_tabs(demo: TestClient) -> None:
    text = get(demo, "/console/overview?period=30&client=acme-demo").text
    assert "30 days, acme-demo" in text
    assert 'href="/console/fleet?period=30&amp;client=acme-demo"' in text
    assert (
        'class="chip-link on" href="/console/overview?period=30&amp;client=acme-demo">30 days'
        in text
    )
    one = get(demo, "/console/overview?period=1").text
    assert "Today" in one and "Detection volume · today" in one


def test_the_client_filter_changes_the_numbers(demo: TestClient) -> None:
    everything = get(demo, "/console/overview").text
    unassigned = get(demo, "/console/overview?client=unassigned").text
    assert "0 alerts in, 0 pages to a human, 0 cases" in unassigned
    assert "0 alerts in" not in everything
    assert "No alerts in this period" in unassigned


# ---- the panels, on the seeded demo ----


def test_the_overview_shows_every_panel_with_real_figures(demo: TestClient) -> None:
    text = get(demo, "/console/overview").text
    for heading in (
        "Signal flow",
        "Case queue",
        "Detection volume",
        "Case funnel",
        "ATT&amp;CK tactics seen",
        "Pipeline health",
        "What it costs to run",
    ):
        assert heading in text, heading
    assert re.search(r"[\d,]+ alerts in, [\d,]+ pages to a human, [\d,]+ cases\.", text)
    # the signal flow: sensor groups, bands with real counts, incidents drawn as not built
    for title in ("ALERTS IN", "CASES", "PAGED", "QUIET LANE", "INCIDENTS"):
        assert f">{title}<" in text, title
    assert "13 of 15 reporting" in text and "Sprint 5 / 9" in text and "not built yet" in text
    assert re.search(r"pager p95 \d\.\d s", text)
    # queue: lanes, severity classes, "not analyzed" and never a clean verdict
    assert 'class="lane paged"' in text and 'class="lane quiet"' in text
    assert "not analyzed" in text and "clean" not in text.lower().replace("unclean", "")
    assert re.search(r'class="sev (high|medium|low|critical|info)"', text)
    # response tiles
    assert text.count("Mean time to acknowledge") == 2 and text.count("Mean time to close") == 2
    assert re.search(r"\d+m \d\ds|\d+h \d\dm", text)
    # funnel, tactics, deploys on the timeline
    assert "paged" in text and "Execution" in text and "Discovery" in text
    assert "T1082" in text and 'class="deploy"' in text and "3f9c1e4" in text
    assert "edr-webhook" in text and "network-ids" in text and "vendor-feed" in text
    # placeholders that must not pretend to be numbers
    assert "Costs: from Sprint 5" in text and "$" not in text


def test_the_timeline_is_stacked_by_source_type_in_svg(demo: TestClient) -> None:
    text = get(demo, "/console/overview").text
    assert '<svg class="timeline"' in text and 'class="t0"' in text and 'class="t1"' in text
    assert "per hour" in text and "per day" in get(demo, "/console/overview?period=30").text
    assert "echarts" not in text.lower()


def test_health_shows_the_sensor_amber_and_the_rest_green(demo: TestClient) -> None:
    text = get(demo, "/console/overview").text
    assert "1 of 12 endpoints offline" in text and 'class="sdot warn"' in text
    assert 'class="sdot up"' in text and 'class="sdot down"' not in text
    assert "1 of 3 quiet · longest quiet 3d" in text  # a quiet source is amber, not red
    assert "independent of the SOC service; not monitored here" in text


def test_fleet_lists_every_sensor_with_the_offline_one_first(demo: TestClient) -> None:
    text = get(demo, "/console/fleet").text
    assert text.count("<tr>") == 16  # header + 12 endpoints + 3 sources
    assert text.index("ws-demo-07") < text.index("ws-demo-01")
    assert ">offline</span>" in text and ">isolated</span>" in text
    assert "1 offline · 1 quiet" in text


def test_sources_shows_types_clients_and_catch_up(demo: TestClient) -> None:
    text = get(demo, "/console/sources").text
    assert "edr-webhook #1" in text and "network-ids #2" in text and "vendor-feed #3" in text
    assert "no catch-up" in text and "last ran 3m ago" in text
    assert "acme-demo" in text


def test_rules_shows_the_noisiest_first_and_the_inventory(demo: TestClient) -> None:
    text = get(demo, "/console/rules").text
    assert "demo.Net.InboundScan" in text or "demo.Recon.WhoamiBurst" in text
    assert text.index("Top noisy rules") < text.index("Rule inventory")
    assert "disabled" in text and "Namespace" in text and ">general<" in text


def test_no_source_slug_appears_on_any_page(demo: TestClient) -> None:
    for path in (
        *PAGES,
        "/console",
        "/console/cases",
        "/console/overview?period=30",
        "/console/rules?client=acme-demo",
    ):
        text = get(demo, path).text
        for slug in SLUGS:
            assert slug not in text, (path, slug)


# ---- honest empty states ----


def test_an_empty_database_says_so_everywhere(db: TestDb) -> None:
    c = client(db)
    text = get(c, "/console/overview").text
    assert "0 alerts in, 0 pages to a human, 0 cases." in text
    assert "No open cases." in text and "No alerts in this period." in text
    assert "No alert in this period carries an ATT&amp;CK hint" in text
    assert "none yet" in text and "no sensor data yet" in text
    assert "Health unknown" not in text  # the console is connected, so health is known
    assert "to a human · none sent yet" in text
    assert "No sensor data" in get(c, "/console/fleet").text
    assert "No source is configured" in get(c, "/console/sources").text
    assert "No alerts in this period." in get(c, "/console/rules").text


def test_a_hint_free_demo_shows_the_tactics_empty_state(demo: TestClient, db: TestDb) -> None:
    sql(db, "UPDATE alert SET mitre_hint = NULL")
    assert "carries an ATT&amp;CK hint" in get(demo, "/console/overview").text


def test_a_verdict_is_shown_when_there_is_one(demo: TestClient, db: TestDb) -> None:
    sql(db, "UPDATE soc_case SET verdict = 'suspicious'")
    text = get(demo, "/console/overview").text
    assert "suspicious" in text and "not analyzed" not in text


def test_a_sensor_going_offline_shows_on_the_next_load(demo: TestClient, db: TestDb) -> None:
    assert "11/12" in get(demo, "/console/overview").text
    sql(db, "UPDATE sensor_state SET online = false WHERE hostname = 'ws-demo-01'")
    text = get(demo, "/console/overview").text
    assert "10/12" in text and "2 of 12 endpoints offline" in text
    sql(db, "UPDATE sensor_state SET online = true")
    assert "12/12" in get(demo, "/console/overview").text


def test_a_degraded_pipeline_turns_the_pill_red_with_a_count(demo: TestClient, db: TestDb) -> None:
    sql(db, "UPDATE backup_state SET last_ok_at = now() - interval '14 hours'")
    text = get(demo, "/console/overview").text
    assert "Degraded · 1" in text and "All systems nominal" not in text
    assert "Pipeline degraded" in text and 'class="sdot down"' in text


def test_without_a_database_login_the_pages_say_so_and_the_pill_is_unknown() -> None:
    c = TestClient(
        create_console_app(Settings(env="prod", console_users=USERS, version="e", git_sha="a" * 40))
    )
    for path in PAGES:
        r = get(c, path)
        assert r.status_code == 503 and "Health unknown" in r.text, path


def test_an_unreachable_database_gives_a_fixed_503_without_detail(db: TestDb) -> None:
    url = "postgresql+psycopg://soc_console:pw-secret@127.0.0.1:1/soc"
    c = client(db, console_database_url=url)
    for path in PAGES:
        r = get(c, path)
        assert r.status_code == 503 and "pw-secret" not in r.text and "127.0.0.1" not in r.text


def test_hostile_text_is_escaped_on_the_new_pages(db: TestDb) -> None:
    fx = Fixture(db)
    hostile = "<img src=x onerror=alert(1)>"
    fx.alert(rule=hostile, host="<b>h</b>")
    fx.assign()
    fx.run("UPDATE source SET type = %s", (hostile,))
    fx.run(
        "INSERT INTO sensor_state (sid, hostname, platform, online, isolated) "
        "VALUES ('demo-sensor-h1', %s, 'x', true, false)",
        (hostile,),
    )
    c = client(db)
    for path in (*PAGES,):
        text = get(c, path).text
        assert "<img src=x" not in text and "<b>h</b>" not in text, path
    assert "&lt;img src=x onerror=alert(1)&gt;" in get(c, "/console/rules").text


def test_the_templates_hold_no_inline_script_or_style_attribute() -> None:
    for tpl in (console.HERE / "templates").glob("*.html"):
        text = tpl.read_text().lower()
        assert " style=" not in text and "<style" not in text, tpl.name
        for tag in re.findall(r"<script\b[^>]*>", text, re.I):
            assert 'src="/console/overview.js"' in tag, (tpl.name, tag)


def test_every_filter_link_is_a_path_on_this_site(demo: TestClient) -> None:
    for path in ("/console/overview", "/console/fleet", "/console/sources", "/console/rules"):
        text = get(demo, path).text
        hrefs = re.findall(r'class="chip-link[^"]*" href="([^"]*)"', text)
        assert hrefs, path
        assert all(h.startswith("/console/") for h in hrefs), (path, hrefs)
