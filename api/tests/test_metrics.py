"""The console's /metrics page: Prometheus text from the database's pipeline counters.

The text is tested without a database (what may appear in it, and what is dropped) and with
one (the real soc_console login, the real function, the real console app). The page lives on
the console app only, behind the same identity and allow-list as every console page.
"""

import re
from typing import Any

import psycopg
import pytest
from conftest import ROLE_PASSWORD, TestDb
from fastapi.testclient import TestClient
from test_worker_db import Fixture

from soc_api import db as soc_db
from soc_api import metrics
from soc_api.config import Settings
from soc_api.main import create_app, create_console_app

LOGIN = "operator@example.com"
HEADERS = {"Tailscale-User-Login": LOGIN}
SAMPLE = re.compile(
    r'^[a-z_][a-z0-9_]*(\{[a-z_]+="[A-Za-z0-9+_.-]*"(,[a-z_]+="[A-Za-z0-9+_.-]*")*\})? '
    r"-?[0-9]+(\.[0-9]+)?(e[+-]?[0-9]+)?$"
)


def parse(text: str) -> dict[str, float]:
    """A strict reading of the text format: every line is a comment or one sample, the text
    ends with a newline, every sample's family has a TYPE line, and no series repeats."""
    assert text.endswith("\n") and not text.endswith("\n\n")
    samples: dict[str, float] = {}
    families: set[str] = set()
    for line in text.splitlines():
        if line.startswith("# HELP "):
            continue
        if line.startswith("# TYPE "):
            families.add(line.split()[2])
            continue
        assert SAMPLE.match(line), line
        name, value = line.rsplit(" ", 1)
        assert name not in samples, f"repeated series {name}"
        samples[name] = float(value)
        family = re.sub(r"(_bucket|_sum|_count)?(\{.*)?$", "", name)
        assert family in families, f"{name} has no TYPE line"
    return samples


# ---- the text, without a database ----


def test_an_empty_database_still_gives_valid_text() -> None:
    samples = parse(metrics.render([]))
    assert samples == {
        'soc_ack_latency_seconds_bucket{le="+Inf"}': 0,
        "soc_ack_latency_seconds_sum": 0,
        "soc_ack_latency_seconds_count": 0,
    }


def test_rows_become_the_named_series() -> None:
    rows = [
        ("alerts_ingested", "", 7.0),
        ("alerts_grouped", "", 3.0),
        ("pages_sent", "page", 2.0),
        ("pages_sent", "repage1", 1.0),
        ("ack_latency_bucket", "60", 1.0),
        ("ack_latency_bucket", "300", 2.0),
        ("ack_latency_sum", "", 210.5),
        ("ack_latency_count", "", 2.0),
    ]
    samples = parse(metrics.render(rows))
    assert samples["soc_alerts_ingested_total"] == 7
    assert samples["soc_alerts_grouped_total"] == 3
    assert samples['soc_pages_sent_total{kind="repage1"}'] == 1
    assert samples['soc_ack_latency_seconds_bucket{le="300"}'] == 2
    assert samples['soc_ack_latency_seconds_bucket{le="+Inf"}'] == 2
    assert samples["soc_ack_latency_seconds_sum"] == 210.5


@pytest.mark.parametrize(
    "label",
    ['x"} 1\nsoc_evil 1\n#', "Acme Corp", "host-1.example.com", "lc-abcdefgh12345678", "UPPER"],
)
def test_alerts_ingested_never_carries_a_label(label: str) -> None:
    text = metrics.render([("alerts_ingested", label, 5.0)])
    assert "Acme" not in text and "evil" not in text and "host-1" not in text
    assert "lc-abcdefgh" not in text and 'source="' not in text
    parse(text)


def test_unknown_kinds_unknown_metrics_and_odd_bounds_are_dropped() -> None:
    text = metrics.render(
        [
            ("pages_sent", "something-else", 1.0),
            ("secret_thing", "", 1.0),
            ("ack_latency_bucket", "1e9", 1.0),
            ("ack_latency_bucket", "60}", 1.0),
        ]
    )
    assert "something-else" not in text and "secret_thing" not in text
    assert 'le="1e9"' not in text and 'le="60}"' not in text
    parse(text)


# ---- the page: placement and access, without a database ----


def console(**over: Any) -> TestClient:
    base: dict[str, Any] = {"version": "edge", "git_sha": "a" * 40}
    return TestClient(create_console_app(Settings(**{**base, **over})))


def test_the_public_app_has_no_metrics_page() -> None:
    public = TestClient(create_app(Settings(version="edge", git_sha="a" * 40)))
    for headers in ({}, HEADERS):
        assert public.get("/metrics", headers=headers).status_code == 404


def test_prod_refuses_metrics_without_a_tailnet_identity_or_off_the_allowlist() -> None:
    c = console(env="prod", console_users=LOGIN)
    assert c.get("/metrics").status_code == 403
    assert (
        c.get("/metrics", headers={"Tailscale-User-Login": "other@example.com"}).status_code == 403
    )
    # the same two checks the console pages have, in dev with an allowlist too
    c = console(console_users=LOGIN)
    assert c.get("/metrics").status_code == 403


def test_without_a_database_login_the_page_says_so_and_nothing_more() -> None:
    r = console(env="prod", console_users=LOGIN).get("/metrics", headers=HEADERS)
    assert r.status_code == 503 and r.text == "metrics are not set up on this host"


def test_an_unreachable_database_gives_a_fixed_refusal_without_detail() -> None:
    url = "postgresql+psycopg://soc_console:pw-secret@127.0.0.1:1/soc"
    r = console(env="prod", console_users=LOGIN, console_database_url=url).get(
        "/metrics", headers=HEADERS
    )
    assert r.status_code == 503 and r.text == "the database cannot be reached"
    assert "pw-secret" not in r.text and "127.0.0.1" not in r.text


# ---- the page and the function, with a database ----


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def seeded(fx: Fixture) -> None:
    """src-a: three alerts of one case (two grouped) and one that was found late; src-b: one
    alert in its own case, with a page that failed. Two cases acknowledged: 200 s and 1000 s
    after their pages went out. A third acknowledged case never had a page sent."""
    for age in (50, 30, 5):
        fx.alert(source="a", host="h1", age_min=age)
    fx.alert(source="a", host="h2", event="late-one")
    fx.alert(source="b", host="h3", rule="other.Rule")
    fx.alert(source="b", host="h4", rule="third.Rule")
    fx.run(
        "UPDATE alert SET detected_at = received_at - interval '10 minutes' "
        "WHERE event_id = 'late-one'"
    )
    fx.assign()
    cases = {
        host: fx.one("SELECT case_id FROM alert WHERE raw #>> '{routing,hostname}' = %s", (host,))[
            0
        ]
        for host in ("h1", "h2", "h3", "h4")
    }
    for host in ("h1", "h2"):
        fx.run(
            "UPDATE notification SET status = 'sent', sent_at = now() - interval '1 hour' "
            "WHERE case_id = %s",
            (cases[host],),
        )
    fx.run("UPDATE notification SET status = 'failed' WHERE case_id = %s", (cases["h3"],))
    for host in ("h1", "h2", "h4"):
        fx.run("SELECT ack_case(%s, %s)", (cases[host], LOGIN))
    for host, secs in (("h1", 200), ("h2", 1000)):
        fx.run(
            "UPDATE case_event SET at = (SELECT sent_at FROM notification WHERE case_id = %s) "
            "+ make_interval(secs => %s) WHERE case_id = %s AND kind = 'acked'",
            (cases[host], secs, cases[host]),
        )


def rows(fx: Fixture) -> list[tuple[str, str, float]]:
    with fx.db.connect("soc_console") as c:
        return [(m, label, v) for m, label, v in c.execute("SELECT * FROM pipeline_metrics()")]


def page_text(fx: Fixture) -> str:
    settings = Settings(
        env="prod",
        console_users=LOGIN,
        version="edge",
        git_sha="a" * 40,
        console_database_url=fx.db.sqlalchemy_url("soc_console", ROLE_PASSWORD),
    )
    r = TestClient(create_console_app(settings)).get("/metrics", headers=HEADERS)
    assert r.status_code == 200
    assert r.headers["content-type"] == metrics.CONTENT_TYPE
    return r.text


def page(fx: Fixture) -> dict[str, float]:
    return parse(page_text(fx))


def test_the_numbers_on_a_seeded_database(fx: Fixture) -> None:
    seeded(fx)
    s = page(fx)
    assert s["soc_alerts_ingested_total"] == 6
    assert not any("source=" in k for k in s)
    assert s["soc_alerts_grouped_total"] == 2
    assert s["soc_alerts_late_total"] == 1
    assert s['soc_pages_sent_total{kind="page"}'] == 2
    assert s['soc_pages_sent_total{kind="repage1"}'] == 0
    assert s["soc_pages_failed_total"] == 1
    assert s["soc_cases_acknowledged_total"] == 3
    # the third acknowledged case never had a push sent, so it has no latency
    assert s["soc_ack_latency_seconds_count"] == 2
    assert 1190 <= s["soc_ack_latency_seconds_sum"] <= 1210
    assert s['soc_ack_latency_seconds_bucket{le="60"}'] == 0
    assert s['soc_ack_latency_seconds_bucket{le="300"}'] == 1
    assert s['soc_ack_latency_seconds_bucket{le="900"}'] == 1
    assert s['soc_ack_latency_seconds_bucket{le="3600"}'] == 2
    assert s['soc_ack_latency_seconds_bucket{le="+Inf"}'] == 2


def test_a_new_database_is_all_zero_and_no_source_slug_appears(fx: Fixture) -> None:
    text = page_text(fx)
    assert "src-a" not in text and "src-b" not in text
    s = parse(text)
    assert s["soc_alerts_ingested_total"] == 0
    assert s["soc_cases_acknowledged_total"] == 0 and s["soc_ack_latency_seconds_count"] == 0


def test_an_alert_without_a_detection_time_is_not_late(fx: Fixture) -> None:
    fx.alert()
    assert page(fx)["soc_alerts_late_total"] == 0


def test_nothing_a_client_or_sender_wrote_reaches_the_output(fx: Fixture) -> None:
    fx.run("UPDATE client SET name = 'Zebra Dental Ltd' WHERE slug = 'client-a'")
    fx.alert(host="zebra-host.internal", rule="zebra.Rule", cat="ZEBRA_CAT")
    fx.assign()
    settings = Settings(
        env="prod",
        console_users=LOGIN,
        version="edge",
        git_sha="a" * 40,
        console_database_url=fx.db.sqlalchemy_url("soc_console", ROLE_PASSWORD),
    )
    text = TestClient(create_console_app(settings)).get("/metrics", headers=HEADERS).text
    for word in ("zebra", "Zebra", "client-a", "internal", "summary", "actor"):
        assert word not in text
    allowed = {"src-a", "src-b", "page", "repage1", "repage2", "60", "300", "900", "3600", "14400"}
    assert {label for _, label, _ in rows(fx) if label} <= allowed


def test_only_the_console_login_can_call_it(fx: Fixture) -> None:
    def can(role: str) -> bool:
        return bool(
            fx.one("SELECT has_function_privilege(%s, 'pipeline_metrics()', 'EXECUTE')", (role,))[0]
        )

    assert can("soc_console")
    for role in ("soc_app", "soc_ingest", "soc_worker", "soc_reconcile"):
        assert not can(role), role
    assert not can("public")
    for role in ("soc_app", "soc_ingest", "soc_worker", "soc_reconcile"):
        with fx.db.connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM pipeline_metrics()")


def test_it_is_a_definer_owned_by_the_writer_with_a_pinned_search_path(fx: Fixture) -> None:
    row = fx.one(
        "SELECT p.prosecdef, p.proconfig, r.rolname, r.rolcanlogin, r.rolsuper, r.rolbypassrls "
        "FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner WHERE p.proname = 'pipeline_metrics'"
    )
    assert row[0] is True and row[2] == "soc_console_writer" and not any(row[3:])
    assert row[1] and any(x.startswith("search_path=pg_catalog") for x in row[1])


def test_the_login_still_reads_no_table_and_the_writer_gets_nothing_on_source(
    fx: Fixture,
) -> None:
    with fx.db.connect("soc_console") as c:
        for query in ("SELECT slug FROM source", "SELECT * FROM source", "SELECT id FROM alert"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(query)

    def can(column: str, privilege: str) -> bool:
        return bool(
            fx.one(
                "SELECT has_column_privilege('soc_console_writer', 'source', %s, %s)",
                (column, privilege),
            )[0]
        )

    for column in ("id", "slug", "client_id", "type", "external_id", "secret_ref", "enabled"):
        assert not can(column, "SELECT"), column
    for column in ("id", "slug", "secret_ref", "enabled"):
        assert not can(column, "UPDATE") and not can(column, "INSERT"), column


def test_downgrading_removes_it_and_upgrading_brings_it_back(db: TestDb, fx: Fixture) -> None:
    url = db.sqlalchemy_url()
    soc_db.downgrade(url, "0008")
    with db.connect() as c:
        assert c.execute("SELECT to_regprocedure('pipeline_metrics()')").fetchone() == (None,)
    soc_db.upgrade(url)
    assert ("alerts_grouped", "", 0.0) in rows(fx)
