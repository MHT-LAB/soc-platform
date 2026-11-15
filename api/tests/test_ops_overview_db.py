"""Migration 0012: ops_overview(), deploy_mark(), and who may call them.

Real Postgres, real logins. The overview function is the only way the console reads the fleet,
the sources and the rule inventory; it must never return a source's slug (the secret part of the
public webhook path), and deploy_mark must be callable by the superuser alone.
"""

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from conftest import SEED_FILE, TestDb
from test_worker_db import Fixture

from soc_api import db as soc_db
from soc_api import seed as soc_seed

SERVICE_ROLES = (
    "soc_app",
    "soc_ingest",
    "soc_console",
    "soc_reconcile",
    "soc_worker",
    "soc_posture",
)
SHA = "c0ffee" + "1" * 34


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def overview(fx: Fixture, days: int = 7, client: str = "all") -> dict[str, Any]:
    with fx.db.connect("soc_console") as c:
        row = c.execute("SELECT ops_overview(%s, %s)", (days, client)).fetchone()
    assert row is not None
    doc: dict[str, Any] = row[0]
    return doc


def demo(db: TestDb) -> Any:
    """The demo tenant only (no test fixture clients): anything with a .db will do."""
    soc_seed.seed(db.sqlalchemy_url(), SEED_FILE)
    soc_seed.seed_activity(db.sqlalchemy_url(), SEED_FILE, now=datetime.now(UTC))
    return SimpleNamespace(db=db)


def can_execute(fx: Fixture, role: str, function: str) -> bool:
    row = fx.one("SELECT has_function_privilege(%s, %s::regprocedure, 'EXECUTE')", (role, function))
    return bool(row[0])


# ---- who may call what ----


def test_only_the_console_login_can_call_the_overview(fx: Fixture) -> None:
    for role in (*SERVICE_ROLES, "public"):
        assert can_execute(fx, role, "ops_overview(integer, text)") == (role == "soc_console"), role
    for role in ("soc_app", "soc_ingest", "soc_reconcile", "soc_worker", "soc_posture"):
        with fx.db.connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT ops_overview(7, 'all')")


def test_the_overview_is_a_definer_owned_by_the_writer_with_a_pinned_search_path(
    fx: Fixture,
) -> None:
    row = fx.one(
        "SELECT p.prosecdef, p.provolatile, p.proconfig, r.rolname, r.rolcanlogin, r.rolsuper, "
        "r.rolbypassrls FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
        "WHERE p.proname = 'ops_overview'"
    )
    assert row[0] is True and row[1] == "s" and row[3] == "soc_console_writer"
    assert not any(row[4:])
    assert row[2] and any(x.startswith("search_path=pg_catalog") for x in row[2])


def test_no_service_role_may_mark_a_deploy(fx: Fixture) -> None:
    for role in (*SERVICE_ROLES, "soc_console_writer", "soc_worker_writer", "public"):
        assert not can_execute(fx, role, "deploy_mark(text)"), role
    for role in ("soc_console", "soc_worker", "soc_app"):
        with fx.db.connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT deploy_mark(%s)", (SHA,))
    assert fx.one("SELECT count(*) FROM deploy_event") == (0,)


def test_the_superuser_marks_a_deploy_and_it_shows_on_the_timeline(fx: Fixture) -> None:
    fx.run("SELECT deploy_mark(%s)", (SHA,))
    assert overview(fx)["deploys"][0]["sha"] == SHA[:7]
    assert overview(fx, days=1)["deploys"][0]["sha"] == SHA[:7]
    fx.run("UPDATE deploy_event SET at = now() - interval '10 days'")
    assert overview(fx, days=7)["deploys"] == []
    assert len(overview(fx, days=30)["deploys"]) == 1


@pytest.mark.parametrize(
    "bad", ["NULL", "'abc'", "'" + "G" * 40 + "'", "'" + "a" * 39 + "'", "'" + "A" * 40 + "'"]
)
def test_a_deploy_needs_a_full_lower_case_commit_hash(fx: Fixture, bad: str) -> None:
    with pytest.raises(psycopg.errors.RaiseException):
        fx.run(f"SELECT deploy_mark({bad}::text)")
    assert fx.one("SELECT count(*) FROM deploy_event") == (0,)


def test_the_new_table_is_closed_to_every_login_and_has_row_level_security(fx: Fixture) -> None:
    assert fx.one("SELECT relrowsecurity FROM pg_class WHERE relname = 'deploy_event'") == (True,)
    for role in SERVICE_ROLES:
        with fx.db.connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM deploy_event")


def test_the_writer_reads_only_the_columns_the_overview_needs(fx: Fixture) -> None:
    def can(table: str, column: str, privilege: str = "SELECT") -> bool:
        return bool(
            fx.one(
                "SELECT has_column_privilege('soc_console_writer', %s, %s, %s)",
                (table, column, privilege),
            )[0]
        )

    for column in ("slug", "external_id", "secret_ref"):
        assert not can("source", column), column
    for table, columns in (
        ("source", ("id", "client_id", "type", "enabled")),
        ("sensor_state", ("hostname", "online", "last_seen", "updated_at")),
        ("rule_inventory", ("namespace", "name", "enabled")),
        ("deploy_event", ("at", "sha")),
        ("reconcile_cursor", ("source_id", "last_error", "last_success")),
        ("posture_run", ("at", "ok", "org_error_count")),
    ):
        for column in columns:
            assert can(table, column) and not can(table, column, "UPDATE"), (table, column)
            assert not can(table, column, "INSERT"), (table, column)
    assert not can("sensor_state", "tags") and not can("posture_run", "error")
    for table in ("source", "sensor_state", "rule_inventory", "deploy_event"):
        delete = fx.one("SELECT has_table_privilege('soc_console_writer', %s, 'DELETE')", (table,))
        assert delete == (False,), table


# ---- the arguments ----


@pytest.mark.parametrize("days", [0, 2, 8, 31, -1, 365])
def test_only_the_three_periods_are_accepted(fx: Fixture, days: int) -> None:
    with pytest.raises(psycopg.errors.RaiseException):
        overview(fx, days=days)


@pytest.mark.parametrize("client", ["nobody", "", "client-a'; DROP TABLE alert;--", "CLIENT-A"])
def test_an_unknown_client_is_refused_and_nothing_is_run(fx: Fixture, client: str) -> None:
    with pytest.raises(psycopg.errors.RaiseException):
        overview(fx, client=client)
    assert fx.one("SELECT to_regclass('alert') IS NOT NULL") == (True,)


def test_a_known_client_filters_every_count(fx: Fixture) -> None:
    fx.alert(source="a", host="h1")
    fx.alert(source="b", host="h2", rule="b.Rule")
    fx.assign()
    assert overview(fx)["totals"]["alerts_in"] == 2
    assert overview(fx, client="client-a")["totals"] == {"alerts_in": 1, "pages": 0, "cases": 1}
    assert overview(fx, client="client-b")["totals"]["alerts_in"] == 1
    assert [r["rule"] for r in overview(fx, client="client-b")["rules"]] == ["b.Rule"]
    assert "client-a" in overview(fx)["clients"] and "unassigned" in overview(fx)["clients"]


# ---- the numbers ----


def test_an_empty_database_gives_zeros_and_empty_lists(fx: Fixture) -> None:
    doc = overview(fx)
    assert doc["totals"] == {"alerts_in": 0, "pages": 0, "cases": 0}
    assert doc["queue"] == [] and doc["tactics"] == [] and doc["fleet"] == []
    assert doc["funnel"] == [] and doc["rules"] == [] and doc["deploys"] == []
    assert doc["response"]["7"]["mtta"] == {"n": 0, "avg_s": None}
    assert doc["flow"]["pager_p95_s"] is None and doc["flow"]["last_alert_age_s"] is None
    assert len(doc["timeline"]["rows"]) in (168, 169) and doc["timeline"]["unit"] == "hour"
    assert doc["health"]["sensors_total"] == 0


def test_the_timeline_buckets_hourly_for_a_week_and_daily_for_a_month(fx: Fixture) -> None:
    assert overview(fx, days=1)["timeline"]["unit"] == "hour"
    assert len(overview(fx, days=1)["timeline"]["rows"]) in (24, 25)
    month = overview(fx, days=30)["timeline"]
    assert month["unit"] == "day" and len(month["rows"]) in (30, 31)


def test_the_timeline_counts_by_source_type_never_by_source(fx: Fixture) -> None:
    fx.run("UPDATE source SET type = 'edr-webhook' WHERE slug = 'src-a'")
    fx.run("UPDATE source SET type = 'network-ids' WHERE slug = 'src-b'")
    fx.alert(source="a", host="h1")
    fx.alert(source="a", host="h2")
    fx.alert(source="b", host="h3")
    totals: dict[str, int] = {}
    for row in overview(fx)["timeline"]["rows"]:
        for kind, n in row["c"].items():
            totals[kind] = totals.get(kind, 0) + n
    assert totals == {"edr-webhook": 2, "network-ids": 1}
    assert "src-a" not in json.dumps(overview(fx)) and "src-b" not in json.dumps(overview(fx))


def test_pages_failed_and_the_pager_p95_come_from_the_notifications(fx: Fixture) -> None:
    for host in ("h1", "h2", "h3"):
        fx.alert(host=host)
    fx.assign()
    ids = [r[0] for r in fx.rows("SELECT id FROM notification ORDER BY id")]
    for i, nid in enumerate(ids[:2]):
        fx.run(
            "UPDATE notification SET status = 'sent', created_at = now() - interval '1 hour', "
            "sent_at = now() - interval '1 hour' + make_interval(secs => %s) WHERE id = %s",
            (2 + 6 * i, nid),
        )
    fx.run("UPDATE notification SET status = 'failed' WHERE id = %s", (ids[2],))
    flow = overview(fx)["flow"]
    assert flow["pager_n"] == 2 and 7.5 <= flow["pager_p95_s"] <= 8.0
    assert flow["pages_failed"] == 1 and overview(fx)["totals"]["pages"] == 2
    assert overview(fx, days=1)["totals"]["pages"] == 2


def test_mtta_and_mttr_are_means_over_the_window(fx: Fixture) -> None:
    for host in ("h1", "h2", "h3"):
        fx.alert(host=host)
    fx.assign()
    cases = {
        h: fx.one("SELECT case_id FROM alert WHERE raw #>> '{routing,hostname}' = %s", (h,))[0]
        for h in ("h1", "h2", "h3")
    }
    for h in ("h1", "h2"):
        fx.run(
            "UPDATE notification SET status = 'sent', sent_at = now() - interval '1 hour' "
            "WHERE case_id = %s",
            (cases[h],),
        )
        fx.run("SELECT ack_case(%s, 'operator@example.com')", (cases[h],))
    for h, secs in (("h1", 200), ("h2", 1000)):
        fx.run(
            "UPDATE case_event SET at = now() - interval '1 hour' + make_interval(secs => %s) "
            "WHERE case_id = %s AND kind = 'acked'",
            (secs, cases[h]),
        )
    fx.run("SELECT close_case(%s, 'operator@example.com', 'done')", (cases["h1"],))
    fx.run(
        "UPDATE soc_case SET opened_at = now() - interval '5 hours', "
        "closed_at = now() - interval '2 hours' WHERE id = %s",
        (cases["h1"],),
    )
    r7 = overview(fx)["response"]["7"]
    assert r7["mtta"] == {"n": 2, "avg_s": 600}
    assert r7["mttr"] == {"n": 1, "avg_s": 10800}
    # an acknowledgement 10 days ago counts in 30 days only
    fx.run("UPDATE case_event SET at = at - interval '10 days' WHERE kind = 'acked'")
    fx.run("UPDATE notification SET sent_at = sent_at - interval '10 days'")
    assert overview(fx)["response"]["7"]["mtta"]["n"] == 0
    assert overview(fx)["response"]["30"]["mtta"] == {"n": 2, "avg_s": 600}


def test_lanes_are_derived_and_a_written_lane_wins(fx: Fixture) -> None:
    fx.alert(host="h1", severity="high")
    fx.alert(host="h2", severity="low")
    fx.alert(host="h3", severity="low")
    fx.assign()
    c3 = fx.one("SELECT case_id FROM alert WHERE raw #>> '{routing,hostname}' = 'h3'")[0]
    fx.run("UPDATE soc_case SET lane = 'vendor' WHERE id = %s", (c3,))
    fx.run("DELETE FROM notification WHERE case_id = %s", (c3,))
    lanes = {(r["lane"], r["status"]): r["n"] for r in overview(fx)["funnel"]}
    paged = fx.one(
        "SELECT count(*) FROM notification WHERE kind = 'page' "
        "AND status IN ('pending', 'sent', 'failed')"
    )[0]
    assert lanes.get(("vendor", "open")) == 1
    assert lanes.get(("paged", "open"), 0) == paged
    assert sum(lanes.values()) == 3
    queue_lanes = {q["host"]: q["lane"] for q in overview(fx)["queue"]}
    assert queue_lanes["h3"] == "vendor"


def test_the_queue_has_the_verdict_or_nothing_and_the_age(fx: Fixture) -> None:
    fx.alert(host="h1", rule="r.One", severity="high")
    fx.assign()
    q = overview(fx)["queue"][0]
    assert q["verdict"] is None and q["rule"] == "r.One" and q["host"] == "h1"
    assert q["severity"] == "high" and q["status"] == "open" and 0 <= q["age_s"] < 60
    fx.run("UPDATE soc_case SET verdict = 'suspicious'")
    assert overview(fx)["queue"][0]["verdict"] == "suspicious"
    fx.run("SELECT close_case(id, 'operator@example.com', 'x') FROM soc_case")
    assert overview(fx)["queue"] == []


def test_tactics_come_from_the_mitre_hint_and_are_empty_without_one(fx: Fixture) -> None:
    fx.alert(host="h1")
    assert overview(fx)["tactics"] == []
    fx.alert(host="h2")
    fx.alert(host="h3")
    fx.alert(host="h4")
    fx.run(
        "UPDATE alert SET mitre_hint = 'Execution / T1059.004' WHERE event_id IN ('ev-1', 'ev-2')"
    )
    fx.run("UPDATE alert SET mitre_hint = 'Discovery' WHERE event_id = 'ev-3'")
    fx.run("UPDATE alert SET mitre_hint = 'Persistence / not a technique' WHERE event_id = 'ev-4'")
    got = {(t["tactic"], t["technique"]): t["n"] for t in overview(fx)["tactics"]}
    assert got == {
        ("Execution", "T1059.004"): 2,
        ("Discovery", None): 1,
        ("Persistence", None): 1,
    }


def test_sensors_sources_and_rules_are_listed_without_a_slug(fx: Fixture) -> None:
    fx.run(
        "INSERT INTO sensor_state (sid, hostname, platform, online, isolated, last_seen) VALUES "
        "('demo-sensor-a1', 'ws-1', 'windows', true, false, now() - interval '5 seconds'), "
        "('demo-sensor-a2', 'ws-2', 'linux', false, false, now() - interval '3 hours')"
    )
    fx.run(
        "INSERT INTO rule_inventory (namespace, name, enabled) VALUES ('general', 'Rule One', true)"
    )
    fx.alert(source="a", host="h1", rule="Rule One")
    fx.alert(source="a", host="h2", rule="Rule One")
    fx.alert(source="b", host="h3", rule="Other", severity="critical")
    fx.run(
        "INSERT INTO reconcile_cursor (source_id, window_end, last_success, last_error) "
        "SELECT id, now(), now() - interval '4 minutes', 'rate_limited' FROM source "
        "WHERE slug = 'src-a'"
    )
    doc = overview(fx)
    assert [(s["hostname"], s["online"]) for s in doc["fleet"]] == [("ws-2", False), ("ws-1", True)]
    assert doc["fleet"][0]["last_seen_age_s"] >= 10700
    assert doc["health"]["sensors_total"] == 2 and doc["health"]["sensors_online"] == 1
    sources = {s["client"]: s for s in doc["sources"]}
    assert set(sources) == {"client-a", "client-b"}
    assert sources["client-a"]["alerts"] == 2 and sources["client-a"]["has_cursor"] is True
    assert sources["client-a"]["catchup_error"] == "rate_limited"
    assert sources["client-b"]["has_cursor"] is False
    assert all("slug" not in s for s in doc["sources"])
    rules = {r["rule"]: r for r in doc["rules"]}
    assert rules["Rule One"]["alerts"] == 2 and rules["Rule One"]["inventory"] == "enabled"
    assert rules["Other"]["worst"] == "critical" and rules["Other"]["inventory"] is None
    assert doc["rule_inventory"] == [{"namespace": "general", "enabled": 1, "disabled": 0}]
    text = json.dumps(doc)
    assert "src-a" not in text and "src-b" not in text


# ---- the seeded demo tenant fills every panel ----


def test_the_demo_seed_fills_every_panel(db: TestDb) -> None:
    fx = demo(db)
    doc = overview(fx)
    t = doc["totals"]
    assert t["alerts_in"] > 100 and t["pages"] > 5 and t["cases"] > 20
    # Which lanes appear among the newest open cases depends on the time of day the seed
    # runs (its activity is spread over past hours); every lane is checked in the funnel.
    lanes = {q["lane"] for q in doc["queue"]}
    assert doc["queue"] and "paged" in lanes and lanes <= {"paged", "quiet", "vendor"}
    assert all(q["verdict"] is None for q in doc["queue"])
    assert len(doc["tactics"]) >= 6
    assert {f["lane"] for f in doc["funnel"]} == {"paged", "quiet", "vendor"}
    assert {f["status"] for f in doc["funnel"]} == {"open", "acknowledged", "closed"}
    assert doc["response"]["7"]["mtta"]["n"] > 0 and doc["response"]["30"]["mttr"]["n"] > 0
    assert doc["health"]["sensors_total"] == 15 and doc["health"]["sensors_online"] == 13
    assert (
        len(doc["deploys"]) == 2 and len(doc["fleet"]) == 15 and doc["fleet"][0]["online"] is False
    )
    assert len(doc["sources"]) == 3 and len(doc["rules"]) >= 8 and doc["rule_inventory"]
    kinds = {k for row in doc["timeline"]["rows"] for k in row["c"]}
    assert kinds == {"edr-webhook", "network-ids", "vendor-feed"}
    assert doc["flow"]["pager_n"] > 0 and doc["flow"]["pager_p95_s"] < 12
    # nothing in the demo trips the pager's own stale conditions
    assert doc["health"]["failed_last_24h"] == 0 and doc["health"]["posture_quiet_s"] < 600
    for slug in ("acme-lc", "acme-ids-7f3a", "acme-vendor-9c21"):
        assert slug not in json.dumps(doc)


def test_the_demo_seed_refuses_to_load_twice(db: TestDb) -> None:
    demo(db)
    with pytest.raises(soc_seed.SeedConflict):
        soc_seed.seed_activity(db.sqlalchemy_url(), SEED_FILE)


def test_the_demo_names_are_synthetic() -> None:
    text = SEED_FILE.read_text()
    for host in json.loads(text)["activity"]["hosts"]:
        assert host.startswith(("ws-demo-", "srv-demo-"))
    for adapter in json.loads(text)["activity"]["adapters"]:
        assert "-demo-" in adapter["hostname"] or adapter["hostname"].endswith("-demo-feed")
    assert "@example.com" in text


# ---- the migration itself ----


def test_downgrading_removes_it_all_and_upgrading_brings_it_back(db: TestDb, fx: Fixture) -> None:
    url = db.sqlalchemy_url()
    soc_db.downgrade(url, "0011")
    with db.connect() as c:
        assert c.execute("SELECT to_regprocedure('ops_overview(integer, text)')").fetchone() == (
            None,
        )
        assert c.execute("SELECT to_regprocedure('deploy_mark(text)')").fetchone() == (None,)
        assert c.execute("SELECT to_regclass('deploy_event')").fetchone() == (None,)
        assert c.execute(
            "SELECT count(*) FROM pg_policies WHERE policyname = 'console_overview_read'"
        ).fetchone() == (0,)
        for table, column in (("source", "type"), ("sensor_state", "hostname")):
            assert c.execute(
                "SELECT has_column_privilege('soc_console_writer', %s, %s, 'SELECT')",
                (table, column),
            ).fetchone() == (False,)
    soc_db.upgrade(url)
    assert overview(fx)["totals"]["alerts_in"] == 0
