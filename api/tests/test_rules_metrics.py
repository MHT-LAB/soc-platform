"""Migration 0020 and the Rules tab's quality card: fire rate, false-positive share, tactics.

Real Postgres for the function and the page; plain unit tests for how the page words it.
"""

import copy
from datetime import UTC, datetime
from typing import Any

import psycopg
import pytest
from conftest import ROLE_PASSWORD, SEED_FILE, TestDb
from fastapi.testclient import TestClient
from test_ops_overview_db import can_execute
from test_ops_overview_pages import USERS, get
from test_worker_db import Fixture

from soc_api import cases
from soc_api import db as soc_db
from soc_api import overview as ov
from soc_api import seed as soc_seed
from soc_api.config import Settings
from soc_api.main import create_console_app

SIG = "rules_metrics(text)"
DAY = 24 * 60  # minutes


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def metrics(fx: Fixture, client: str = "all") -> dict[str, Any]:
    with fx.db.connect("soc_console") as c:
        row = c.execute("SELECT rules_metrics(%s)", (client,)).fetchone()
    assert row is not None
    doc: dict[str, Any] = row[0]
    return doc


def by_rule(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["rule"]: r for r in doc["rules"]}


def case(fx: Fixture, events: list[str], verdict: str | None, status: str = "closed") -> None:
    """One case holding these alerts (all of one client), closed (or not) with a verdict."""
    row = fx.one(
        "SELECT client_id FROM alert WHERE event_id = %s",
        (events[0],),
    )
    made = fx.one(
        "INSERT INTO soc_case (client_id, severity, status, verdict, closed_at) "
        "VALUES (%s, 'low', %s, %s, CASE WHEN %s = 'closed' THEN now() END) RETURNING id",
        (row[0], status, verdict, status),
    )
    fx.run("UPDATE alert SET case_id = %s WHERE event_id = ANY(%s)", (made[0], events))


# ---- who may call it ----


def test_only_the_console_login_can_call_it(fx: Fixture) -> None:
    for role in (
        "soc_app",
        "soc_ingest",
        "soc_console",
        "soc_reconcile",
        "soc_worker",
        "soc_posture",
        "public",
    ):
        assert can_execute(fx, role, SIG) == (role == "soc_console"), role
    for role in ("soc_app", "soc_ingest", "soc_reconcile", "soc_worker", "soc_posture"):
        with fx.db.connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT rules_metrics('all')")


def test_it_is_a_definer_owned_by_the_writer_with_a_pinned_search_path(fx: Fixture) -> None:
    row = fx.one(
        "SELECT p.prosecdef, p.provolatile, p.proconfig, r.rolname, r.rolcanlogin, r.rolsuper, "
        "r.rolbypassrls FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
        "WHERE p.proname = 'rules_metrics'"
    )
    assert row[0] is True and row[1] == "s" and row[3] == "soc_console_writer"
    assert not any(row[4:])
    assert row[2] and any(x.startswith("search_path=pg_catalog") for x in row[2])


def test_downgrade_drops_it_and_upgrade_brings_it_back(db: TestDb) -> None:
    url = db.sqlalchemy_url()
    soc_db.downgrade(url, "0019")
    with db.connect() as c:
        assert c.execute(
            "SELECT count(*) FROM pg_proc WHERE proname = 'rules_metrics'"
        ).fetchone() == (0,)
    soc_db.upgrade(url)
    with db.connect() as c:
        assert c.execute(
            "SELECT count(*) FROM pg_proc WHERE proname = 'rules_metrics'"
        ).fetchone() == (1,)


# ---- what it counts ----


def test_nothing_yet_is_empty_lists_and_no_deploy(fx: Fixture) -> None:
    assert metrics(fx) == {"rules": [], "tactics": [], "deployed_at": None}


def test_the_seven_and_thirty_day_windows_are_each_their_own(fx: Fixture) -> None:
    fx.alert(rule="r.one", age_min=60)
    fx.alert(rule="r.one", age_min=3 * DAY)
    fx.alert(rule="r.one", age_min=7 * DAY + 600)  # just outside the 7 days
    fx.alert(rule="r.one", age_min=20 * DAY)
    fx.alert(rule="r.one", age_min=31 * DAY)  # too old for either
    row = by_rule(metrics(fx))["r.one"]
    assert (row["alerts_7"], row["alerts_30"]) == (2, 4)


def test_rules_come_busiest_first(fx: Fixture) -> None:
    for _ in range(3):
        fx.alert(rule="r.busy")
    fx.alert(rule="r.quiet")
    assert [r["rule"] for r in metrics(fx)["rules"]] == ["r.busy", "r.quiet"]


def test_only_closed_cases_with_a_real_verdict_are_judged(fx: Fixture) -> None:
    ev = [fx.alert(rule="r.one") for _ in range(7)]
    case(fx, [ev[0]], "test")
    case(fx, [ev[1]], "authorized_activity")
    case(fx, [ev[2]], "false_positive")
    case(fx, [ev[3]], "duplicate")  # says nothing about the rule
    case(fx, [ev[4]], None)  # closed with a plain note, no verdict
    case(fx, [ev[5]], "false_positive", status="open")  # not closed
    row = by_rule(metrics(fx))["r.one"]
    assert (row["judged"], row["noise"]) == (3, 3)


def test_a_case_with_several_alerts_of_one_rule_counts_once(fx: Fixture) -> None:
    ev = [fx.alert(rule="r.one") for _ in range(3)]
    case(fx, ev, "false_positive")
    row = by_rule(metrics(fx))["r.one"]
    assert (row["alerts_30"], row["judged"], row["noise"]) == (3, 1, 1)


def test_a_case_counts_for_every_rule_with_an_alert_in_it(fx: Fixture) -> None:
    case(fx, [fx.alert(rule="r.one"), fx.alert(rule="r.two")], "test")
    rows = by_rule(metrics(fx))
    assert (rows["r.one"]["noise"], rows["r.two"]["noise"]) == (1, 1)


def test_a_rule_whose_cases_were_all_real_has_no_noise(fx: Fixture) -> None:
    # "duplicate" is the only verdict that is not a judgment of the rule, and "true positive"
    # is not a quick-close verdict: a case closed any other way has no verdict at all
    ev = fx.alert(rule="r.one")
    case(fx, [ev], "duplicate")
    row = by_rule(metrics(fx))["r.one"]
    assert (row["judged"], row["noise"]) == (0, 0)


def test_the_client_filter_and_an_unknown_client(fx: Fixture) -> None:
    fx.alert("a", rule="r.a")
    fx.alert("b", rule="r.b")
    assert list(by_rule(metrics(fx, "client-a"))) == ["r.a"]
    assert sorted(by_rule(metrics(fx))) == ["r.a", "r.b"]
    with fx.db.connect("soc_console") as c, pytest.raises(psycopg.errors.RaiseException):
        c.execute("SELECT rules_metrics('nobody')")
    with fx.db.connect("soc_console") as c, pytest.raises(psycopg.errors.RaiseException):
        c.execute("SELECT rules_metrics(NULL)")


def test_the_alert_without_a_rule_name_is_one_row(fx: Fixture) -> None:
    fx.alert(rule=None)
    assert [r["rule"] for r in metrics(fx)["rules"]] == [""]


def test_tactics_are_counted_per_tactic_and_rule_from_the_hint(fx: Fixture) -> None:
    e = [fx.alert(rule="r.one"), fx.alert(rule="r.one"), fx.alert(rule="r.two")]
    fx.run(
        "UPDATE alert SET mitre_hint = 'Execution / T1059.004' WHERE event_id = ANY(%s)", (e[:2],)
    )
    fx.run("UPDATE alert SET mitre_hint = 'Execution' WHERE event_id = %s", (e[2],))
    fx.alert(rule="r.three")  # no hint: not counted
    fx.alert(rule="r.four", age_min=31 * DAY)
    fx.run("UPDATE alert SET mitre_hint = 'Impact' WHERE rule = 'r.four'")  # too old
    fx.run("UPDATE alert SET mitre_hint = '  / T1059' WHERE rule = 'r.three'")  # no tactic
    assert metrics(fx)["tactics"] == [
        {"tactic": "Execution", "rule": "r.one", "alerts": 2},
        {"tactic": "Execution", "rule": "r.two", "alerts": 1},
    ]


def test_the_deploy_time_is_the_newest_manifest_on_record(fx: Fixture) -> None:
    fx.run(
        "INSERT INTO rules_drift (manifest, missing_count, missing, manifest_at, manifest_at_max) "
        "VALUES ('ok', 0, '{}', 1763000000, 1763500000)"
    )
    assert metrics(fx)["deployed_at"] == 1763500000


# ---- how the page words it ----


def doc(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "rules": [
            {"rule": "r.one", "alerts_7": 14, "alerts_30": 30, "judged": 4, "noise": 3},
            {"rule": "r.two", "alerts_7": 0, "alerts_30": 1, "judged": 0, "noise": 0},
        ],
        "tactics": [
            {"tactic": "Execution", "rule": "r.one", "alerts": 9},
            {"tactic": "execution", "rule": "r.two", "alerts": 1},
            {"tactic": "Privilege Esc", "rule": "r.one", "alerts": 2},
            {"tactic": "Made Up", "rule": "r.one", "alerts": 5},
        ],
        "deployed_at": 1763500000,
    }
    base.update(over)
    return base


def test_the_share_is_a_whole_percent_or_a_dash() -> None:
    assert [ov.share(1, 3), ov.share(2, 3), ov.share(0, 5), ov.share(5, 5)] == [
        "33%",
        "67%",
        "0%",
        "100%",
    ]
    assert ov.share(0, 0) == "–"


def test_each_row_has_rates_a_share_and_a_flag_only_when_it_is_mostly_noise() -> None:
    m = ov.rules_metrics(doc())
    assert m is not None
    one, two = m["rows"]
    assert (one["per_day_7"], one["per_day_30"]) == ("2.0", "1.0")
    assert (one["fp_share"], one["hot"]) == ("75%", True)
    assert (two["fp_share"], two["hot"]) == ("–", False)


def test_a_few_cases_are_never_flagged() -> None:
    d = doc(rules=[{"rule": "r", "alerts_7": 1, "alerts_30": 1, "judged": 2, "noise": 2}])
    m = ov.rules_metrics(d)
    assert m is not None and m["rows"][0]["hot"] is False  # 100%, but only two cases
    half = doc(rules=[{"rule": "r", "alerts_7": 1, "alerts_30": 1, "judged": 4, "noise": 2}])
    m = ov.rules_metrics(half)
    assert m is not None and m["rows"][0]["hot"] is False  # exactly half is not "mostly"


def test_noise_can_never_exceed_judged() -> None:
    m = ov.rules_metrics(doc(rules=[{"rule": "r", "judged": 1, "noise": 9, "alerts_30": 1}]))
    assert m is not None and (m["rows"][0]["noise"], m["rows"][0]["fp_share"]) == (1, "100%")


def test_tactics_merge_spellings_and_count_each_rule_once() -> None:
    m = ov.rules_metrics(doc())
    assert m is not None
    cov = {c["name"]: c for c in m["coverage"]}
    assert (cov["Execution"]["alerts"], cov["Execution"]["rules"]) == (10, 2)
    assert (cov["Privilege Escalation"]["alerts"], cov["Privilege Escalation"]["rules"]) == (2, 1)
    assert (cov["Other"]["alerts"], cov["Other"]["rules"]) == (5, 1)
    assert cov["Impact"] == {"name": "Impact", "alerts": 0, "rules": 0}
    assert m["covered"] == 2 and m["tactic_total"] == 14
    assert [c["name"] for c in m["coverage"]][:3] == [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
    ]


def test_other_is_listed_only_when_something_landed_there() -> None:
    m = ov.rules_metrics(doc(tactics=[]))
    assert m is not None and "Other" not in [c["name"] for c in m["coverage"]]
    assert m["covered"] == 0


def test_the_deploy_time_is_written_in_utc_or_absent() -> None:
    m = ov.rules_metrics(doc())
    assert m is not None
    assert m["deployed"] == datetime.fromtimestamp(1763500000, UTC).strftime("%Y-%m-%d %H:%M UTC")
    for bad in (None, 0, -5, True, "x", 1.5):
        m = ov.rules_metrics(doc(deployed_at=bad))
        assert m is not None and m["deployed"] is None, bad


def test_junk_in_the_document_is_ignored_not_trusted() -> None:
    assert ov.rules_metrics(None) is None
    assert ov.rules_metrics("x") is None  # type: ignore[arg-type]
    d = copy.deepcopy(doc())
    d["rules"] = ["junk", 3, {"rule": None, "alerts_7": "9", "alerts_30": True}]
    d["tactics"] = [None, {"tactic": 7, "rule": None, "alerts": "x"}]
    m = ov.rules_metrics(d)
    assert m is not None
    assert m["rows"] == [
        {
            "rule": "(no rule name)",
            "alerts_7": 0,
            "alerts_30": 0,
            "per_day_7": "0.0",
            "per_day_30": "0.0",
            "judged": 0,
            "noise": 0,
            "fp_share": "–",
            "hot": False,
        }
    ]
    assert ov.rules_metrics({}) is not None


# ---- the page ----


@pytest.fixture
def demo(db: TestDb) -> TestClient:
    soc_seed.seed(db.sqlalchemy_url(), SEED_FILE)
    soc_seed.seed_activity(db.sqlalchemy_url(), SEED_FILE, now=datetime.now(UTC))
    settings = Settings(
        env="prod",
        console_users=USERS,
        version="edge",
        git_sha="a" * 40,
        console_database_url=db.sqlalchemy_url("soc_console", ROLE_PASSWORD),
    )
    return TestClient(create_console_app(settings))


def test_the_rules_tab_shows_the_quality_card_between_drift_and_the_noisy_list(
    demo: TestClient,
) -> None:
    text = get(demo, "/console/rules").text
    assert (
        text.index("Deployed from git") < text.index("Rule quality") < text.index("Top noisy rules")
    )
    assert "ATT&amp;CK tactics seen" in text and "False-positive share" in text
    assert "<script" in text and text.count("<script") == 1  # still only the clock's file


def test_the_card_does_not_move_with_the_period_or_client_filter(demo: TestClient) -> None:
    for path in ("/console/rules?period=1", "/console/rules?period=30&client=acme-demo"):
        assert "Rule quality" in get(demo, path).text, path


def test_if_only_the_metrics_read_fails_the_rest_of_the_page_still_shows(
    demo: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: Any, client: str) -> dict[str, Any]:
        raise cases.CasesUnavailable

    monkeypatch.setattr(cases.CaseDb, "rules_metrics", boom)
    r = get(demo, "/console/rules")
    assert r.status_code == 200
    assert "The rule numbers could not be read just now." in r.text
    assert "Top noisy rules" in r.text and "ATT&amp;CK tactics seen" not in r.text


def test_a_hostile_rule_name_is_escaped_on_the_new_card(db: TestDb, demo: TestClient) -> None:
    fx = Fixture(db)
    fx.alert(rule="<img src=x onerror=alert(1)>")
    text = get(demo, "/console/rules").text
    assert "&lt;img src=x onerror=alert(1)&gt;" in text and "<img src=x" not in text
