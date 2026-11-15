"""What the overview shows, worked out from the database's document (no database here)."""

import copy
from typing import Any

import pytest

from soc_api import overview as ov


def doc(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "generated_at": 1_763_000_000,
        "totals": {"alerts_in": 1512, "pages": 80, "cases": 402},
        "flow": {
            "last_alert_age_s": 4,
            "sources_total": 3,
            "sources_enabled": 3,
            "pages_sent": 80,
            "pages_failed": 0,
            "pager_p95_s": 3.14,
            "pager_n": 80,
            "unacked_pages": 0,
            "last_ack_age_s": 600,
        },
        "open_by_severity": {"high": 2, "low": 1},
        "queue": [],
        "tactics": [],
        "health": {
            "oldest_pending_page_s": None,
            "failed_last_24h": 0,
            "oldest_unassigned_alert_s": None,
            "reconcile_sources": 2,
            "reconcile_quiet_s": 120.0,
            "backup_age_s": 3600.0,
            "posture_runs": 5,
            "posture_quiet_s": 100.0,
            "reconcile_errors": 0,
            "org_errors": 0,
            "sensors_total": 4,
            "sensors_online": 4,
            "sensors_updated_age_s": 30,
            "last_page_sent_age_s": 90,
        },
        "timeline": {"unit": "hour", "rows": []},
        "deploys": [],
        "funnel": [],
        "response": {},
    }
    base.update(over)
    return base


def states(data: dict[str, Any]) -> dict[str, str]:
    return {r["name"]: r["state"] for r in ov.health(data)}


def test_durations_read_the_way_the_mockup_writes_them() -> None:
    assert [ov.ago(s) for s in (None, 4, 59, 60, 725, 6720, 90000)] == [
        "never",
        "4s",
        "59s",
        "1m",
        "12m",
        "1h 52m",
        "1d",
    ]
    assert [ov.dur(s) for s in (None, 5, 125, 11000, 200000)] == [
        "none",
        "5s",
        "2m 05s",
        "3h 03m",
        "2d 7h",
    ]
    assert ov.ago(True) == "never" and ov.ago("7") == "never" and ov.ago(-5) == "0s"


def test_filters_are_a_fixed_set_and_a_slug_syntax() -> None:
    assert ov.parse_filters("7", "all") == ("7", 7, "all")
    assert ov.parse_filters("1", "acme-demo") == ("1", 1, "acme-demo")
    for period, client in (
        ("2", "all"),
        ("", "all"),
        ("7 ", "all"),
        ("7", "A"),
        ("7", "a b"),
        ("7", "x;y"),
        ("7", ""),
        ("7", "a" * 65),
    ):
        with pytest.raises(ValueError, match="period|client"):
            ov.parse_filters(period, client)
    assert (
        ov.keep_query("7", "all") == ""
        and ov.keep_query("30", "acme-demo") == "?period=30&client=acme-demo"
    )


def test_the_title_line_and_flow_use_the_real_figures_and_name_the_unbuilt() -> None:
    d = doc()
    assert ov.title_line(d) == "1,512 alerts in, 80 pages to a human, 402 cases."
    f = ov.flow(d)
    assert [n["title"] for n in f["nodes"]] == ["SOURCES", "INGEST", "PAGE", "TRIAGE", "RESPOND"]
    assert [n["planned"] for n in f["nodes"]] == [False, False, False, True, True]
    assert f["nodes"][3]["big"] == "Sprint 5" and f["nodes"][4]["big"] == "Sprint 9"
    assert "pager p95 3.1 s" in f["meta"] and "newest alert 4s ago" in f["meta"]
    quiet = ov.flow(
        doc(flow={**d["flow"], "pager_n": 0, "pager_p95_s": None, "last_alert_age_s": None})
    )
    assert (
        "no pages yet" in quiet["meta"]
        and quiet["nodes"][2]["lines"][0] == "no page sent in this period"
    )


def test_a_healthy_pipeline_is_green_and_the_unbuilt_parts_are_grey() -> None:
    s = states(doc())
    assert s["Endpoint sensors"] == s["Pager and case builder"] == s["Database backups"] == "up"
    assert s["Catch-up worker"] == s["Posture collector"] == s["Alert sources"] == "up"
    assert s["Email backup path"] == s["LLM analyst"] == "idle"


def test_health_uses_the_pagers_own_thresholds() -> None:
    d = doc()
    for key, value, name, expect in (
        ("backup_age_s", 14 * 3600.0, "Database backups", "down"),
        ("backup_age_s", 8 * 3600.0, "Database backups", "warn"),
        ("backup_age_s", 12 * 3600.0, "Database backups", "warn"),
        ("reconcile_quiet_s", 1801.0, "Catch-up worker", "down"),
        ("reconcile_quiet_s", 1000.0, "Catch-up worker", "warn"),
        ("posture_quiet_s", 1801.0, "Posture collector", "down"),
        ("oldest_pending_page_s", 601, "Pager and case builder", "down"),
        ("oldest_pending_page_s", 599, "Pager and case builder", "up"),
        ("failed_last_24h", 1, "Pager and case builder", "down"),
        ("oldest_unassigned_alert_s", 700, "Pager and case builder", "down"),
        ("sensors_online", 3, "Endpoint sensors", "warn"),
        ("org_errors", 2, "Posture collector", "warn"),
        ("reconcile_errors", 1, "Catch-up worker", "warn"),
    ):
        d2 = copy.deepcopy(d)
        d2["health"][key] = value
        assert states(d2)[name] == expect, (key, value)
    # a host that never turned the collector, the catch-up worker or the sensors on is grey
    d3 = copy.deepcopy(d)
    d3["health"].update(
        posture_runs=0,
        posture_quiet_s=None,
        reconcile_sources=0,
        reconcile_quiet_s=None,
        sensors_total=0,
        sensors_online=0,
    )
    s3 = states(d3)
    assert s3["Posture collector"] == s3["Catch-up worker"] == s3["Endpoint sensors"] == "idle"


def test_a_cased_lane_outside_the_fixed_set_is_other_and_a_missing_verdict_is_not_analyzed() -> (
    None
):
    q = ov.queue(
        doc(
            queue=[
                {
                    "id": "11111111-1111-4111-8111-111111111111",
                    "severity": "high",
                    "status": "open",
                    "rule": "r",
                    "summary": "",
                    "host": None,
                    "lane": 'x" onload="y',
                    "verdict": None,
                    "age_s": 61,
                },
                {
                    "id": "22222222-2222-4222-8222-222222222222",
                    "severity": "low",
                    "status": "open",
                    "rule": "r",
                    "summary": "s",
                    "host": "h",
                    "lane": "vendor",
                    "verdict": "suspicious",
                    "age_s": 7300,
                },
            ]
        )
    )
    assert q[0]["lane"] == "other" and q[0]["lane_label"] == "other" and q[0]["verdict"] is None
    assert (
        q[0]["summary"] == "r"
        and q[0]["host"] == ""
        and q[0]["age"] == "1m"
        and q[0]["short"] == "11111111"
    )
    assert q[1]["lane"] == "vendor" and q[1]["verdict"] == "suspicious" and q[1]["age"] == "2h 01m"


def test_tactics_are_merged_ranked_and_never_free_text() -> None:
    rows = [
        {"tactic": "Execution", "technique": "T1059.004", "n": 5},
        {"tactic": "execution", "technique": "T1059", "n": 2},
        {"tactic": "Privilege Esc.", "technique": None, "n": 3},
        {"tactic": "<script>alert(1)</script>", "technique": None, "n": 1},
        {"tactic": "Command & Control", "technique": "T1071", "n": 4},
    ]
    t = ov.tactics(doc(tactics=rows))
    assert [(x["name"], x["n"], x["tech"]) for x in t] == [
        ("Execution", 7, "T1059.004"),
        ("Command and Control", 4, "T1071"),
        ("Privilege Escalation", 3, ""),
        ("Other", 1, ""),
    ]
    assert t[0]["pct"] == "100.0" and t[1]["pct"] == "57.1"
    assert ov.tactics(doc()) == []


def test_the_funnel_segments_add_up_and_stay_in_the_bar() -> None:
    f = ov.funnel(
        doc(
            funnel=[
                {"lane": "paged", "status": "open", "n": 2},
                {"lane": "paged", "status": "closed", "n": 8},
                {"lane": "quiet", "status": "closed", "n": 5},
                {"lane": "weird", "status": "odd", "n": 1},
            ]
        )
    )
    assert [(r["lane"], r["total"]) for r in f] == [("paged", 10), ("quiet", 5), ("other", 1)]
    for row in f:
        assert sum(float(s["w"]) for s in row["segments"]) <= 100.05
    assert f[0]["segments"][0] == {"status": "open", "n": 2, "x": "0.0", "w": "20.0"}


def test_the_response_tiles_say_none_yet_without_data() -> None:
    tiles = ov.response(
        doc(response={"7": {"mtta": {"n": 0, "avg_s": None}, "mttr": {"n": 2, "avg_s": 7200}}})
    )
    assert [t["value"] for t in tiles] == ["none yet", "2h 00m", "none yet", "none yet"]
    assert tiles[1]["note"].endswith("2 cases") and tiles[0]["label"].endswith("7 d")


def timeline_doc(
    rows: list[tuple[int, dict[str, int]]], unit: str = "hour", **over: Any
) -> dict[str, Any]:
    return doc(timeline={"unit": unit, "rows": [{"t": t, "c": c} for t, c in rows]}, **over)


def test_the_timeline_stacks_by_type_and_folds_the_sixth_type_into_other() -> None:
    base = 1_763_000_000 - 1_763_000_000 % 3600
    types = {f"type-{i}": 10 - i for i in range(7)}
    tl = ov.timeline(timeline_doc([(base, types), (base + 3600, {})]))
    assert len(tl["legend"]) == 6 and tl["legend"][-1]["type"] == "other types"
    assert tl["legend"][-1]["total"] == 5 + 4 and tl["total"] == sum(types.values())
    assert {b["cls"] for b in tl["bars"]} == {"t0", "t1", "t2", "t3", "t4", "t5"}
    assert len(tl["bars"]) == 6 and not tl["empty"]
    assert all(float(b["y"]) >= float(tl["top"]) for b in tl["bars"])  # nothing above the plot
    assert all("type-" in b["tip"] or "other types" in b["tip"] for b in tl["bars"])


def test_the_timeline_marks_only_deploys_inside_its_window() -> None:
    base = 1_763_000_000 - 1_763_000_000 % 3600
    rows = [(base + 3600 * i, {"edr": 1}) for i in range(24)]
    tl = ov.timeline(
        timeline_doc(
            rows,
            deploys=[
                {"at": base + 7200, "sha": "a" * 40},
                {"at": base - 99999, "sha": "b" * 40},
            ],
        )
    )
    assert [d["sha"] for d in tl["deploys"]] == ["aaaaaaa"]
    assert ov.PLOT_L < float(tl["deploys"][0]["x"]) < ov.PLOT_R
    assert ov.timeline(timeline_doc([(base, {})]))["empty"] is True


def test_nice_ceiling_gives_round_axis_tops() -> None:
    assert [ov.nice_ceiling(n) for n in (0, 3, 4, 5, 11, 20, 21, 130, 1900)] == [
        4,
        4,
        4,
        5,
        20,
        20,
        25,
        200,
        2000,
    ]


def test_fleet_sources_and_rules_rows() -> None:
    d = doc(
        fleet=[
            {
                "hostname": "ws-1",
                "platform": "windows",
                "version": None,
                "online": False,
                "isolated": False,
                "last_seen_age_s": 10800,
                "updated_age_s": 40,
            },
            {
                "hostname": "ws-2",
                "platform": "linux",
                "version": "1",
                "online": True,
                "isolated": True,
                "last_seen_age_s": 3,
                "updated_age_s": 40,
            },
        ],
        sources=[
            {
                "type": "edr",
                "client": "c",
                "enabled": True,
                "alerts": 4,
                "last_alert_age_s": 5,
                "has_cursor": True,
                "catchup_age_s": 100,
                "catchup_error": None,
            },
            {
                "type": "edr",
                "client": "c",
                "enabled": True,
                "alerts": 0,
                "last_alert_age_s": None,
                "has_cursor": True,
                "catchup_age_s": 2000,
                "catchup_error": None,
            },
            {
                "type": "ids",
                "client": "c",
                "enabled": False,
                "alerts": 0,
                "last_alert_age_s": None,
                "has_cursor": False,
                "catchup_age_s": None,
                "catchup_error": None,
            },
            {
                "type": "ids",
                "client": "c",
                "enabled": True,
                "alerts": 1,
                "last_alert_age_s": 5,
                "has_cursor": True,
                "catchup_age_s": 10,
                "catchup_error": "rate_limited",
            },
        ],
        rules=[
            {
                "rule": "",
                "alerts": 5,
                "cases": 2,
                "last_age_s": 60,
                "worst": "high",
                "inventory": None,
            }
        ],
    )
    assert [(r["label"], r["state"]) for r in ov.fleet(d)] == [
        ("offline", "down"),
        ("isolated", "warn"),
    ]
    assert [r["state"] for r in ov.sources(d)] == ["up", "down", "idle", "down"]
    assert ov.sources(d)[0]["label"] == "edr #1"
    rules = ov.rules(d)
    assert rules[0]["rule"] == "(no rule name)" and rules[0]["inventory"] == "not listed"
