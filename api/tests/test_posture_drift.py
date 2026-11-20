"""Rule drift (Sprint 4 E4): the posture collector checks each general rule's stamp.

Three layers. The stamp logic and the collector run against the same fake vendor API as the
collector's own tests, with a recording stand-in for the database, so they need no Postgres.
The database tests (migration 0018, the pager's count, the console's block) need one and are
skipped without it, exactly like the rest of the database suite.
"""

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import ROLE_PASSWORD, TestDb
from test_posture import OID, FakeLc, client, settings
from test_worker_db import Fixture

from soc_api import db as soc_db
from soc_api import overview as ov
from soc_api import posture as p
from soc_api import worker as w
from soc_api.rules import stamp as st

STAMP_KEY = "stamp-key-for-tests-only-0123456789abcdef"
OTHER_KEY = "another-key-for-tests-only-0123456789abcd"
PREFIXES = ("T - ", "BASE - ")
DETECT = {"event": "NEW_PROCESS", "op": "is", "path": "event/FILE_PATH", "value": "x.exe"}
RESPOND = [{"action": "report", "name": "t"}]
SECRET_TAG = "SECRET-TAG-DO-NOT-STORE"  # noqa: S105 - a marker, not a secret
SECRET_COMMENT = "SECRET-COMMENT-DO-NOT-STORE"  # noqa: S105 - a marker, not a secret


def deployed(
    name: str, *, detect: Any = DETECT, enabled: bool = True, key: str = STAMP_KEY
) -> dict[str, Any]:
    """A rule as the platform holds it after a deploy: the body, and the stamp in the tags."""
    tag = st.stamp_tag(key, detect, RESPOND, enabled)
    return {
        "data": {"detect": detect, "respond": RESPOND},
        "usr_mtd": {"enabled": enabled, "tags": [tag, SECRET_TAG], "comment": SECRET_COMMENT},
    }


AT = 1795190000  # the deploy time the test manifests carry


def manifest_rule(
    names: list[str],
    *,
    key: str = STAMP_KEY,
    at: int = AT,
    stamps: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The manifest as the deploy writes it: each name with the stamp of the body it deployed."""
    listed = (
        stamps
        if stamps is not None
        else {n: st.stamp_tag(STAMP_KEY, DETECT, RESPOND, True) for n in names}
    )
    return {
        "data": {"detect": st.MANIFEST_DETECT, "respond": st.MANIFEST_RESPOND},
        "usr_mtd": {
            "enabled": False,
            "tags": [st.stamp_tag(key, st.MANIFEST_DETECT, st.MANIFEST_RESPOND, False)],
            "comment": st.manifest_comment(key, listed, at),
        },
    }


def healthy(names: tuple[str, ...] = ("T - One", "T - Two")) -> dict[str, dict[str, Any]]:
    rules = {n: deployed(n) for n in names}
    rules[st.MANIFEST_NAME] = manifest_rule(list(names))
    return rules


class RecordingDb:
    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []

    def record(self, doc: dict[str, Any]) -> None:
        self.docs.append(doc)

    def fail(self, code: str) -> None:  # pragma: no cover - a failed run is not under test here
        raise AssertionError(code)

    def close(self) -> None:
        pass


@pytest.fixture
def lc() -> Iterator[FakeLc]:
    fake = FakeLc()
    fake.rules["dr-general"] = healthy()
    yield fake
    fake.server.shutdown()
    fake.server.server_close()


def run(fake: FakeLc, *, key: str = STAMP_KEY) -> tuple[dict[str, Any], p.Counts]:
    db = RecordingDb()
    collector = p.Collector(
        client(fake),
        db,  # type: ignore[arg-type]
        stamp_key=key,
        prefixes=PREFIXES,
    )
    counts = collector.run_once()
    return db.docs[-1], counts


def verdicts(doc: dict[str, Any]) -> dict[str, str | None]:
    return {r["name"]: r["drift"] for r in doc["rules"] if r["namespace"] == "general"}


# ---- the stamp logic ----


def test_a_rule_whose_stamp_matches_is_ok() -> None:
    tags = [st.stamp_tag(STAMP_KEY, DETECT, RESPOND, True)]
    assert st.classify_rule(STAMP_KEY, PREFIXES, "x", DETECT, RESPOND, True, tags) == "ok"


@pytest.mark.parametrize("what", ["detect", "respond", "enabled", "key", "second", "garbled"])
def test_any_change_to_the_body_the_flag_or_the_stamp_is_changed(what: str) -> None:
    detect, respond, enabled = dict(DETECT), list(RESPOND), True
    tag = st.stamp_tag(STAMP_KEY, DETECT, RESPOND, True)
    tags = [tag]
    if what == "detect":
        detect["value"] = "y.exe"
    elif what == "respond":
        respond = [{"action": "report", "name": "other"}]
    elif what == "enabled":
        enabled = False
    elif what == "key":
        tags = [st.stamp_tag(OTHER_KEY, DETECT, RESPOND, True)]
    elif what == "second":
        tags = [tag, "git:000000000000"]
    elif what == "garbled":
        tags = ["git:"]
    assert (
        st.classify_rule(STAMP_KEY, PREFIXES, "x", detect, respond, enabled, tags) == "changed"
    ), what


def test_a_rule_that_lost_its_stamp_is_changed_only_if_a_valid_manifest_lists_it() -> None:
    args = (STAMP_KEY, PREFIXES, "Plain", DETECT, RESPOND, True, ["other"])
    assert st.classify_rule(*args) is None
    assert st.classify_rule(*args, listed={"Plain": "git:000000000000"}) == "changed"


def test_a_hand_made_rule_with_a_managed_prefix_is_unmanaged_and_other_rules_are_not_ours() -> None:
    assert st.classify_rule(STAMP_KEY, PREFIXES, "T - Mine", DETECT, RESPOND, True, []) == (
        "unmanaged"
    )
    assert st.classify_rule(STAMP_KEY, PREFIXES, "Lab thing", DETECT, RESPOND, True, []) is None
    assert st.classify_rule(STAMP_KEY, (), "T - Mine", DETECT, RESPOND, True, []) is None


def test_a_malformed_body_does_not_crash_the_check() -> None:
    tags = ["git:abcdef012345"]
    assert st.classify_rule(STAMP_KEY, PREFIXES, "x", object(), None, True, tags) == "changed"


def test_a_manifest_is_good_only_for_the_key_that_made_it_and_with_its_own_body_intact() -> None:
    good = manifest_rule(["a", "b"])
    meta = good["usr_mtd"]
    args = (good["data"]["detect"], good["data"]["respond"], False, meta["tags"], meta["comment"])
    tag = st.stamp_tag(STAMP_KEY, DETECT, RESPOND, True)
    assert st.check_manifest(STAMP_KEY, *args) == ("ok", {"a": tag, "b": tag}, AT)
    assert st.check_manifest(OTHER_KEY, *args) == ("bad", {}, None)
    for broken in (
        (st.MANIFEST_DETECT | {"value": "x"}, args[1], False, args[3], args[4]),
        (args[0], [], False, args[3], args[4]),
        (args[0], args[1], True, args[3], args[4]),
        (args[0], args[1], False, [], args[4]),
        (args[0], args[1], False, args[3], args[4].replace('"a"', '"z"')),
        (args[0], args[1], False, args[3], args[4].replace(f'"at":{AT}', f'"at":{AT + 1}')),
        (args[0], args[1], False, args[3], args[4].replace(tag, "git:000000000000", 1)),
        (args[0], args[1], False, args[3], args[4].replace('"v":2', '"v":1')),
        (args[0], args[1], False, args[3], "soc-manifest not-json"),
        (args[0], args[1], False, args[3], None),
    ):
        assert st.check_manifest(STAMP_KEY, *broken) == ("bad", {}, None), broken


@pytest.mark.parametrize("at", [0, -5, st.MAX_AT + 1])
def test_a_manifest_time_out_of_range_is_not_accepted_even_with_a_good_check(at: int) -> None:
    tag = st.stamp_tag(STAMP_KEY, DETECT, RESPOND, True)
    body = {
        "v": 2,
        "rules": {"a": tag},
        "at": at,
        "mac": st.manifest_mac(STAMP_KEY, {"a": tag}, at),
    }
    comment = st.MANIFEST_COMMENT_PREFIX + json.dumps(body, separators=(",", ":"))
    assert st.parse_manifest_comment(STAMP_KEY, comment) is None
    assert st.parse_manifest_comment(STAMP_KEY, st.manifest_comment(STAMP_KEY, {"a": tag}, AT))


# ---- the collector ----


def test_a_deployed_org_has_no_drift(lc: FakeLc) -> None:
    doc, counts = run(lc)
    assert verdicts(doc) == {"T - One": "ok", "T - Two": "ok", "soc-manifest": None}
    assert doc["drift"] == {"manifest": "ok", "missing_count": 0, "missing": [], "manifest_at": AT}
    assert counts.drifted == 0
    # Only the general namespace carries a verdict.
    assert {r["drift"] for r in doc["rules"] if r["namespace"] != "general"} == {None}


def test_the_log_line_gives_the_drift_count_only_when_drift_is_checked(lc: FakeLc) -> None:
    _, checked = run(lc)
    _, unchecked = run(lc, key="")
    assert checked.line().endswith(" drifted=0")
    assert "drifted=" not in unchecked.line()


def test_a_rule_edited_in_the_web_app_is_changed(lc: FakeLc) -> None:
    lc.rules["dr-general"]["T - One"]["data"]["detect"] = dict(DETECT, value="evil.exe")
    doc, counts = run(lc)
    assert verdicts(doc)["T - One"] == "changed" and verdicts(doc)["T - Two"] == "ok"
    assert counts.drifted == 1


def test_a_rule_switched_off_in_the_web_app_is_changed(lc: FakeLc) -> None:
    lc.rules["dr-general"]["T - One"]["usr_mtd"]["enabled"] = False
    doc, _ = run(lc)
    assert verdicts(doc)["T - One"] == "changed"


def test_a_rule_whose_stamp_was_removed_is_changed_because_the_manifest_lists_it(
    lc: FakeLc,
) -> None:
    lc.rules["dr-general"]["T - One"]["usr_mtd"]["tags"] = [SECRET_TAG]
    doc, counts = run(lc)
    assert verdicts(doc)["T - One"] == "changed" and counts.drifted == 1


def test_a_stamp_made_with_another_key_is_changed(lc: FakeLc) -> None:
    lc.rules["dr-general"]["T - One"] = deployed("T - One", key=OTHER_KEY)
    doc, _ = run(lc)
    assert verdicts(doc)["T - One"] == "changed"


def test_a_rule_made_by_hand_under_a_managed_prefix_is_unmanaged(lc: FakeLc) -> None:
    lc.rules["dr-general"]["BASE - Mine"] = {"data": {"detect": DETECT}, "usr_mtd": {}}
    lc.rules["dr-general"]["Lab Rule"] = {"data": {"detect": DETECT}, "usr_mtd": {}}
    doc, counts = run(lc)
    assert verdicts(doc)["BASE - Mine"] == "unmanaged"
    assert verdicts(doc)["Lab Rule"] is None
    assert counts.drifted == 1


def test_a_rule_deleted_in_the_web_app_is_reported_missing(lc: FakeLc) -> None:
    del lc.rules["dr-general"]["T - Two"]
    doc, counts = run(lc)
    assert doc["drift"] == {
        "manifest": "ok",
        "missing_count": 1,
        "missing": ["T - Two"],
        "manifest_at": AT,
    }
    assert counts.drifted == 1


def test_a_deleted_manifest_beside_stamped_rules_is_absent_and_counts(lc: FakeLc) -> None:
    del lc.rules["dr-general"][st.MANIFEST_NAME]
    doc, counts = run(lc)
    assert doc["drift"]["manifest"] == "absent" and counts.drifted == 1


def test_no_manifest_and_no_stamped_rules_means_nothing_was_deployed_yet(lc: FakeLc) -> None:
    lc.rules["dr-general"] = {"Lab Rule": {"data": {"detect": DETECT}, "usr_mtd": {}}}
    doc, counts = run(lc)
    assert doc["drift"]["manifest"] == "none" and counts.drifted == 0


def test_a_forged_manifest_is_bad_and_cannot_hide_a_deleted_rule(lc: FakeLc) -> None:
    # Someone deletes T - Two and rewrites the list without it, but cannot make the check value.
    forged = manifest_rule(["T - One"], key=OTHER_KEY)
    lc.rules["dr-general"][st.MANIFEST_NAME] = forged
    del lc.rules["dr-general"]["T - Two"]
    doc, counts = run(lc)
    assert doc["drift"]["manifest"] == "bad" and counts.drifted == 1


def test_a_rule_put_back_to_an_older_deployed_version_is_changed(lc: FakeLc) -> None:
    # The live rule is an older deployed body with that body's own valid stamp; the manifest
    # of the current deploy lists the newer body's stamp for the name.
    newer = dict(DETECT, value="newer.exe")
    stamps = {
        "T - One": st.stamp_tag(STAMP_KEY, newer, RESPOND, True),
        "T - Two": st.stamp_tag(STAMP_KEY, DETECT, RESPOND, True),
    }
    lc.rules["dr-general"][st.MANIFEST_NAME] = manifest_rule([], stamps=stamps)
    doc, counts = run(lc)
    assert verdicts(doc)["T - One"] == "changed" and verdicts(doc)["T - Two"] == "ok"
    assert counts.drifted == 1


def test_a_bad_manifest_sends_no_deploy_time(lc: FakeLc) -> None:
    lc.rules["dr-general"][st.MANIFEST_NAME]["usr_mtd"]["enabled"] = True
    doc, _ = run(lc)
    assert doc["drift"]["manifest"] == "bad" and doc["drift"]["manifest_at"] is None


def test_a_good_stamp_on_a_name_the_manifest_does_not_list_is_unmanaged(lc: FakeLc) -> None:
    # A deployed body copied under a new name carries a valid stamp, but git never named it.
    lc.rules["dr-general"]["Copy Of One"] = deployed("Copy Of One")
    doc, counts = run(lc)
    assert verdicts(doc)["Copy Of One"] == "unmanaged" and counts.drifted == 1


def test_an_edited_manifest_body_is_bad(lc: FakeLc) -> None:
    lc.rules["dr-general"][st.MANIFEST_NAME]["usr_mtd"]["enabled"] = True
    doc, _ = run(lc)
    assert doc["drift"]["manifest"] == "bad"


def test_a_list_of_missing_rules_is_cut_at_the_cap_but_counted_exactly(lc: FakeLc) -> None:
    names = [f"T - R{i:03d}" for i in range(p.MAX_MISSING + 5)]
    lc.rules["dr-general"] = {st.MANIFEST_NAME: manifest_rule(names)}
    doc, counts = run(lc)
    assert doc["drift"]["missing_count"] == len(names)
    assert len(doc["drift"]["missing"]) == p.MAX_MISSING
    assert counts.drifted == len(names)


def test_without_a_stamp_key_drift_is_not_checked_and_never_reported_as_clean(
    lc: FakeLc,
) -> None:
    doc, counts = run(lc, key="")
    assert "drift" not in doc and counts.drifted is None
    assert set(verdicts(doc).values()) == {None}


def test_a_namespace_the_org_does_not_have_means_drift_is_not_checked(lc: FakeLc) -> None:
    lc.fail["/hive/dr-general/" + OID] = 404
    doc, counts = run(lc)
    assert "drift" not in doc and counts.drifted is None


def test_nothing_from_a_rule_body_tag_comment_or_the_key_reaches_the_document(
    lc: FakeLc, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    doc, counts = run(lc)
    text = json.dumps(doc) + counts.line() + caplog.text
    for secret in (SECRET_TAG, SECRET_COMMENT, STAMP_KEY, "x.exe", "NEW_PROCESS"):
        assert secret not in text, secret
    stamps = [st.stamp_tag(STAMP_KEY, DETECT, RESPOND, True)]
    assert stamps[0] not in text


def test_drift_adds_no_new_vendor_call(lc: FakeLc) -> None:
    run(lc)
    with_drift = sorted(lc.gets())
    lc.log.clear()
    run(lc, key="")
    assert sorted(lc.gets()) == with_drift


def test_a_rule_record_of_the_wrong_shape_is_still_only_a_changed_verdict(lc: FakeLc) -> None:
    lc.rules["dr-general"]["T - One"] = {"data": "nope", "usr_mtd": {"tags": "nope"}}
    doc, _ = run(lc)
    assert verdicts(doc)["T - One"] in ("changed", "unmanaged")


# ---- configuration ----


def test_the_stamp_key_and_prefixes_are_read_from_their_own_settings() -> None:
    cfg = p.Config.from_settings(
        settings(posture_stamp_key=STAMP_KEY, posture_rules_prefixes="T - |BASE - ")
    )
    assert cfg.stamp_key == STAMP_KEY and cfg.prefixes == ("T - ", "BASE - ")
    assert STAMP_KEY not in repr(cfg)


def test_without_a_stamp_key_the_collector_is_configured_exactly_as_before() -> None:
    cfg = p.Config.from_settings(settings())
    assert cfg.stamp_key == "" and cfg.prefixes == ()


@pytest.mark.parametrize(
    ("kw", "named"),
    [
        ({"posture_stamp_key": "short"}, "SOC_POSTURE_STAMP_KEY"),
        ({"posture_stamp_key": "a b" * 20}, "SOC_POSTURE_STAMP_KEY"),
        (
            {"posture_stamp_key": STAMP_KEY, "posture_rules_prefixes": "x"},
            "SOC_POSTURE_RULES_PREFIXES",
        ),
        (
            {"posture_stamp_key": STAMP_KEY, "posture_rules_prefixes": "ok one|b$d one"},
            "SOC_POSTURE_RULES_PREFIXES",
        ),
    ],
)
def test_a_malformed_stamp_key_or_prefix_stops_the_service_and_names_the_setting(
    kw: dict[str, str], named: str
) -> None:
    with pytest.raises(ValueError, match=named) as err:
        p.Config.from_settings(settings(**kw))
    assert STAMP_KEY not in str(err.value)


# ---- the pager's text and the console's block ----


def test_the_push_says_how_many_and_never_which() -> None:
    assert (
        w.stale_text("rules_drift", 1) == "1 detection rule change outside git. Open the Rules tab."
    )
    assert w.stale_text("rules_drift", 3).startswith("3 detection rule changes outside git")
    assert w.stale_text("backup_old") == w.STALE_TEXT["backup_old"]
    assert not re.search(r"[A-Za-z]+ - ", w.stale_text("rules_drift", 3))


def test_drift_is_a_stale_reason_only_when_something_is_wrong() -> None:
    counts = {"oldest_pending_page_s": 0, "failed_last_24h": 0, "oldest_unassigned_alert_s": 0}
    kwargs = {
        "counts": counts,
        "sources": 0,
        "quiet": None,
        "backup_age": 0.0,
        "limits": w.Limits(),
    }
    assert w.stale_reasons(**kwargs)["rules_drift"] is False
    assert w.stale_reasons(**kwargs, rules_drift=0)["rules_drift"] is False
    assert w.stale_reasons(**kwargs, rules_drift=2)["rules_drift"] is True


def test_the_rules_tab_block_names_what_is_wrong_and_says_when_nothing_was_checked() -> None:
    assert ov.rules_drift({}) is None and ov.rules_drift({"rules_drift": None}) is None
    block = ov.rules_drift(
        {
            "rules_drift": {
                "manifest": "ok",
                "missing_count": 3,
                "missing": ["Gone"],
                "ok": 12,
                "rules": [
                    {"name": "Edited", "state": "changed"},
                    {"name": "Mine", "state": "unmanaged"},
                ],
            }
        }
    )
    assert block is not None
    assert block["wrong"] == 5 and block["ok"] == 12 and block["missing_count"] == 3
    assert [(r["name"], r["what"]) for r in block["changed"]] == [
        ("Edited", "changed outside git"),
        ("Mine", "made by hand, not deployed"),
    ]


def test_an_unknown_manifest_word_is_shown_as_bad() -> None:
    block = ov.rules_drift({"rules_drift": {"manifest": "weird", "missing_count": 0}})
    assert block is not None and block["manifest"] == "bad" and block["wrong"] == 1


def test_the_system_page_reads_the_same_count_as_the_pager() -> None:
    health = {
        "oldest_pending_page_s": 0,
        "failed_last_24h": 0,
        "oldest_unassigned_alert_s": 0,
        "reconcile_sources": 0,
        "reconcile_quiet_s": None,
        "backup_age_s": 0,
        "posture_runs": 1,
        "posture_quiet_s": 10,
    }
    assert ov.stale_firing({"health": health})["rules_drift"] is False
    assert ov.stale_firing({"health": {**health, "rules_drift": None}})["rules_drift"] is False
    assert ov.stale_firing({"health": {**health, "rules_drift": 0}})["rules_drift"] is False
    assert ov.stale_firing({"health": {**health, "rules_drift": 2}})["rules_drift"] is True


# ---- the migration, without a database ----

VERSIONS = Path(__file__).resolve().parents[1] / "src" / "soc_api" / "migrations" / "versions"


def _module(prefix: str) -> Any:
    import importlib.util

    path = next(VERSIONS.glob(f"{prefix}_*.py"))
    spec = importlib.util.spec_from_file_location(f"mig_{prefix}", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_text_swap_of_the_migration_matches_the_definition_it_patches_exactly_once() -> None:
    m18 = _module("0018")
    posture_source = (next(VERSIONS.glob("0011_*.py"))).read_text()
    for old, _ in m18.RECORD_SWAPS:
        assert posture_source.count(old) == 1, old
    overview_source = _module("0012").OPS_OVERVIEW.replace(
        _module("0016").ANCHOR, _module("0016").ADDED
    )
    for old, _ in m18.OVERVIEW_SWAPS:
        assert overview_source.count(old) == 1, old


def test_the_swaps_can_be_undone_exactly() -> None:
    m18 = _module("0018")
    source = (next(VERSIONS.glob("0011_*.py"))).read_text()
    forward = source
    for old, new in m18.RECORD_SWAPS:
        forward = forward.replace(old, new)
    back = forward
    for old, new in m18.RECORD_SWAPS:
        assert back.count(new) == 1, new
        back = back.replace(new, old)
    assert back == source


def test_every_text_swap_of_0019_matches_the_definitions_0018_left_exactly_once() -> None:
    m18, m19 = _module("0018"), _module("0019")
    record = (next(VERSIONS.glob("0011_*.py"))).read_text()
    for old, new in m18.RECORD_SWAPS:
        record = record.replace(old, new)
    for old, _ in m19.RECORD_SWAPS:
        assert record.count(old) == 1, old
    overview = _module("0012").OPS_OVERVIEW.replace(_module("0016").ANCHOR, _module("0016").ADDED)
    for old, new in m18.OVERVIEW_SWAPS:
        overview = overview.replace(old, new)
    health = (next(VERSIONS.glob("0018_*.py"))).read_text()
    for old, _ in m19.COUNT_SWAPS:
        assert overview.count(old) == 1, old
        assert m18.WRONG_COUNT.count(old) == 1, old
        assert health.count("rules_drift_health") >= 1


# ---- the database (skipped without Postgres) ----


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


@pytest.fixture
def posture_db(fx: Fixture) -> Iterator[p.PostureDb]:
    handle = p.PostureDb(fx.db.sqlalchemy_url("soc_posture", ROLE_PASSWORD))
    yield handle
    handle.close()


def base_doc(drift: dict[str, Any] | None, **verdict: str | None) -> dict[str, Any]:
    rules = [
        {"namespace": "general", "name": name, "enabled": True, "drift": v}
        for name, v in verdict.items()
    ]
    doc: dict[str, Any] = {
        "sensors": [],
        "rules": rules,
        "org_errors": {"count": 0, "newest": None},
    }
    if drift is not None:
        doc["drift"] = drift
    return doc


CLEAN = {"manifest": "ok", "missing_count": 0, "missing": []}


def test_the_verdicts_and_the_manifest_state_are_stored_and_replaced(
    fx: Fixture, posture_db: p.PostureDb
) -> None:
    posture_db.record(
        base_doc(
            {"manifest": "ok", "missing_count": 1, "missing": ["Gone"]}, A="ok", B="changed", C=None
        )
    )
    assert fx.rows("SELECT name, drift FROM rule_inventory ORDER BY name") == [
        ("A", "ok"),
        ("B", "changed"),
        ("C", None),
    ]
    assert fx.rows("SELECT manifest, missing_count, missing FROM rules_drift") == [
        ("ok", 1, ["Gone"])
    ]
    posture_db.record(base_doc(CLEAN, A="ok"))
    assert fx.rows("SELECT name FROM rule_inventory") == [("A",)]
    assert fx.rows("SELECT missing_count, missing FROM rules_drift") == [(0, [])]


def test_a_document_without_drift_clears_the_state_so_it_reads_as_not_checked(
    fx: Fixture, posture_db: p.PostureDb
) -> None:
    posture_db.record(base_doc(CLEAN, A="changed"))
    posture_db.record(base_doc(None, A=None))
    assert fx.rows("SELECT * FROM rules_drift") == []
    assert fx.rows("SELECT drift FROM rule_inventory") == [(None,)]
    assert fx.one("SELECT checked, wrong FROM rules_drift_health()") == (False, 0)


@pytest.mark.parametrize(
    "doc",
    [
        base_doc({"manifest": "weird", "missing_count": 0, "missing": []}),
        base_doc({"manifest": "ok", "missing_count": -1, "missing": []}),
        base_doc({"manifest": "ok", "missing_count": 0, "missing": [1]}),
        base_doc({"manifest": "ok", "missing_count": 0, "missing": ["x"] * 201}),
        base_doc({"manifest": "ok", "missing_count": 0, "missing": ["x" * 256]}),
        base_doc({"manifest": "ok", "missing_count": 0}),
        base_doc(CLEAN, A="bogus"),
    ],
)
def test_a_bad_drift_field_is_refused_and_nothing_is_written(
    fx: Fixture, posture_db: p.PostureDb, doc: dict[str, Any]
) -> None:
    import psycopg

    with pytest.raises(psycopg.errors.RaiseException):
        posture_db.record(doc)
    assert (
        fx.rows("SELECT * FROM rule_inventory") == [] and fx.rows("SELECT * FROM rules_drift") == []
    )


def test_deleting_the_manifest_and_every_managed_rule_stays_absent_not_none(
    fx: Fixture, posture_db: p.PostureDb
) -> None:
    posture_db.record(base_doc(CLEAN, A="ok"))
    none = {"manifest": "none", "missing_count": 0, "missing": []}
    for _ in range(2):  # and it stays so on the next runs
        posture_db.record(base_doc(none, Lab=None))
        assert fx.rows("SELECT manifest FROM rules_drift") == [("absent",)]
        assert fx.one("SELECT checked, wrong FROM rules_drift_health()") == (True, 1)
    posture_db.record(base_doc(CLEAN, A="ok"))
    assert fx.rows("SELECT manifest FROM rules_drift") == [("ok",)]


def test_a_first_check_with_nothing_deployed_is_none(fx: Fixture, posture_db: p.PostureDb) -> None:
    posture_db.record(base_doc({"manifest": "none", "missing_count": 0, "missing": []}))
    assert fx.one("SELECT checked, wrong FROM rules_drift_health()") == (True, 0)


def manifest_doc(state: str = "ok", at: int | None = AT) -> dict[str, Any]:
    return {"manifest": state, "missing_count": 0, "missing": [], "manifest_at": at}


def test_a_whole_older_deploy_put_back_is_stale_until_a_newer_one(
    fx: Fixture, posture_db: p.PostureDb
) -> None:
    posture_db.record(base_doc(manifest_doc(at=AT), A="ok"))
    posture_db.record(base_doc(manifest_doc(at=AT + 3600), A="ok"))
    assert fx.rows("SELECT manifest, manifest_at, manifest_at_max FROM rules_drift") == [
        ("ok", AT + 3600, AT + 3600)
    ]
    for _ in range(2):  # the older manifest, with the rules it listed, put back
        posture_db.record(base_doc(manifest_doc(at=AT), A="ok"))
        assert fx.rows("SELECT manifest, manifest_at_max FROM rules_drift") == [
            ("stale", AT + 3600)
        ]
        assert fx.one("SELECT checked, wrong FROM rules_drift_health()") == (True, 1)
    posture_db.record(base_doc(manifest_doc(at=AT + 7200), A="ok"))
    assert fx.rows("SELECT manifest, manifest_at_max FROM rules_drift") == [("ok", AT + 7200)]
    assert fx.one("SELECT checked, wrong FROM rules_drift_health()") == (True, 0)


def test_the_same_deploy_seen_again_is_not_stale(fx: Fixture, posture_db: p.PostureDb) -> None:
    for _ in range(3):
        posture_db.record(base_doc(manifest_doc(at=AT), A="ok"))
    assert fx.rows("SELECT manifest FROM rules_drift") == [("ok",)]


def test_the_console_counts_and_names_a_stale_manifest(
    fx: Fixture, posture_db: p.PostureDb
) -> None:
    posture_db.record(base_doc(manifest_doc(at=AT + 60), A="ok"))
    posture_db.record(base_doc(manifest_doc(at=AT), A="ok"))
    with fx.db.connect("soc_console") as c:
        row = c.execute("SELECT ops_overview(7, 'all')").fetchone()
    assert row is not None
    data = dict(row[0])
    assert data["health"]["rules_drift"] == 1 and data["rules_drift"]["manifest"] == "stale"
    block = ov.rules_drift(data)
    assert block is not None and block["wrong"] == 1 and "put back" in block["manifest_text"]


@pytest.mark.parametrize("at", [-1, 1.5, "x", 10**11, True])
def test_a_bad_manifest_time_is_refused(fx: Fixture, posture_db: p.PostureDb, at: Any) -> None:
    import psycopg

    with pytest.raises(psycopg.errors.RaiseException):
        posture_db.record(base_doc(manifest_doc(at=at), A="ok"))
    assert fx.rows("SELECT * FROM rules_drift") == []


def test_an_old_collector_document_without_the_new_fields_still_records(
    fx: Fixture, posture_db: p.PostureDb
) -> None:
    doc = base_doc(None)
    doc["rules"] = [{"namespace": "general", "name": "A", "enabled": True}]
    posture_db.record(doc)
    assert fx.rows("SELECT name, drift FROM rule_inventory") == [("A", None)]


def test_the_pager_counts_changed_unmanaged_missing_and_a_bad_manifest(
    fx: Fixture, posture_db: p.PostureDb
) -> None:
    def wrong() -> Any:
        return fx.one("SELECT checked, wrong FROM rules_drift_health()")

    assert wrong() == (False, 0)
    posture_db.record(base_doc(CLEAN, A="ok"))
    assert wrong() == (True, 0)
    posture_db.record(
        base_doc(
            {"manifest": "bad", "missing_count": 2, "missing": ["x", "y"]},
            A="ok",
            B="changed",
            C="unmanaged",
        )
    )
    assert wrong() == (True, 5)


def test_the_pager_worker_may_call_the_count_and_the_other_service_logins_may_not(
    fx: Fixture,
) -> None:
    import psycopg

    with fx.db.connect("soc_worker") as c:
        assert c.execute("SELECT checked FROM rules_drift_health()").fetchone() == (False,)
    for role in ("soc_posture", "soc_console", "soc_ingest", "soc_app"):
        with fx.db.connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM rules_drift_health()")


def test_the_new_table_is_closed_to_every_login_and_to_the_worker_and_console_writers_writes(
    fx: Fixture,
) -> None:
    import psycopg

    assert fx.one("SELECT relrowsecurity FROM pg_class WHERE relname = 'rules_drift'") == (True,)
    for role in ("soc_posture", "soc_console", "soc_worker", "soc_ingest", "soc_app"):
        with fx.db.connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM rules_drift")
    for role in ("soc_console_writer", "soc_worker_writer"):
        for command in ("INSERT", "UPDATE", "DELETE"):
            assert fx.one("SELECT has_table_privilege(%s, 'rules_drift', %s)", (role, command)) == (
                False,
            ), (role, command)
    for role in ("soc_console_writer", "soc_worker_writer"):
        assert fx.one(
            "SELECT has_column_privilege(%s, 'rule_inventory', 'drift', 'SELECT')", (role,)
        ) == (True,)


def test_the_console_overview_carries_the_count_and_the_names(
    fx: Fixture, posture_db: p.PostureDb
) -> None:
    def overview() -> dict[str, Any]:
        with fx.db.connect("soc_console") as c:
            row = c.execute("SELECT ops_overview(7, 'all')").fetchone()
        assert row is not None
        return dict(row[0])

    before = overview()
    assert before["rules_drift"] is None and before["health"]["rules_drift"] is None
    posture_db.record(
        base_doc({"manifest": "ok", "missing_count": 1, "missing": ["Gone"]}, A="ok", B="changed")
    )
    data = overview()
    assert data["health"]["rules_drift"] == 2
    block = data["rules_drift"]
    assert block["manifest"] == "ok" and block["missing"] == ["Gone"] and block["ok"] == 1
    assert block["rules"] == [{"name": "B", "state": "changed"}]
    # The page builder reads the same data.
    assert ov.rules_drift(data) is not None
    assert ov.stale_firing(data)["rules_drift"] is True


def drift_snapshot(fx: Fixture) -> dict[str, Any]:
    return {
        "functions": fx.rows(
            "SELECT p.proname, pg_get_functiondef(p.oid) FROM pg_proc p "
            "WHERE p.proname IN ('posture_record', 'ops_overview', 'rules_drift_health') "
            "ORDER BY 1"
        ),
        "columns": fx.rows(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'rule_inventory' ORDER BY 1"
        ),
        "tables": fx.rows("SELECT to_regclass('rules_drift')::text"),
        "policies": fx.rows(
            "SELECT tablename, policyname FROM pg_policies "
            "WHERE tablename IN ('rule_inventory', 'rules_drift') ORDER BY 1, 2"
        ),
    }


def test_downgrade_restores_the_0017_definitions_exactly(fx: Fixture) -> None:
    url = fx.db.sqlalchemy_url()
    head = drift_snapshot(fx)
    assert head["tables"] == [("rules_drift",)]
    soc_db.downgrade(url, "0017")
    after_down = drift_snapshot(fx)
    assert after_down["tables"] == [(None,)]
    assert [n for n, _ in after_down["functions"]] == ["ops_overview", "posture_record"]
    # the 0017 definitions are what the earlier migrations themselves build
    soc_db.downgrade(url, "0010")
    soc_db.upgrade(url, "0017")
    assert drift_snapshot(fx) == after_down
    soc_db.upgrade(url)
    assert drift_snapshot(fx) == head
