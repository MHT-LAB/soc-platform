"""The rules deploy (Sprint 4, E3): what git wants against what the platform has, the typed yes,
the stamps, the manifest, and what happens when something goes wrong part-way.

The platform is a fake that remembers what it was given; the wire format of the real client is
checked at the bottom against a local server."""

import json
import threading
import urllib.parse
from collections import deque
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from test_rules import cmd, put, valid_rule

from soc_api import rules_deploy as rd
from soc_api.reconcile import LcError
from soc_api.rules import stamp

OID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
LC_KEY = "vendor-key-for-tests-only"
STAMP_KEY = "stamp-key-for-tests-only-0123456789abcdef"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
NOW = datetime(2026, 11, 18, 9, 30, tzinfo=UTC)


def org_rule(name: str, enabled: bool = True, **over: Any) -> dict[str, Any]:
    rule = valid_rule(
        name=name,
        org="acme",
        enabled=enabled,
        respond=[{"action": "report", "name": name.replace(" ", "_"), "priority": 2}],
    )
    del rule["pack"]
    rule.update(over)
    return rule


def write_rules(tmp: Path, *rules: dict[str, Any]) -> Path:
    root = tmp / "detections"
    for i, rule in enumerate(rules):
        put(root, rule, f"orgs/acme/rule-{i}.json")
    return root


def make_cfg(tmp: Path, **over: Any) -> rd.Config:
    base: dict[str, Any] = {
        "key": LC_KEY,
        "oid": OID,
        "stamp_key": STAMP_KEY,
        "commit": COMMIT,
        "rules_dir": tmp / "detections",
        "org": "acme",
        "prefixes": ("T - ",),
        "out_dir": tmp / "out",
    }
    base.update(over)
    (tmp / "out").mkdir(exist_ok=True)
    return rd.Config(**base)


class FakeBackend:
    """The platform: it stores what it is given, the way the real one replaces metadata."""

    def __init__(self, live: dict[str, rd.LiveRule] | None = None) -> None:
        self.live: dict[str, rd.LiveRule] = dict(live or {})
        self.calls: list[tuple[str, str]] = []
        self.sent: list[dict[str, Any]] = []
        self.fail_on_call: int | None = None
        self.list_error: str | None = None
        self.reads = 0

    def list_rules(self) -> dict[str, rd.LiveRule]:
        self.reads += 1
        if self.list_error:
            raise LcError(self.list_error)
        return dict(self.live)

    def _tick(self, kind: str, name: str) -> None:
        if self.fail_on_call is not None and len(self.calls) == self.fail_on_call:
            raise LcError("http_5xx")
        self.calls.append((kind, name))

    def set_rule(
        self, name: str, data: dict[str, Any], usr_mtd: dict[str, Any], etag: str | None
    ) -> None:
        self._tick("set", name)
        self.sent.append({"name": name, "data": data, "usr_mtd": usr_mtd, "etag": etag})
        self.live[name] = rd.LiveRule(
            name,
            data["detect"],
            data["respond"],
            usr_mtd["enabled"],
            list(usr_mtd["tags"]),
            dict(usr_mtd),
            f"etag-{len(self.calls)}",
        )

    def delete_rule(self, name: str) -> None:
        self._tick("delete", name)
        del self.live[name]


def deploy(
    cfg: rd.Config, backend: FakeBackend, *, yes: bool = True, at: datetime = NOW
) -> tuple[int, list[str], list[str]]:
    lines: list[str] = []
    asked: list[str] = []

    def confirm(prompt: str) -> bool:
        asked.append(prompt)
        return yes

    code = rd.run(cfg, backend, confirm, lines.append, lambda: at)
    return code, lines, asked


def live_rule(
    name: str,
    detect: Any = None,
    respond: Any = None,
    enabled: bool = True,
    tags: list[str] | None = None,
    **meta: Any,
) -> rd.LiveRule:
    usr = {"enabled": enabled, "tags": tags or [], **meta}
    return rd.LiveRule(
        name, detect or {"op": "exists"}, respond or [], enabled, tags or [], usr, "e1"
    )


def stamped(r: dict[str, Any], key: str = STAMP_KEY, **meta: Any) -> rd.LiveRule:
    """A live rule exactly as a deploy of this git rule would have left it."""
    tag = stamp.stamp_tag(key, r["detect"], r["respond"], r["enabled"])
    return live_rule(r["name"], r["detect"], r["respond"], r["enabled"], [tag], **meta)


# ---- the stamp ----


def test_a_stamp_is_the_same_for_the_same_behaviour_in_any_key_order() -> None:
    a = stamp.stamp_tag(STAMP_KEY, {"op": "is", "path": "p"}, [{"action": "report"}], True)
    b = stamp.stamp_tag(STAMP_KEY, {"path": "p", "op": "is"}, [{"action": "report"}], True)
    assert a == b
    assert a.startswith("git:") and len(a) == len("git:") + 12


@pytest.mark.parametrize("change", ["detect", "respond", "enabled", "key"])
def test_any_change_to_what_a_rule_does_or_the_key_changes_the_stamp(change: str) -> None:
    args: dict[str, Any] = {"detect": {"op": "exists"}, "respond": [], "enabled": True}
    base = stamp.stamp_tag(STAMP_KEY, args["detect"], args["respond"], args["enabled"])
    other_key = STAMP_KEY
    if change == "detect":
        args["detect"] = {"op": "exists", "path": "x"}
    elif change == "respond":
        args["respond"] = [{"action": "report"}]
    elif change == "enabled":
        args["enabled"] = False
    else:
        other_key = STAMP_KEY + "x"
    assert stamp.stamp_tag(other_key, args["detect"], args["respond"], args["enabled"]) != base


def test_a_short_stamp_key_is_refused() -> None:
    with pytest.raises(ValueError, match="at least"):
        stamp.stamp_tag("short", {}, [], True)


def test_stamp_of_reads_exactly_one_git_tag() -> None:
    assert stamp.stamp_of(["x", "git:abc"]) == "git:abc"
    assert stamp.stamp_of(["git:a", "git:b"]) is None
    assert stamp.stamp_of(["x"]) is None
    assert stamp.stamp_of(None) is None


# ---- a first deploy, and a second that has nothing to do (acceptance 3) ----


def test_a_first_deploy_adds_every_rule_stamps_it_and_writes_the_manifest(tmp_path: Path) -> None:
    rules = [org_rule("T - One"), org_rule("T - Two", enabled=False)]
    cfg = make_cfg(tmp_path)
    write_rules(tmp_path, *rules)
    backend = FakeBackend()
    code, lines, asked = deploy(cfg, backend)
    assert code == rd.OK
    assert len(asked) == 1 and COMMIT[:12] in asked[0]
    assert sorted(n for _, n in backend.calls) == ["T - One", "T - Two", "soc-manifest"]
    one, two = backend.live["T - One"], backend.live["T - Two"]
    assert one.enabled is True and two.enabled is False
    assert one.tags == [stamp.stamp_tag(STAMP_KEY, one.detect, one.respond, True)]
    assert one.usr_mtd["comment"] == f"git {COMMIT[:12]}"
    manifest = backend.live["soc-manifest"]
    assert manifest.enabled is False
    comment = json.loads(manifest.usr_mtd["comment"].removeprefix("soc-manifest "))
    stamps = {"T - One": one.tags[0], "T - Two": two.tags[0]}
    assert comment["v"] == 2 and comment["rules"] == stamps
    assert comment["at"] == int(NOW.timestamp())
    assert comment["mac"] == stamp.manifest_mac(STAMP_KEY, stamps, int(NOW.timestamp()))
    assert stamp.parse_manifest_comment(STAMP_KEY, manifest.usr_mtd["comment"]) == (
        stamps,
        int(NOW.timestamp()),
    )
    assert any("added=2" in x and "result=applied" in x for x in lines)


def test_the_diff_is_shown_before_anything_is_asked_or_written(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    backend = FakeBackend()
    seen: list[list[str]] = []
    lines: list[str] = []

    def confirm(_prompt: str) -> bool:
        seen.append(list(lines))
        assert backend.calls == []  # nothing is written before the answer
        return True

    rd.run(make_cfg(tmp_path), backend, confirm, lines.append, lambda: NOW)
    assert any("+ add" in x and "T - One" in x for x in seen[0])
    assert any(x.startswith("=== + T - One") for x in seen[0])


def test_a_second_run_with_nothing_to_change_says_so_and_asks_and_writes_nothing(
    tmp_path: Path,
) -> None:
    # One rule is disabled: its stamp covers `enabled`, so it must still match on the second run.
    write_rules(tmp_path, org_rule("T - One"), org_rule("T - Two", enabled=False))
    cfg = make_cfg(tmp_path)
    backend = FakeBackend()
    deploy(cfg, backend)
    calls = list(backend.calls)
    code, lines, asked = deploy(cfg, backend)
    assert code == rd.OK
    assert asked == []
    assert backend.calls == calls
    assert any(x.startswith("Nothing to do") for x in lines)
    assert any("result=nothing-to-do" in x for x in lines)


def test_without_a_typed_yes_nothing_is_written(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    backend = FakeBackend()
    code, lines, _ = deploy(make_cfg(tmp_path), backend, yes=False)
    assert code == rd.DECLINED
    assert backend.calls == []
    assert any("result=declined" in x for x in lines)


class FakeStdin:
    def __init__(self, tty: bool) -> None:
        self.tty = tty

    def isatty(self) -> bool:
        return self.tty


@pytest.mark.parametrize(
    ("answer", "expected"),
    [("yes", True), (" yes ", True), ("y", False), ("YES", False), ("", False), ("no", False)],
)
def test_the_prompt_takes_exactly_yes(
    monkeypatch: pytest.MonkeyPatch, answer: str, expected: bool
) -> None:
    monkeypatch.setattr(rd.sys, "stdin", FakeStdin(True))
    monkeypatch.setattr("builtins.input", lambda _p: answer)
    assert rd.tty_confirm("ok? ") is expected


def test_with_no_terminal_the_answer_is_no(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rd.sys, "stdin", FakeStdin(False))

    def boom(_p: str) -> str:
        raise AssertionError("must not read without a terminal")

    monkeypatch.setattr("builtins.input", boom)
    assert rd.tty_confirm("ok? ") is False
    assert "no terminal" in capsys.readouterr().out


def test_end_of_input_at_the_prompt_is_no(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rd.sys, "stdin", FakeStdin(True))

    def eof(_p: str) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert rd.tty_confirm("ok? ") is False


# ---- changes, removals and what is never touched ----


def test_a_changed_rule_shows_its_diff_keeps_its_other_metadata_and_sends_the_etag(
    tmp_path: Path,
) -> None:
    git_rule = org_rule("T - One")
    write_rules(tmp_path, git_rule)
    old = live_rule(
        "T - One",
        {"op": "exists", "path": "event/OLD"},
        git_rule["respond"],
        True,
        ["keep-me", "git:oldoldoldold"],
        expiry=1900000000,
        comment="a person wrote this",
    )
    backend = FakeBackend({"T - One": old})
    code, lines, _ = deploy(make_cfg(tmp_path), backend)
    assert code == rd.OK
    assert any(x.startswith("=== ~ T - One") for x in lines)
    assert any("event/OLD" in x and x.startswith("-") for x in lines)  # the old body, struck
    sent = next(s for s in backend.sent if s["name"] == "T - One")
    assert sent["etag"] == "e1"  # the platform refuses the write if the rule moved since
    meta = sent["usr_mtd"]
    assert meta["expiry"] == 1900000000  # replaced as a whole, so the rest goes back as it was
    assert meta["tags"][0] == "keep-me" and len(meta["tags"]) == 2
    assert meta["tags"][1] == stamp.stamp_tag(
        STAMP_KEY, git_rule["detect"], git_rule["respond"], True
    )
    assert meta["comment"] == f"git {COMMIT[:12]}"
    assert sent["data"] == {"detect": git_rule["detect"], "respond": git_rule["respond"]}


def test_a_disabled_rule_in_git_is_written_disabled(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - Off", enabled=False))
    backend = FakeBackend()
    deploy(make_cfg(tmp_path), backend)
    assert backend.live["T - Off"].usr_mtd["enabled"] is False


def test_live_rules_that_are_not_managed_are_listed_and_never_touched(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    lab = live_rule("LAB - something", tags=["lab"])
    backend = FakeBackend({"LAB - something": lab, "extension rule": live_rule("extension rule")})
    _, lines, _ = deploy(make_cfg(tmp_path), backend)
    assert backend.live["LAB - something"] is lab
    assert "extension rule" in backend.live
    assert not any(k == "delete" for k, _ in backend.calls)
    assert any("left alone: 2" in x and "LAB - something" in x for x in lines)


def test_managed_rules_that_left_git_are_removed_by_prefix_and_by_stamp(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - Keep"))
    backend = FakeBackend(
        {
            "T - Gone by prefix": live_rule("T - Gone by prefix"),
            "lowercase-gone": live_rule("lowercase-gone", tags=["git:abcabcabcabc"]),
            "not ours": live_rule("not ours"),
        }
    )
    code, lines, _ = deploy(make_cfg(tmp_path), backend)
    assert code == rd.OK
    assert "T - Gone by prefix" not in backend.live
    assert "lowercase-gone" not in backend.live
    assert "not ours" in backend.live
    assert any("- remove" in x and "T - Gone by prefix" in x for x in lines)
    assert any("removed=2" in x for x in lines)


def test_a_rule_named_in_git_but_not_yet_stamped_is_adopted_without_a_body_change(
    tmp_path: Path,
) -> None:
    git_rule = org_rule("lower-case-rule")
    write_rules(tmp_path, git_rule)
    backend = FakeBackend(
        {
            "lower-case-rule": live_rule(
                "lower-case-rule", git_rule["detect"], git_rule["respond"], True
            )
        }
    )
    _, lines, _ = deploy(make_cfg(tmp_path), backend)
    assert any("only the stamp is new or wrong" in x for x in lines)
    assert not any(x.startswith("=== ~ lower-case-rule") for x in lines)  # no body diff to show
    assert backend.live["lower-case-rule"].tags[0].startswith("git:")


def test_a_rule_edited_in_the_web_app_after_a_deploy_is_put_back(tmp_path: Path) -> None:
    git_rule = org_rule("T - One")
    write_rules(tmp_path, git_rule)
    edited = live_rule(
        "T - One",
        {"op": "exists", "path": "event/SNEAKY"},
        git_rule["respond"],
        True,
        [stamp.stamp_tag(STAMP_KEY, git_rule["detect"], git_rule["respond"], True)],
    )
    backend = FakeBackend({"T - One": edited})
    deploy(make_cfg(tmp_path), backend)
    assert backend.live["T - One"].detect == git_rule["detect"]


def test_a_stamp_made_with_another_key_is_replaced(tmp_path: Path) -> None:
    git_rule = org_rule("T - One")
    write_rules(tmp_path, git_rule)
    backend = FakeBackend({"T - One": stamped(git_rule, key=STAMP_KEY + "other")})
    code, lines, asked = deploy(make_cfg(tmp_path), backend)
    assert asked  # not "nothing to do"
    assert backend.live["T - One"].tags == [
        stamp.stamp_tag(STAMP_KEY, git_rule["detect"], git_rule["respond"], True)
    ]
    assert code == rd.OK and lines


def test_two_stamps_on_one_rule_are_not_a_match(tmp_path: Path) -> None:
    git_rule = org_rule("T - One")
    write_rules(tmp_path, git_rule)
    good = stamped(git_rule)
    two = live_rule("T - One", good.detect, good.respond, True, [*good.tags, "git:forgedforged"])
    backend = FakeBackend({"T - One": two})
    _, _, asked = deploy(make_cfg(tmp_path), backend)
    assert asked
    assert len(backend.live["T - One"].tags) == 1


def test_a_changed_rule_list_rewrites_the_manifest_and_only_then(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    cfg = make_cfg(tmp_path)
    backend = FakeBackend()
    deploy(cfg, backend)
    first = backend.live["soc-manifest"].usr_mtd["comment"]
    put(tmp_path / "detections", org_rule("T - Two"), "orgs/acme/two.json")
    deploy(cfg, backend)
    second = backend.live["soc-manifest"].usr_mtd["comment"]
    assert first != second and "T - Two" in second


def test_a_later_run_with_nothing_changed_keeps_the_manifest_and_its_time(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    cfg = make_cfg(tmp_path)
    backend = FakeBackend()
    deploy(cfg, backend)
    first = backend.live["soc-manifest"].usr_mtd["comment"]
    calls = list(backend.calls)
    code, lines, asked = deploy(cfg, backend, at=NOW + timedelta(days=3))
    assert code == rd.OK and asked == [] and backend.calls == calls
    assert backend.live["soc-manifest"].usr_mtd["comment"] == first
    assert any(x.startswith("Nothing to do") for x in lines)


def test_a_changed_rule_body_gets_a_new_stamp_in_a_newer_manifest(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    cfg = make_cfg(tmp_path)
    backend = FakeBackend()
    deploy(cfg, backend)
    old_tag = backend.live["T - One"].tags[0]
    changed = org_rule("T - One")
    changed["description"] = "edited"
    changed["respond"] = [{"action": "report", "name": "T_One_v2", "priority": 2}]
    write_rules(tmp_path, changed)
    later = NOW + timedelta(hours=1)
    deploy(cfg, backend, at=later)
    new_tag = backend.live["T - One"].tags[0]
    parsed = stamp.parse_manifest_comment(
        STAMP_KEY, backend.live["soc-manifest"].usr_mtd["comment"]
    )
    assert new_tag != old_tag
    assert parsed == ({"T - One": new_tag}, int(later.timestamp()))


def test_a_manifest_of_the_old_format_is_replaced(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    cfg = make_cfg(tmp_path)
    backend = FakeBackend()
    deploy(cfg, backend)
    m = backend.live["soc-manifest"]
    m.usr_mtd["comment"] = 'soc-manifest {"v":1,"names":["T - One"],"mac":"000000000000"}'
    code, _, asked = deploy(cfg, backend)
    assert code == rd.OK and asked
    assert stamp.parse_manifest_comment(STAMP_KEY, backend.live["soc-manifest"].usr_mtd["comment"])


def test_a_manifest_deleted_or_edited_live_is_written_again(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    cfg = make_cfg(tmp_path)
    backend = FakeBackend()
    deploy(cfg, backend)
    del backend.live["soc-manifest"]
    code, _, asked = deploy(cfg, backend)
    assert code == rd.OK and asked and "soc-manifest" in backend.live


# ---- when something is wrong ----


def test_a_failure_part_way_stops_and_the_next_run_finishes_the_job(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"), org_rule("T - Two"), org_rule("T - Three"))
    cfg = make_cfg(tmp_path)
    backend = FakeBackend()
    backend.fail_on_call = 1  # the second write fails
    code, lines, _ = deploy(cfg, backend)
    assert code == rd.FAILED
    assert any("FAILED part-way (http_5xx)" in x for x in lines)
    assert any("result=failed-http_5xx" in x for x in lines)
    assert len(backend.live) == 1  # one done, the rest not tried
    backend.fail_on_call = None
    code, _, asked = deploy(cfg, backend)
    assert code == rd.OK and asked
    assert set(backend.live) == {"T - One", "T - Two", "T - Three", "soc-manifest"}
    assert deploy(cfg, backend)[2] == []  # and now there is nothing left


def test_rules_that_fail_the_contract_are_refused_before_the_platform_is_even_read(
    tmp_path: Path,
) -> None:
    bad = org_rule("T - Bad")
    bad["tests"]["negative"] = []
    write_rules(tmp_path, org_rule("T - Good"), bad)
    backend = FakeBackend()
    code, lines, asked = deploy(make_cfg(tmp_path), backend)
    assert code == rd.REFUSED
    assert backend.reads == 0 and backend.calls == [] and asked == []
    assert any("refused" in x and "nothing was changed" in x for x in lines)


def test_rules_whose_tests_do_not_pass_are_refused(tmp_path: Path) -> None:
    bad = org_rule("T - Bad")
    bad["tests"]["positive"] = [cmd("nothing to see")]
    write_rules(tmp_path, bad)
    backend = FakeBackend()
    code, lines, _ = deploy(make_cfg(tmp_path), backend)
    assert code == rd.REFUSED and backend.reads == 0
    assert any("does not fire on positive" in x for x in lines)


def test_an_unreadable_platform_refuses_and_changes_nothing(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    backend = FakeBackend()
    backend.list_error = "http_403"
    code, lines, asked = deploy(make_cfg(tmp_path), backend)
    assert code == rd.REFUSED and backend.calls == [] and asked == []
    assert any("result=refused-http_403" in x for x in lines)


def test_an_empty_org_folder_is_refused_so_it_can_never_wipe_the_org(tmp_path: Path) -> None:
    root = tmp_path / "detections"
    put(root, org_rule("T - Elsewhere", org="other"), "orgs/other/x.json")
    (root / "orgs" / "acme").mkdir(parents=True)
    backend = FakeBackend({"T - Live": live_rule("T - Live")})
    code, lines, _ = deploy(make_cfg(tmp_path), backend)
    assert code == rd.REFUSED
    assert "T - Live" in backend.live and backend.calls == [] and backend.reads == 0
    assert any("no deployable rules" in x for x in lines)


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda r: r.pop("enabled"), "explicit true or false 'enabled'"),
        (lambda r: r.update(enabled="yes"), "explicit true or false 'enabled'"),
        (lambda r: r.update(name="soc-manifest"), "reserved"),
    ],
)
def test_a_rule_that_cannot_be_deployed_safely_is_refused(
    tmp_path: Path, mutate: Any, expected: str
) -> None:
    rule = org_rule("T - One")
    mutate(rule)
    write_rules(tmp_path, rule)
    code, lines, _ = deploy(make_cfg(tmp_path), FakeBackend())
    assert code == rd.REFUSED
    assert any(expected in x for x in lines)


def test_only_the_configured_orgs_rules_are_deployed(tmp_path: Path) -> None:
    root = write_rules(tmp_path, org_rule("T - Mine"))
    put(root, org_rule("T - Theirs", org="other"), "orgs/other/theirs.json")
    backend = FakeBackend()
    deploy(make_cfg(tmp_path), backend)
    assert "T - Mine" in backend.live and "T - Theirs" not in backend.live


def test_the_keys_are_never_printed(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    backend = FakeBackend({"T - Old": live_rule("T - Old")})
    _, lines, _ = deploy(make_cfg(tmp_path), backend)
    text = "\n".join(lines) + repr(make_cfg(tmp_path))
    assert LC_KEY not in text and STAMP_KEY not in text


def test_the_record_is_one_line_in_the_out_folder_and_on_the_screen(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    cfg = make_cfg(tmp_path)
    _, lines, _ = deploy(cfg, FakeBackend())
    record = (cfg.out_dir / "record.txt").read_text().strip()
    assert "\n" not in record and record == lines[-1]
    assert record == (
        f"rules-deploy 2026-11-18T09:30:00Z org=aaaaaaaa commit={COMMIT[:12]} "
        "added=1 changed=0 removed=0 unchanged=0 unmanaged=0 result=applied"
    )


def test_a_record_that_cannot_be_written_does_not_hide_the_result(tmp_path: Path) -> None:
    write_rules(tmp_path, org_rule("T - One"))
    cfg = make_cfg(tmp_path, out_dir=tmp_path / "missing")
    code, lines, _ = deploy(cfg, FakeBackend())
    assert code == rd.OK
    assert any("could not write the record file" in x for x in lines)
    assert "result=applied" in lines[-1]


# ---- settings ----

GOOD_ENV = {
    "SOC_RULES_LC_KEY": LC_KEY,
    "SOC_RULES_LC_OID": OID,
    "SOC_RULES_STAMP_KEY": STAMP_KEY,
    "SOC_RULES_COMMIT": COMMIT,
    "SOC_RULES_ORG": "acme",
    "SOC_RULES_PREFIXES": "T - ",
}


def test_the_folders_have_defaults_but_the_org_and_prefixes_never_do() -> None:
    cfg = rd.Config.from_env(GOOD_ENV)
    assert cfg.org == "acme" and cfg.prefixes == ("T - ",)
    assert cfg.rules_dir == Path("/rules") and cfg.out_dir == Path("/out")


def test_settings_accept_several_prefixes() -> None:
    cfg = rd.Config.from_env({**GOOD_ENV, "SOC_RULES_PREFIXES": "T - |BASE - "})
    assert cfg.prefixes == ("T - ", "BASE - ")


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("SOC_RULES_LC_KEY", "short"),
        ("SOC_RULES_LC_OID", "not-a-uuid"),
        ("SOC_RULES_STAMP_KEY", "x" * 31),
        ("SOC_RULES_STAMP_KEY", "has a space " + "x" * 40),
        ("SOC_RULES_COMMIT", "main"),
        ("SOC_RULES_COMMIT", COMMIT[:39]),
        ("SOC_RULES_ORG", "Not Valid"),
        ("SOC_RULES_PREFIXES", "a|"),
        ("SOC_RULES_PREFIXES", "T - |"),
        ("SOC_RULES_PREFIXES", 'T - "x'),
        ("SOC_RULES_STAMP_KEY", "x" * 31 + "$"),
        ("SOC_RULES_STAMP_KEY", "x" * 40 + "#"),
    ],
)
def test_a_bad_setting_is_refused_by_name_and_never_by_value(name: str, bad: str) -> None:
    with pytest.raises(rd.ConfigError) as err:
        rd.Config.from_env({**GOOD_ENV, name: bad})
    assert name in str(err.value) and bad not in str(err.value)


@pytest.mark.parametrize("name", sorted(GOOD_ENV))
def test_a_missing_setting_is_refused(name: str) -> None:
    env = {k: v for k, v in GOOD_ENV.items() if k != name}
    with pytest.raises(rd.ConfigError, match=name):
        rd.Config.from_env(env)


def test_main_refuses_without_settings(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in GOOD_ENV:
        monkeypatch.delenv(name, raising=False)
    assert rd.main() == rd.REFUSED
    assert "refused" in capsys.readouterr().out


# ---- the wire: what the real client sends ----


class FakeLc:
    TOKEN = "header.payload.signature"  # noqa: S105 - a fake, for a fake server

    def __init__(self) -> None:
        self.log: list[dict[str, Any]] = []
        self.statuses: deque[int] = deque()  # answers for the next hive calls, before the real one
        self.rules: dict[str, Any] = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _read_form(self) -> dict[str, str]:
                raw = self.rfile.read(int(self.headers.get("content-length") or 0))
                return dict(urllib.parse.parse_qsl(raw.decode()))

            def _reply(self, status: int, body: bytes = b"{}") -> None:
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _hive(self, method: str) -> None:
                form = self._read_form()
                outer.log.append(
                    {
                        "method": method,
                        "path": urllib.parse.unquote(self.path),
                        "form": form,
                        "type": self.headers.get("Content-Type"),
                        "auth": self.headers.get("Authorization"),
                    }
                )
                if outer.statuses:
                    return self._reply(outer.statuses.popleft())
                if self.headers.get("Authorization") != f"Bearer {outer.TOKEN}":
                    return self._reply(401)
                if method == "GET":
                    return self._reply(200, json.dumps(outer.rules).encode())
                self._reply(200)

            def do_POST(self) -> None:
                if self.path == "/jwt":
                    self._read_form()
                    return self._reply(200, json.dumps({"jwt": outer.TOKEN}).encode())
                self._hive("POST")

            def do_GET(self) -> None:
                self._hive("GET")

            def do_DELETE(self) -> None:
                self._hive("DELETE")

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def hive_calls(self) -> list[dict[str, Any]]:
        return [x for x in self.log if x["path"].startswith("/v1/hive/")]


@pytest.fixture
def lc() -> Iterator[FakeLc]:
    fake = FakeLc()
    yield fake
    fake.server.shutdown()
    fake.server.server_close()


def real_client(fake: FakeLc) -> rd.RulesClient:
    return rd.RulesClient(
        OID, LC_KEY, api_url=fake.url, jwt_url=fake.url + "/jwt", allow_http=True, timeout=3.0
    )


def test_a_rule_with_null_tags_is_read_as_no_tags(lc: FakeLc) -> None:
    # The shape the platform really sends for every rule (seen on the live org, 2026-11-23).
    lc.rules = {
        "Rule A": {
            "data": {"detect": {"op": "exists"}, "respond": []},
            "usr_mtd": {
                "comment": "",
                "enabled": True,
                "expiry": 0,
                "tags": None,
                "ui_actions": None,
            },
            "sys_mtd": {"etag": "abc"},
        }
    }
    got = real_client(lc).list_rules()["Rule A"]
    assert got.tags == [] and got.enabled is True and got.etag == "abc"


def test_the_client_reads_rules_with_their_bodies_tags_and_etags(lc: FakeLc) -> None:
    lc.rules = {
        "Rule A": {
            "data": {"detect": {"op": "exists"}, "respond": [{"action": "report"}]},
            "usr_mtd": {"enabled": False, "tags": ["x"], "comment": "c"},
            "sys_mtd": {"etag": "abc"},
        },
        "Rule B": {"data": {}, "usr_mtd": None},
    }
    got = real_client(lc).list_rules()
    a = got["Rule A"]
    assert (a.detect, a.respond, a.enabled, a.tags, a.etag) == (
        {"op": "exists"},
        [{"action": "report"}],
        False,
        ["x"],
        "abc",
    )
    assert got["Rule B"].enabled is True and got["Rule B"].etag is None  # absent means enabled
    assert lc.hive_calls()[0]["path"] == f"/v1/hive/dr-general/{OID}"


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"R": "not an object"},
        {"R": {"data": []}},
        {"R": {"data": {}, "usr_mtd": {"enabled": "yes"}}},
        {"R": {"data": {}, "usr_mtd": {"tags": "x"}}},
        {"R": {"data": {}, "usr_mtd": {"tags": [1]}}},
        {"R": {"data": {}, "usr_mtd": {"tags": ""}}},  # only null means no tags
        {"R": {"data": {}, "usr_mtd": {"tags": False}}},
    ],
)
def test_the_client_refuses_shapes_it_does_not_know(lc: FakeLc, body: Any) -> None:
    lc.rules = body
    with pytest.raises(LcError) as err:
        real_client(lc).list_rules()
    assert err.value.code == "bad_shape"


def test_setting_a_rule_posts_form_data_to_the_data_path_with_the_whole_metadata(
    lc: FakeLc,
) -> None:
    real_client(lc).set_rule(
        "T - Rule/with slash",
        {"detect": {"op": "exists"}, "respond": []},
        {"enabled": False, "tags": ["git:abc"], "comment": "git 0123"},
        "etag-9",
    )
    call = lc.hive_calls()[0]
    assert call["method"] == "POST"
    assert call["path"] == f"/v1/hive/dr-general/{OID}/T - Rule/with slash/data"
    assert call["type"] == "application/x-www-form-urlencoded"
    assert json.loads(call["form"]["data"]) == {"detect": {"op": "exists"}, "respond": []}
    assert json.loads(call["form"]["usr_mtd"]) == {
        "enabled": False,
        "tags": ["git:abc"],
        "comment": "git 0123",
    }
    assert call["form"]["etag"] == "etag-9"


def test_a_new_rule_is_sent_without_an_etag(lc: FakeLc) -> None:
    real_client(lc).set_rule("R", {"detect": {}, "respond": []}, {"enabled": True}, None)
    assert "etag" not in lc.hive_calls()[0]["form"]


def test_a_name_is_percent_encoded_on_the_wire(lc: FakeLc) -> None:
    real_client(lc).delete_rule("T - A?b#c")
    raw = [x for x in lc.log if x["method"] == "DELETE"]
    assert raw[0]["path"] == f"/v1/hive/dr-general/{OID}/T - A?b#c"


def test_deleting_a_rule_sends_delete_to_its_path(lc: FakeLc) -> None:
    real_client(lc).delete_rule("T - Old")
    call = lc.hive_calls()[0]
    assert (call["method"], call["path"]) == ("DELETE", f"/v1/hive/dr-general/{OID}/T - Old")
    assert call["auth"] == f"Bearer {FakeLc.TOKEN}"


def test_an_expired_token_is_renewed_once_and_the_write_retried(lc: FakeLc) -> None:
    lc.statuses.append(401)
    real_client(lc).delete_rule("T - Old")
    assert [c["method"] for c in lc.hive_calls()] == ["DELETE", "DELETE"]


@pytest.mark.parametrize(
    ("status", "code"), [(403, "http_403"), (404, "http_404"), (500, "http_5xx")]
)
def test_a_refused_write_is_a_short_code_never_a_body(lc: FakeLc, status: int, code: str) -> None:
    lc.statuses.append(status)
    with pytest.raises(LcError) as err:
        real_client(lc).set_rule("R", {"detect": {}, "respond": []}, {"enabled": True}, None)
    assert err.value.code == code


def test_the_whole_deploy_runs_against_the_real_client(tmp_path: Path, lc: FakeLc) -> None:
    """End to end over HTTP: nothing but the `yes` is faked."""
    write_rules(tmp_path, org_rule("T - One"))
    code = rd.run(
        make_cfg(tmp_path), real_client(lc), lambda _p: True, lambda _l: None, lambda: NOW
    )
    assert code == rd.OK
    methods = [
        (c["method"], c["path"].rsplit("/", 2)[-2]) for c in lc.hive_calls() if c["method"] != "GET"
    ]
    assert methods == [("POST", "T - One"), ("POST", "soc-manifest")]


def test_the_line_diff_marks_changes_and_folds_long_unchanged_runs() -> None:
    old = ["a", "b", "c", "d", "e", "f", "g", "OLD", "h"]
    new = ["a", "b", "c", "d", "e", "f", "g", "NEW", "h"]
    assert rd._line_diff(old, new) == [" a", " b", " ...", " f", " g", "-OLD", "+NEW", " h"]
    assert rd._line_diff(["x"], ["x"]) == [" x"]
    assert rd._line_diff([], ["x"]) == ["+x"]
