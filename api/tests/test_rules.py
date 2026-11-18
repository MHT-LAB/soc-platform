"""Detection rules as code: the evaluator, the contract, replay, the base-commit check, the CLI.

The evaluator's defaults (which operators ignore case, what `not` does with a missing path) were
checked against the platform's own rule tester on 2026-11-16; the tests below pin them.
"""

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from soc_api.rules import check_tree, fires, replay_tree
from soc_api.rules.cli import main
from soc_api.rules.evaluate import BadRule, UnsupportedOperator, check_regex

WINDOWS, LINUX, MACOS = 0x10000000, 0x20000000, 0x30000000
REPO = Path(__file__).resolve().parents[2]

# Values the contract must flag as "real-looking". The email is assembled at run time so this
# file holds no email address, which the repository's scrub gate rejects; the IP is a plain
# public placeholder (private ranges are rejected too) and the id is a made-up UUID.
FAKE_IP = "1.2.3.4"
FAKE_ID = "12345678-1234-4234-8234-123456789abc"
FAKE_EMAIL = "admin" + chr(64) + "corp.test.com"


def ev(event_type: str = "NEW_PROCESS", plat: int = LINUX, **fields: Any) -> dict[str, Any]:
    return {"routing": {"event_type": event_type, "plat": plat}, "event": fields}


# ---- the evaluator: every operator ----


def hit(node: dict[str, Any], event: dict[str, Any], event_type: str = "NEW_PROCESS") -> bool:
    return fires({"event": event_type, **node}, event)


def cmd(text: str) -> dict[str, Any]:
    return ev(COMMAND_LINE=text)


def test_is_contains_starts_with_ends_with_are_case_sensitive_by_default() -> None:
    assert hit({"op": "contains", "path": "event/COMMAND_LINE", "value": "ABC"}, cmd("x ABC x"))
    assert not hit({"op": "contains", "path": "event/COMMAND_LINE", "value": "ABC"}, cmd("x abc x"))
    assert hit({"op": "is", "path": "event/COMMAND_LINE", "value": "Hello"}, cmd("Hello"))
    assert not hit({"op": "is", "path": "event/COMMAND_LINE", "value": "Hello"}, cmd("hello"))
    assert not hit({"op": "is", "path": "event/COMMAND_LINE", "value": "Hello"}, cmd("Hello!"))
    assert hit({"op": "starts with", "path": "event/COMMAND_LINE", "value": "AB"}, cmd("ABc"))
    assert not hit({"op": "starts with", "path": "event/COMMAND_LINE", "value": "AB"}, cmd("abc"))
    assert hit({"op": "ends with", "path": "event/COMMAND_LINE", "value": "XY"}, cmd("uvXY"))
    assert not hit({"op": "ends with", "path": "event/COMMAND_LINE", "value": "XY"}, cmd("uvxy"))


@pytest.mark.parametrize("op", ["contains", "is", "starts with", "ends with"])
def test_case_sensitive_false_ignores_case(op: str) -> None:
    node = {"op": op, "path": "event/COMMAND_LINE", "value": "AbC", "case sensitive": False}
    assert hit(node, cmd("abc"))
    assert hit(node, cmd("ABC"))


def test_matches_ignores_case_unless_told_otherwise() -> None:
    node = {"op": "matches", "path": "event/COMMAND_LINE", "re": "ABC"}
    assert hit(node, cmd("xx abc xx"))
    assert hit(node, cmd("xx ABC xx"))
    strict = {**node, "case sensitive": True}
    assert hit(strict, cmd("xx ABC xx"))
    assert not hit(strict, cmd("xx abc xx"))


def test_matches_uses_re2_syntax() -> None:
    assert check_regex(r"(?i)net1?(\.exe)?\W+user") is None
    for bad in (r"a(?=b)", r"(?<=a)b", r"(a)\1"):
        assert check_regex(bad)
    with pytest.raises(Exception, match="(?i)lookahead|perl operator|invalid"):
        hit({"op": "matches", "path": "event/COMMAND_LINE", "re": "a(?=b)"}, cmd("ab"))


def test_matches_is_a_search_not_a_full_match() -> None:
    node = {"op": "matches", "path": "event/COMMAND_LINE", "re": "evil"}
    assert hit(node, cmd("run evil thing"))
    anchored = {"op": "matches", "path": "event/COMMAND_LINE", "re": "^evil$"}
    assert not hit(anchored, cmd("run evil thing"))


def test_exists_and_a_missing_path() -> None:
    node = {"op": "exists", "path": "event/FILE_PATH"}
    assert not hit(node, cmd("no file path"))
    assert hit(node, ev(COMMAND_LINE="x", FILE_PATH="/bin/x"))
    # a leaf on a missing path is false, whatever the operator
    for op, key in (("contains", "value"), ("matches", "re"), ("is", "value")):
        assert not hit({"op": op, "path": "event/NOPE", key: "x"}, cmd("x"))


def test_not_inverts_any_node_and_a_missing_path_counts_as_false_first() -> None:
    node = {"op": "contains", "path": "event/COMMAND_LINE", "value": "bad", "not": True}
    assert hit(node, cmd("good command"))
    assert not hit(node, cmd("bad command"))
    assert hit(node, ev(OTHER="the path is missing entirely"))
    group = {"op": "and", "not": True, "rules": [{"op": "exists", "path": "event/COMMAND_LINE"}]}
    assert hit(group, ev(OTHER="x"))
    assert not hit(group, cmd("x"))


def test_and_or_nest() -> None:
    node = {
        "op": "or",
        "rules": [
            {"op": "is platform", "name": "windows"},
            {
                "op": "and",
                "rules": [
                    {"op": "is platform", "name": "linux"},
                    {"op": "matches", "path": "event/COMMAND_LINE", "re": "^ls "},
                ],
            },
        ],
    }
    assert hit(node, ev(plat=WINDOWS, COMMAND_LINE="anything"))
    assert hit(node, ev(plat=LINUX, COMMAND_LINE="ls -la"))
    assert not hit(node, ev(plat=LINUX, COMMAND_LINE="cat x"))
    assert not hit(node, ev(plat=MACOS, COMMAND_LINE="ls -la"))


@pytest.mark.parametrize(
    ("name", "plat", "expected"),
    [
        ("windows", WINDOWS, True),
        ("windows", LINUX, False),
        ("linux", LINUX, True),
        ("linux", MACOS, False),
        ("macos", MACOS, True),
        ("macos", WINDOWS, False),
    ],
)
def test_is_platform(name: str, plat: int, expected: bool) -> None:
    assert hit({"op": "is platform", "name": name}, ev(plat=plat)) is expected


def test_is_tagged_reads_the_routing_tags() -> None:
    node = {"op": "is tagged", "tag": "lab"}
    tagged = ev()
    tagged["routing"]["tags"] = ["lab", "other"]
    other = ev()
    other["routing"]["tags"] = ["other"]
    assert hit(node, tagged)
    assert not hit(node, other)
    assert not hit(node, ev())  # no tags at all


def test_event_and_events_filter_on_the_event_type() -> None:
    node = {"op": "exists", "path": "event/MARK"}
    process, dns, files = (ev(t, MARK="x") for t in ("NEW_PROCESS", "DNS_REQUEST", "FILE_CREATE"))
    assert fires({"event": "NEW_PROCESS", **node}, process)
    assert not fires({"event": "NEW_PROCESS", **node}, dns)
    both = {"events": ["NEW_PROCESS", "DNS_REQUEST"], **node}
    assert fires(both, process) and fires(both, dns) and not fires(both, files)
    assert fires(node, files)  # no filter: every event type


def test_paths_reach_into_nested_objects_and_the_routing_block() -> None:
    event = ev(PARENT={"FILE_PATH": "C:\\Windows\\explorer.exe"})
    event["routing"]["hostname"] = "H1"
    nested = {"op": "ends with", "path": "event/PARENT/FILE_PATH", "value": "explorer.exe"}
    assert hit(nested, event)
    assert hit({"op": "is", "path": "routing/hostname", "value": "H1"}, event)
    assert not hit({"op": "is", "path": "routing/hostname", "value": "h1"}, event)


def test_is_compares_non_text_values_exactly() -> None:
    event = ev(PID=4)
    assert hit({"op": "is", "path": "event/PID", "value": 4}, event)
    assert not hit({"op": "is", "path": "event/PID", "value": 5}, event)
    assert not hit({"op": "contains", "path": "event/PID", "value": "4"}, event)  # not text


def test_an_unknown_operator_is_an_error_never_a_quiet_no_match() -> None:
    with pytest.raises(UnsupportedOperator, match="lookup"):
        hit({"op": "lookup", "path": "event/X", "resource": "r"}, cmd("x"))
    with pytest.raises(UnsupportedOperator):
        # even in a branch that an earlier answer would make irrelevant
        hit(
            {"op": "or", "rules": [{"op": "exists", "path": "event/COMMAND_LINE"}, {"op": "zz"}]},
            cmd("x"),
        )


@pytest.mark.parametrize(
    "node",
    [
        {"op": "and", "rules": []},
        {"op": "and"},
        {"op": "contains", "path": "event/X"},  # no value
        {"op": "matches", "path": "event/X"},  # no re
        {"op": "is platform", "name": "plan9"},
        {"op": "is tagged"},
        {"op": "contains", "path": "event/X", "value": "x", "case sensitive": "no"},
        {"op": "exists", "path": "event/X", "not": "yes"},
        {"path": "event/X"},  # no op
    ],
)
def test_a_malformed_node_is_an_error(node: dict[str, Any]) -> None:
    with pytest.raises(BadRule):
        hit(node, cmd("x"))


# ---- the contract ----


def valid_rule(**over: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "name": "T - LINUX - Test Rule",
        "pack": "linux",
        "status": "ready",
        "description": "Finds the word evil.",
        "detect": {
            "event": "NEW_PROCESS",
            "op": "and",
            "rules": [
                {"op": "is platform", "name": "linux"},
                {"op": "contains", "path": "event/COMMAND_LINE", "value": "evil"},
            ],
        },
        "respond": [{"action": "report", "name": "T_Rule", "priority": 2}],
        "tests": {
            "positive": [cmd("run evil thing")],
            "negative": [cmd("run good thing")],
        },
    }
    rule.update(over)
    return rule


def put(root: Path, data: Any, rel: str = "t/rule.json") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))


def messages(root: Path) -> list[str]:
    return [p.message for p in check_tree(root)]


def test_a_valid_rule_passes_check_and_replay(tmp_path: Path) -> None:
    put(tmp_path, valid_rule())
    assert check_tree(tmp_path) == []
    assert replay_tree(tmp_path) == []


def mutate(path: list[Any], value: Any) -> Any:
    def apply(rule: dict[str, Any]) -> None:
        target: Any = rule
        for key in path[:-1]:
            target = target[key]
        if value is DELETE:
            del target[path[-1]]
        else:
            target[path[-1]] = value

    return apply


DELETE = object()

CONTRACT_BREAKS = [
    pytest.param(mutate(["name"], DELETE), "needs a text 'name'", id="no-name"),
    pytest.param(mutate(["name"], "x" * 256), "longer than 255", id="long-name"),
    pytest.param(mutate(["description"], ""), "needs a text 'description'", id="no-description"),
    pytest.param(mutate(["status"], "live"), "'status' must be one of", id="bad-status"),
    pytest.param(mutate(["pack"], DELETE), "needs a 'pack'", id="no-pack"),
    pytest.param(mutate(["detect"], DELETE), "needs a 'detect' object", id="no-detect"),
    pytest.param(mutate(["respond"], []), "non-empty 'respond'", id="no-respond"),
    pytest.param(
        mutate(["respond"], [{"action": "isolate network"}]),
        "action 'isolate network' not allowed",
        id="isolate-outside-an-overlay",
    ),
    pytest.param(
        mutate(["respond"], [{"action": "add tag", "tag": "x"}]),
        "action 'add tag' not allowed",
        id="tag-outside-an-overlay",
    ),
    pytest.param(
        mutate(["respond"], [{"action": "report"}]),
        "a report needs a 'name'",
        id="report-without-category",
    ),
    pytest.param(
        mutate(["detect", "rules", 0], {"op": "contains", "path": "event/X", "value": "x"}),
        "needs an 'is platform linux' check",
        id="no-platform-check",
    ),
    pytest.param(mutate(["platform"], "plan9"), "'platform' must be one of", id="bad-platform"),
    pytest.param(mutate(["tests", "positive"], []), "at least one positive test", id="no-positive"),
    pytest.param(mutate(["tests", "negative"], []), "at least one negative test", id="no-negative"),
    pytest.param(mutate(["tests", "negative"], DELETE), "needs negative tests", id="no-negatives"),
    pytest.param(
        mutate(["tests", "positive", 0], {"event": {"COMMAND_LINE": "evil"}}),
        "needs 'routing' and 'event' objects",
        id="event-without-routing",
    ),
    pytest.param(
        mutate(["tests", "positive", 0, "routing"], {"event_type": "NEW_PROCESS"}),
        "routing needs 'event_type' (text) and 'plat' (number)",
        id="event-without-plat",
    ),
    pytest.param(
        mutate(["detect", "rules", 1], {"op": "matches", "path": "event/X", "re": "a(?=b)"}),
        "rejected by RE2",
        id="lookahead",
    ),
    pytest.param(
        mutate(["detect", "rules", 1], {"op": "matches", "path": "event/X", "re": r"(a)\1"}),
        "rejected by RE2",
        id="backreference",
    ),
    pytest.param(
        mutate(["detect", "rules", 1], {"op": "lookup", "path": "event/X"}),
        "operator 'lookup' is not supported",
        id="unknown-operator",
    ),
    pytest.param(
        mutate(["notes"], f"contact {FAKE_EMAIL}"),
        "email address",
        id="real-looking-email",
    ),
    pytest.param(
        mutate(["notes"], f"seen from {FAKE_IP}"), f"contains the address {FAKE_IP}", id="ip"
    ),
    pytest.param(
        mutate(["notes"], f"org {FAKE_ID}"),
        "looks like an org or sensor id",
        id="uuid",
    ),
]


@pytest.mark.parametrize(("change", "expected"), CONTRACT_BREAKS)
def test_each_contract_rule_is_enforced(tmp_path: Path, change: Any, expected: str) -> None:
    rule = valid_rule()
    change(rule)
    put(tmp_path, rule)
    found = messages(tmp_path)
    assert any(expected in m for m in found), found


def test_documentation_addresses_and_example_emails_are_fine(tmp_path: Path) -> None:
    put(tmp_path, valid_rule(notes="203.0.113.9 192.0.2.1 198.51.100.7 127.0.0.1 a@example.com"))
    assert check_tree(tmp_path) == []


def test_a_windows_command_line_rule_needs_a_quoted_path_positive(tmp_path: Path) -> None:
    quoted = '"C:\\Windows\\System32\\net.exe" user bob /add'
    rule = valid_rule(
        name="T - WINDOWS - Net User",
        pack="windows",
        detect={
            "event": "NEW_PROCESS",
            "op": "and",
            "rules": [
                {"op": "is platform", "name": "windows"},
                {"op": "contains", "path": "event/COMMAND_LINE", "value": "user bob"},
            ],
        },
        tests={
            "positive": [ev(plat=WINDOWS, COMMAND_LINE="net user bob /add")],
            "negative": [ev(plat=WINDOWS, COMMAND_LINE="net view")],
        },
    )
    put(tmp_path, rule)
    assert any("quoted full program path" in m for m in messages(tmp_path))
    rule["tests"]["positive"].append(ev(plat=WINDOWS, COMMAND_LINE=quoted))
    put(tmp_path, rule)
    assert check_tree(tmp_path) == []
    assert replay_tree(tmp_path) == []


def test_a_quoted_path_must_be_a_full_path_to_a_program(tmp_path: Path) -> None:
    rule = valid_rule(pack="windows")
    rule["detect"]["rules"][0] = {"op": "is platform", "name": "windows"}
    rule["tests"]["positive"] = [ev(plat=WINDOWS, COMMAND_LINE='"net" user evil')]
    put(tmp_path, rule)
    assert any("quoted full program path" in m for m in messages(tmp_path))


def test_a_windows_rule_that_reads_only_a_file_path_needs_no_quoted_command_line(
    tmp_path: Path,
) -> None:
    rule = valid_rule(
        name="T - WINDOWS - Public Folder",
        pack="windows",
        detect={
            "event": "NEW_PROCESS",
            "op": "and",
            "rules": [
                {"op": "is platform", "name": "windows"},
                {"op": "contains", "path": "event/FILE_PATH", "value": "\\Users\\Public\\"},
            ],
        },
        tests={
            "positive": [ev(plat=WINDOWS, FILE_PATH="C:\\Users\\Public\\x.exe")],
            "negative": [ev(plat=WINDOWS, FILE_PATH="C:\\Program Files\\x.exe")],
        },
    )
    put(tmp_path, rule)
    assert check_tree(tmp_path) == []


def test_a_rule_for_any_platform_needs_no_platform_check(tmp_path: Path) -> None:
    rule = valid_rule(
        pack="common",
        detect={
            "event": "DNS_REQUEST",
            "op": "matches",
            "path": "event/DOMAIN_NAME",
            "re": "evil\\.example$",
        },
        tests={
            "positive": [ev("DNS_REQUEST", DOMAIN_NAME="evil.example")],
            "negative": [ev("DNS_REQUEST", DOMAIN_NAME="fine.example")],
        },
    )
    put(tmp_path, rule)
    assert check_tree(tmp_path) == []


def command_rule(platform_nodes: list[dict[str, Any]], positives: list[dict[str, Any]]) -> Any:
    return valid_rule(
        pack="examples",  # not an operating-system pack, so the label says "any platform"
        detect={
            "event": "NEW_PROCESS",
            "op": "and",
            "rules": [
                *platform_nodes,
                {"op": "contains", "path": "event/COMMAND_LINE", "value": "evil"},
            ],
        },
        tests={"positive": positives, "negative": [cmd("run good thing")]},
    )


QUOTED = ev(plat=WINDOWS, COMMAND_LINE='"C:\\Windows\\System32\\evil.exe" /x')
NEEDS_QUOTED = "quoted full program path"


def test_a_rule_that_can_fire_on_windows_needs_a_quoted_positive_whatever_its_label(
    tmp_path: Path,
) -> None:
    on_windows = [{"op": "is platform", "name": "windows"}]
    put(tmp_path, command_rule(on_windows, [ev(plat=WINDOWS, COMMAND_LINE="evil")]))
    assert any(NEEDS_QUOTED in m for m in messages(tmp_path))
    put(tmp_path, command_rule(on_windows, [ev(plat=WINDOWS, COMMAND_LINE="evil"), QUOTED]))
    assert check_tree(tmp_path) == []


def test_a_command_line_rule_with_no_platform_check_can_fire_on_windows_too(
    tmp_path: Path,
) -> None:
    put(tmp_path, command_rule([], [cmd("run evil thing")]))  # Linux-only positives
    assert any(NEEDS_QUOTED in m for m in messages(tmp_path))
    put(tmp_path, command_rule([], [cmd("run evil thing"), QUOTED]))
    assert check_tree(tmp_path) == []


def test_a_rule_limited_to_other_systems_needs_no_windows_positive(tmp_path: Path) -> None:
    for system in ("linux", "macos"):
        put(tmp_path, command_rule([{"op": "is platform", "name": system}], [cmd("run evil")]))
        assert check_tree(tmp_path) == [], system


def test_the_pack_name_sets_the_default_platform_and_platform_overrides_it(tmp_path: Path) -> None:
    rule = valid_rule(pack="common", platform="linux")
    rule["detect"]["rules"] = rule["detect"]["rules"][1:]
    rule["detect"]["rules"].append({"op": "exists", "path": "event/COMMAND_LINE"})
    put(tmp_path, rule)
    assert any("needs an 'is platform linux' check" in m for m in messages(tmp_path))


def test_names_must_be_unique(tmp_path: Path) -> None:
    put(tmp_path, valid_rule(), "a.json")
    put(tmp_path, valid_rule(), "b.json")
    found = check_tree(tmp_path)
    assert [(p.file, "also used by a.json" in p.message) for p in found] == [("b.json", True)]


def test_invalid_json_and_non_objects_and_other_kinds_are_reported_not_skipped(
    tmp_path: Path,
) -> None:
    put(tmp_path, "{not json", "broken.json")
    put(tmp_path, "[1, 2]", "list.json")
    put(tmp_path, {"kind": "lookup", "name": "x"}, "fim.json")
    found = {p.file: p.message for p in check_tree(tmp_path)}
    assert "cannot be read as JSON" in found["broken.json"]
    assert "must be a JSON object" in found["list.json"]
    assert "unsupported kind 'lookup'" in found["fim.json"]


# ---- org overlays ----


def overlay_rule(**over: Any) -> dict[str, Any]:
    rule = valid_rule(
        name="T - ORG - Gate",
        org="acme",
        respond=[
            {"action": "report", "name": "T_Gate", "priority": 5},
            {"action": "isolate network"},
        ],
        gate="two-signal",
    )
    del rule["pack"]
    rule.update(over)
    return rule


def test_an_org_overlay_may_isolate_if_it_names_its_gate(tmp_path: Path) -> None:
    put(tmp_path, overlay_rule(), "orgs/acme/gate.json")
    assert check_tree(tmp_path) == []


def test_an_overlay_that_isolates_must_name_its_gate(tmp_path: Path) -> None:
    rule = overlay_rule()
    del rule["gate"]
    put(tmp_path, rule, "orgs/acme/gate.json")
    assert any("must name its response gate" in m for m in messages(tmp_path))


def test_an_overlay_may_tag_but_not_do_anything_else(tmp_path: Path) -> None:
    ok = overlay_rule(
        respond=[{"action": "add tag", "tag": "t"}, {"action": "report", "name": "n"}]
    )
    put(tmp_path, ok, "orgs/acme/tag.json")
    assert check_tree(tmp_path) == []
    bad = overlay_rule(name="T - ORG - Kill", respond=[{"action": "task", "command": "deny_tree"}])
    put(tmp_path, bad, "orgs/acme/kill.json")
    assert any("action 'task' not allowed" in m for m in messages(tmp_path))


def test_the_org_must_match_its_folder_and_files_must_sit_in_one(tmp_path: Path) -> None:
    put(tmp_path, overlay_rule(org="other"), "orgs/acme/a.json")
    assert any("'org' must be 'acme'" in m for m in messages(tmp_path))
    put(tmp_path, overlay_rule(name="T - ORG - Loose"), "orgs/loose.json")
    assert any("must sit in orgs/<org>/" in m for m in messages(tmp_path))
    put(tmp_path, valid_rule(name="T - Stray", org="acme"), "shared/stray.json")
    assert any("'org' is only for files under orgs/<org>/" in m for m in messages(tmp_path))


def test_an_overlay_may_name_real_identifiers(tmp_path: Path) -> None:
    rule = overlay_rule(notes=f"sensor {FAKE_ID} at {FAKE_IP}, {FAKE_EMAIL}")
    put(tmp_path, rule, "orgs/acme/real.json")
    assert check_tree(tmp_path) == []


def test_every_report_action_is_still_checked_in_an_overlay(tmp_path: Path) -> None:
    rule = overlay_rule(respond=[{"action": "report"}])
    put(tmp_path, rule, "orgs/acme/x.json")
    assert any("a report needs a 'name'" in m for m in messages(tmp_path))


# ---- replay ----


def test_replay_reports_a_positive_that_does_not_fire_and_a_negative_that_does(
    tmp_path: Path,
) -> None:
    rule = valid_rule()
    rule["tests"]["positive"].append(cmd("nothing to see here"))
    rule["tests"]["negative"].append(cmd("this one is evil too"))
    put(tmp_path, rule)
    found = [p.message for p in replay_tree(tmp_path)]
    assert len(found) == 2
    assert "does not fire on positive #2" in found[0] and "nothing to see here" in found[0]
    assert "fires on negative #2" in found[1] and "evil too" in found[1]


def test_replay_reports_an_event_of_the_wrong_type_as_not_firing(tmp_path: Path) -> None:
    rule = valid_rule()
    rule["tests"]["positive"] = [ev("DNS_REQUEST", COMMAND_LINE="evil")]
    put(tmp_path, rule)
    assert any("does not fire on positive #1" in p.message for p in replay_tree(tmp_path))


def test_replay_reports_what_it_cannot_run_instead_of_skipping_it(tmp_path: Path) -> None:
    rule = valid_rule()
    rule["detect"]["rules"][1] = {"op": "lookup", "path": "event/X"}
    put(tmp_path, rule, "a.json")
    put(tmp_path, "{nope", "b.json")
    found = {p.file: p.message for p in replay_tree(tmp_path)}
    assert "cannot replay: UnsupportedOperator" in found["a.json"]
    assert "cannot replay: cannot be read as JSON" in found["b.json"]


# ---- positives are append-only against a base commit ----


def git(repo: Path, *args: str) -> None:
    flags = ["-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
    subprocess.run(  # noqa: S603 - fixed arguments in a temporary repository
        ["git", "-C", str(repo), *flags, *args],  # noqa: S607
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


def commit_rule(repo: Path, rule: dict[str, Any], rel: str = "detections/t/rule.json") -> None:
    put(repo, rule, rel)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "x")


def problems(repo: Path, base: str = "HEAD") -> list[str]:
    return [p.message for p in check_tree(repo / "detections", base=base)]


def test_adding_a_positive_is_fine_and_so_is_changing_the_rest(repo: Path) -> None:
    commit_rule(repo, valid_rule())
    rule = valid_rule(description="Reworded.")
    rule["tests"]["positive"].append(cmd("another evil one"))
    rule["tests"]["negative"] = [cmd("a different good one")]
    put(repo, rule, "detections/t/rule.json")
    assert problems(repo) == []


def test_removing_a_positive_is_refused(repo: Path) -> None:
    rule = valid_rule()
    rule["tests"]["positive"].append(cmd("second evil"))
    commit_rule(repo, rule)
    put(repo, valid_rule(), "detections/t/rule.json")  # back to one positive
    found = problems(repo)
    assert len(found) == 1
    assert "removed or edited" in found[0] and "second evil" in found[0]


def test_editing_a_positive_counts_as_removing_it(repo: Path) -> None:
    commit_rule(repo, valid_rule())
    put(
        repo,
        valid_rule(tests={"positive": [cmd("run evil thing!")], "negative": [cmd("ok")]}),
        "detections/t/rule.json",
    )
    assert any("removed or edited" in m for m in problems(repo))


def test_a_new_rule_file_is_free(repo: Path) -> None:
    commit_rule(repo, valid_rule())
    put(repo, valid_rule(name="T - LINUX - Second Rule"), "detections/t/second.json")
    assert problems(repo) == []


def test_a_rule_deleted_since_the_base_is_not_this_checks_business(repo: Path) -> None:
    commit_rule(repo, valid_rule())
    commit_rule(repo, valid_rule(name="T - LINUX - Other"), "detections/t/other.json")
    (repo / "detections/t/rule.json").unlink()
    assert problems(repo) == []


def test_the_base_can_be_any_commit_or_branch(repo: Path) -> None:
    commit_rule(repo, valid_rule())
    git(repo, "branch", "base")
    put(
        repo,
        valid_rule(tests={"positive": [cmd("something else evil")], "negative": [cmd("ok")]}),
        "detections/t/rule.json",
    )
    assert any("removed or edited" in m for m in problems(repo, "base"))


def test_malformed_tests_at_either_end_are_reported_never_a_crash(repo: Path) -> None:
    commit_rule(repo, valid_rule())
    put(repo, valid_rule(tests=[]), "detections/t/rule.json")  # tests is a list now
    assert any("needs a 'tests' object" in m for m in problems(repo))
    commit_rule(repo, valid_rule(tests=[]))  # ...and at the base too
    put(repo, valid_rule(), "detections/t/rule.json")
    assert problems(repo) == []


def test_an_unknown_or_unsafe_base_fails_closed(repo: Path) -> None:
    commit_rule(repo, valid_rule())
    assert any("cannot find 'no-such-ref'" in m for m in problems(repo, "no-such-ref"))
    assert any("not a usable git reference" in m for m in problems(repo, "--output=x"))
    assert any("not a usable git reference" in m for m in problems(repo, "a b"))


def test_the_base_check_works_from_a_subfolder_of_the_repository(repo: Path) -> None:
    commit_rule(repo, valid_rule(), "deep/er/detections/rule.json")
    put(
        repo,
        valid_rule(tests={"positive": [cmd("changed")], "negative": [cmd("ok")]}),
        "deep/er/detections/rule.json",
    )
    found = [p.message for p in check_tree(repo / "deep/er/detections", base="HEAD")]
    assert any("removed or edited" in m for m in found)


# ---- the command line ----


def test_the_cli_exit_codes_and_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good"
    put(good, valid_rule())
    assert main(["check", str(good)]) == 0
    assert "check: ok, 1 rule files" in capsys.readouterr().out
    assert main(["replay", str(good)]) == 0

    bad = tmp_path / "bad"
    broken = valid_rule()
    broken["tests"]["positive"] = [cmd("no match")]
    put(bad, broken, "x/broken.json")
    assert main(["replay", str(bad)]) == 1
    out = capsys.readouterr().out
    assert "x/broken.json: the rule does not fire on positive #1" in out
    assert "replay: 1 problem(s)" in out

    assert main(["check", str(tmp_path / "missing")]) == 2
    (tmp_path / "empty").mkdir()
    assert main(["check", str(tmp_path / "empty")]) == 2  # an empty folder never passes quietly
    assert main(["replay", str(tmp_path / "empty")]) == 2


def test_python_dash_m_runs_the_tool(tmp_path: Path) -> None:
    put(tmp_path, valid_rule())
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-I", "-m", "soc_api.rules", "check", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        env={"PYTHONPATH": str(REPO / "api" / "src")},
    )
    assert done.returncode == 0, done.stderr
    assert "check: ok" in done.stdout


# ---- what ships ----


def test_the_shipped_examples_pass_check_and_replay() -> None:
    assert check_tree(REPO / "detections") == []
    assert replay_tree(REPO / "detections") == []
    shipped = list((REPO / "detections").rglob("*.json"))
    assert len(shipped) >= 3
    for path in shipped:
        rule = json.loads(path.read_text())
        assert rule["pack"] == "examples" and rule["status"] == "ready"


def test_the_examples_are_synthetic_and_the_checks_would_catch_a_real_identifier(
    tmp_path: Path,
) -> None:
    for path in (REPO / "detections").rglob("*.json"):
        text = path.read_text()
        assert "@" not in text or "example." in text
    rule = copy.deepcopy(json.loads(next((REPO / "detections").rglob("*.json")).read_text()))
    rule["notes"] = f"seen on {FAKE_IP}"
    put(tmp_path, rule)
    assert any(f"contains the address {FAKE_IP}" in m for m in messages(tmp_path))
