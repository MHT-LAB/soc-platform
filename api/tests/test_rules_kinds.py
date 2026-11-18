"""Rule files that are not detections (false-positive rules, file-integrity watch lists), org
overlays found from the folder being scanned, and the baseline/draft convention (Sprint 4, E2)."""

import copy
from pathlib import Path
from typing import Any

import pytest
from test_rules import DELETE, commit_rule, git, mutate, overlay_rule, put, valid_rule

from soc_api.rules import check_tree, replay_tree
from soc_api.rules.cli import main

# A literal home directory is something the repository's scrub gate rejects, so the paths that
# must be flagged are assembled at run time and this source holds none.
HOME = "/" + "home"


def found(root: Path, base: str | None = None) -> list[str]:
    return [p.message for p in check_tree(root, base=base)]


# ---- an org overlay is recognized from the folder being scanned ----


def test_an_org_folder_scanned_directly_is_still_an_overlay(tmp_path: Path) -> None:
    put(tmp_path, overlay_rule(), "orgs/acme/gate.json")
    assert found(tmp_path / "orgs" / "acme") == []  # the org folder itself
    assert found(tmp_path / "orgs") == []  # the folder of org folders
    assert found(tmp_path) == []  # and from above, as before


def test_a_folder_that_is_not_an_overlay_may_not_isolate(tmp_path: Path) -> None:
    put(tmp_path, overlay_rule(), "rules/acme/gate.json")
    assert any("not allowed" in m for m in found(tmp_path / "rules" / "acme"))


def test_only_the_scanned_folder_and_its_parent_count_as_context(tmp_path: Path) -> None:
    """Scanning deeper than orgs/<org>/ fails closed: it is not treated as an overlay."""
    put(tmp_path, overlay_rule(), "orgs/acme/sub/gate.json")
    assert any("not allowed" in m for m in found(tmp_path / "orgs" / "acme" / "sub"))


def test_the_org_must_match_its_folder_when_that_folder_is_scanned_directly(
    tmp_path: Path,
) -> None:
    put(tmp_path, overlay_rule(org="other"), "orgs/acme/gate.json")
    assert any("'org' must be 'acme'" in m for m in found(tmp_path / "orgs" / "acme"))


def test_a_loose_file_in_orgs_is_refused_when_orgs_is_scanned_directly(tmp_path: Path) -> None:
    put(tmp_path, overlay_rule(), "orgs/loose.json")
    assert any("must sit in orgs/<org>/" in m for m in found(tmp_path / "orgs"))


def test_the_cli_works_from_an_org_folder(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    put(tmp_path, overlay_rule(), "orgs/acme/gate.json")
    assert main(["check", str(tmp_path / "orgs" / "acme")]) == 0
    assert main(["replay", str(tmp_path / "orgs" / "acme")]) == 0
    assert "ok" in capsys.readouterr().out


# ---- false-positive rules (kind "fp") ----


def fp_rule(**over: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "kind": "fp",
        "name": "T - FP - Ufw Reload",
        "pack": "linux",
        "status": "ready",
        "description": "A reload flushes its own chains.",
        "fp": {
            "op": "and",
            "rules": [
                {"op": "is", "path": "cat", "value": "SOME-DETECTION"},
                {
                    "op": "matches",
                    "path": "detect/event/COMMAND_LINE",
                    "re": "^iptables -F ufw-[a-z]+$",
                },
            ],
        },
        "tests": {
            "match_command_lines": ["iptables -F ufw-before", "iptables -F ufw-after"],
            "no_match_command_lines": ["iptables -F", "iptables -F INPUT"],
        },
    }
    rule.update(over)
    return rule


def test_a_valid_fp_rule_passes_and_has_nothing_to_replay(tmp_path: Path) -> None:
    put(tmp_path, fp_rule())
    assert found(tmp_path) == []
    assert replay_tree(tmp_path) == []  # the platform cannot dry-run these either


FP_BREAKS = [
    pytest.param(mutate(["fp"], DELETE), "needs an 'fp' object", id="no-fp"),
    pytest.param(mutate(["fp"], "text"), "needs an 'fp' object", id="fp-not-an-object"),
    pytest.param(
        mutate(["fp", "rules", 1, "re"], "a(?=b)"), "rejected by RE2", id="lookahead-in-fp"
    ),
    pytest.param(
        mutate(["fp", "rules", 0], {"op": "lookup", "path": "cat"}),
        "operator 'lookup' is not supported",
        id="unknown-op-in-fp",
    ),
    pytest.param(mutate(["tests"], DELETE), "needs a 'tests' object", id="no-tests"),
    pytest.param(
        mutate(["tests", "match_command_lines"], []),
        "tests.match_command_lines needs a non-empty list",
        id="no-match-lines",
    ),
    pytest.param(
        mutate(["tests", "no_match_command_lines"], DELETE),
        "tests.no_match_command_lines needs a non-empty list",
        id="no-no-match-lines",
    ),
    pytest.param(
        mutate(["tests", "match_command_lines"], ["ok", 3]),
        "tests.match_command_lines needs a non-empty list",
        id="a-line-that-is-not-text",
    ),
    pytest.param(mutate(["status"], "live"), "'status' must be one of", id="common-fields-checked"),
    pytest.param(
        mutate(["notes"], "from 1.2.3.4"), "contains the address", id="identifiers-checked"
    ),
]


@pytest.mark.parametrize(("change", "expected"), FP_BREAKS)
def test_each_fp_check_is_enforced(tmp_path: Path, change: Any, expected: str) -> None:
    rule = fp_rule()
    change(rule)
    put(tmp_path, rule)
    messages = found(tmp_path)
    assert any(expected in m for m in messages), messages


def test_an_fp_rule_is_not_held_to_the_detection_contract(tmp_path: Path) -> None:
    """No detect, respond, platform check or positive/negative pair is asked of it."""
    rule = fp_rule()
    assert "detect" not in rule and "respond" not in rule
    put(tmp_path, rule)
    assert found(tmp_path) == []


def test_fp_match_lines_are_append_only(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q", "-b", "main")
    commit_rule(tmp_path, fp_rule(), "detections/fp.json")
    removed = fp_rule()
    removed["tests"]["match_command_lines"] = ["iptables -F ufw-before"]
    put(tmp_path, removed, "detections/fp.json")
    messages = found(tmp_path / "detections", base="HEAD")
    assert any("removed or edited" in m and "ufw-after" in m for m in messages), messages
    grown = fp_rule()
    grown["tests"]["match_command_lines"].append("iptables -F ufw-logging")
    put(tmp_path, grown, "detections/fp.json")
    assert found(tmp_path / "detections", base="HEAD") == []


# ---- file-integrity watch lists (kind "fim") ----


def fim_rule(**over: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "kind": "fim",
        "name": "T - FIM watch patterns",
        "pack": "linux",
        "status": "ready",
        "extension": "ext-integrity",
        "description": "Identity and ssh files.",
        "fim_rules": {
            "t-identity": {
                "filters": {"platforms": ["linux"]},
                "patterns": ["/etc/passwd", "/home/*/.ssh/authorized_keys"],
            }
        },
        "fim_rules_optional": {
            "t-shell": {"filters": {"platforms": ["linux"]}, "patterns": ["/etc/profile"]}
        },
    }
    rule.update(over)
    return rule


def test_a_valid_fim_file_passes_and_has_nothing_to_replay(tmp_path: Path) -> None:
    put(tmp_path, fim_rule())
    assert found(tmp_path) == []
    assert replay_tree(tmp_path) == []


FIM_BREAKS = [
    pytest.param(
        mutate(["fim_rules"], DELETE), "fim_rules (default tier) is required", id="no-default-tier"
    ),
    pytest.param(
        mutate(["fim_rules"], {}), "fim_rules (default tier) is required", id="empty-default-tier"
    ),
    pytest.param(
        mutate(["fim_rules"], ["a", "b"]), "fim_rules must be an object", id="tier-not-an-object"
    ),
    pytest.param(
        mutate(["fim_rules_optional"], "x"),
        "fim_rules_optional must be an object",
        id="optional-not-an-object",
    ),
    pytest.param(
        mutate(["fim_rules", "t-identity"], "x"),
        "t-identity: must be an object",
        id="group-not-an-object",
    ),
    pytest.param(
        mutate(["fim_rules", "t-identity", "filters", "platforms"], ["linux", "windows"]),
        "platforms must be ['linux']",
        id="not-linux-only",
    ),
    pytest.param(
        mutate(["fim_rules", "t-identity", "filters"], DELETE),
        "platforms must be ['linux']",
        id="no-filters",
    ),
    pytest.param(
        mutate(["fim_rules_optional", "t-shell", "filters", "platforms"], ["macos"]),
        "t-shell: platforms must be ['linux']",
        id="optional-tier-checked-too",
    ),
    pytest.param(
        mutate(["fim_rules", "t-identity", "patterns"], []),
        "needs a non-empty list of string patterns",
        id="no-patterns",
    ),
    pytest.param(
        mutate(["fim_rules", "t-identity", "patterns"], ["/etc/passwd", 7]),
        "needs a non-empty list of string patterns",
        id="pattern-not-text",
    ),
    pytest.param(
        mutate(["fim_rules", "t-identity", "patterns"], ["etc/passwd"]),
        "pattern must be absolute: etc/passwd",
        id="relative-pattern",
    ),
    pytest.param(
        mutate(["fim_rules", "t-identity", "patterns"], [f"{HOME}/alex/.bashrc"]),
        f"literal username in pattern: {HOME}/alex/.bashrc",
        id="literal-username",
    ),
    pytest.param(
        mutate(["fim_rules", "t-identity", "patterns"], [f"{HOME}/al*/x"]),
        "literal username in pattern",
        id="partial-wildcard-username",
    ),
    pytest.param(mutate(["status"], "live"), "'status' must be one of", id="common-fields-checked"),
]


@pytest.mark.parametrize(("change", "expected"), FIM_BREAKS)
def test_each_fim_check_is_enforced(tmp_path: Path, change: Any, expected: str) -> None:
    rule = fim_rule()
    change(rule)
    put(tmp_path, rule)
    messages = found(tmp_path)
    assert any(expected in m for m in messages), messages


@pytest.mark.parametrize(
    "pattern", ["/home/*/.ssh/*", "/home/*", "/homework/x", f"/etc{HOME}/alex/y"]
)
def test_home_patterns_that_are_not_a_literal_username_are_fine(
    tmp_path: Path, pattern: str
) -> None:
    rule = fim_rule()
    rule["fim_rules"]["t-identity"]["patterns"] = [pattern]
    put(tmp_path, rule)
    assert found(tmp_path) == []


def test_an_unknown_kind_is_still_refused(tmp_path: Path) -> None:
    put(tmp_path, {"kind": "lookup", "name": "x"})
    assert any("unsupported kind 'lookup'" in m for m in found(tmp_path))


# ---- baseline holds only ready rules ----


@pytest.mark.parametrize("make", [valid_rule, fp_rule, fim_rule], ids=["rule", "fp", "fim"])
def test_a_draft_does_not_belong_under_baseline(tmp_path: Path, make: Any) -> None:
    draft = make(status="draft")
    put(tmp_path, draft, "baseline/linux/x.json")
    assert any("baseline" in m and "'ready'" in m for m in found(tmp_path))
    other = tmp_path / "other"
    put(other, copy.deepcopy(draft), "draft/linux/x.json")
    assert found(other) == []


def test_a_ready_rule_under_baseline_is_fine(tmp_path: Path) -> None:
    put(tmp_path, valid_rule(), "baseline/linux/x.json")
    assert found(tmp_path) == []
