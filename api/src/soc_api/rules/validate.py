"""The rule contract (note 29, section 2), and replay of each rule's own test events.

`check_tree` enforces the contract on every rule file; `replay_tree` runs every test event through
the local evaluator. Both return a list of Problems, empty when all is well.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import re2

from soc_api.rules.evaluate import (
    PLATFORM_CODES,
    SUPPORTED_OPS,
    BadRule,
    UnsupportedOperator,
    check_regex,
    describe_regex_error,
    fires,
    iter_nodes,
)
from soc_api.rules.loader import Problem, RuleFile, load_tree

STATUSES = ("ready", "draft")
PLATFORMS = (*PLATFORM_CODES, "any")
# A rule outside an org overlay may only report. An overlay rule may also tag and isolate, and
# must name the gate that decides when it does.
REPORT_ONLY = frozenset({"report"})
OVERLAY_ACTIONS = REPORT_ONLY | {"add tag", "remove tag", "isolate network"}

_QUOTED_EXE = re.compile(r'^"[A-Za-z]:\\[^"]+\.[A-Za-z]{2,4}"(\s|$)')
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
_DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.", "127.")
_ANY_ADDR = "0.0.0.0"  # noqa: S104 - an address that identifies nothing, not a bind
_EXAMPLE_HOSTS = ("example.com", "example.org", "example.net")
_EXAMPLE_TLDS = (".example", ".invalid", ".test")
_SAFE_REF = re.compile(r"^[A-Za-z0-9._/~^@{}-]{1,200}$")


class GitError(RuntimeError):
    """git could not answer (not installed, not a repository, no such commit)."""


# ---- where a file sits ----


def overlay_org(rel: str) -> str | None:
    """The org name for a file under orgs/<org>/, else None."""
    parts = rel.split("/")
    if "orgs" in parts[:-1]:
        i = parts.index("orgs")
        if i + 1 < len(parts) - 1:
            return parts[i + 1]
    return None


# ---- one file ----


def _event_problems(events: Any, kind: str) -> list[str]:
    if not isinstance(events, list):
        return [f"tests.{kind} must be a list"]
    out: list[str] = []
    for n, event in enumerate(events, start=1):
        label = f"{kind} #{n}"
        routing = event.get("routing") if isinstance(event, dict) else None
        body = event.get("event") if isinstance(event, dict) else None
        if not isinstance(routing, dict) or not isinstance(body, dict):
            out.append(f"{label}: needs 'routing' and 'event' objects")
        elif not isinstance(routing.get("event_type"), str) or not isinstance(
            routing.get("plat"), int
        ):
            out.append(f"{label}: routing needs 'event_type' (text) and 'plat' (number)")
    return out


def _identifier_problems(data: Any) -> list[str]:
    """What identifies a real org, sensor or person, in a file that is not an org overlay."""
    text = json.dumps(data)
    out: list[str] = []
    for ip in dict.fromkeys(_IPV4.findall(text)):
        if all(int(o) <= 255 for o in ip.split(".")) and not ip.startswith(_DOC_NETS):
            if ip != _ANY_ADDR:
                out.append(f"contains the address {ip}; use a documentation address")
    if _UUID.search(text):
        out.append("contains an identifier that looks like an org or sensor id")
    domains = dict.fromkeys(m.group(1).lower() for m in _EMAIL.finditer(text))
    if any(d not in _EXAMPLE_HOSTS and not d.endswith(_EXAMPLE_TLDS) for d in domains):
        out.append("contains an email address; use an example.com address")
    return out


def check_rule(rf: RuleFile) -> list[str]:
    """The contract problems of one rule file, as sentences."""
    if rf.error:
        return [rf.error]
    data = rf.data
    if not isinstance(data, dict):
        return ["must be a JSON object"]
    kind = data.get("kind", "rule")
    if kind != "rule":
        return [f"unsupported kind {kind!r}: this tool checks detection rules only"]

    out: list[str] = []
    org_dir = overlay_org(rf.rel)
    if "orgs" in rf.rel.split("/")[:-1] and org_dir is None:
        out.append("files under orgs/ must sit in orgs/<org>/")

    for key in ("name", "description"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            out.append(f"needs a text {key!r}")
    if isinstance(data.get("name"), str) and len(data["name"]) > 255:
        out.append("'name' is longer than 255 characters")
    if data.get("status") not in STATUSES:
        out.append(f"'status' must be one of {', '.join(STATUSES)}")
    pack, org = data.get("pack"), data.get("org")
    if not (isinstance(pack, str) and pack) and not (isinstance(org, str) and org):
        out.append("needs a 'pack' (shared rules) or an 'org' (an org's own rules)")
    if org_dir is not None and org != org_dir:
        out.append(f"'org' must be {org_dir!r} to match its folder")
    if org_dir is None and org:
        out.append("'org' is only for files under orgs/<org>/")

    detect = data.get("detect")
    if not isinstance(detect, dict):
        out.append("needs a 'detect' object")
        detect = {}

    # response: report-only unless this is an org overlay that names its gate
    respond = data.get("respond")
    if not isinstance(respond, list) or not respond:
        out.append("needs a non-empty 'respond' list")
        respond = []
    allowed = OVERLAY_ACTIONS if org_dir is not None else REPORT_ONLY
    acting = False
    for n, action in enumerate(respond, start=1):
        name = action.get("action") if isinstance(action, dict) else None
        if not isinstance(name, str):
            out.append(f"respond #{n}: needs an 'action'")
        elif name not in allowed:
            where = "an org overlay may only" if org_dir is not None else "only"
            out.append(
                f"respond #{n}: action {name!r} not allowed; {where} {', '.join(sorted(allowed))}"
            )
        elif name != "report":
            acting = True
        if name == "report" and not (
            isinstance(action.get("name"), str) and action["name"].strip()
        ):
            out.append(f"respond #{n}: a report needs a 'name' (its category, used for paging)")
    if acting and not (isinstance(data.get("gate"), str) and data["gate"].strip()):
        out.append("a rule that tags or isolates must name its response gate in 'gate'")

    # nodes: supported operators, RE2-only regexes, platform check
    nodes = list(iter_nodes(detect))
    paths = {n["path"] for n in nodes if isinstance(n.get("path"), str)}
    for node in nodes:
        op = node.get("op")
        if not isinstance(op, str) or op not in SUPPORTED_OPS:
            out.append(f"operator {op!r} is not supported by the local replay")
        elif op == "matches":
            pattern = node.get("re")
            reason = check_regex(pattern) if isinstance(pattern, str) else "no 're' text"
            if reason:
                out.append(f"regex {str(pattern)[:60]!r} rejected by RE2: {reason}")
    default_platform = pack if isinstance(pack, str) and pack in PLATFORM_CODES else "any"
    platform = data.get("platform", default_platform)
    if platform not in PLATFORMS:
        out.append(f"'platform' must be one of {', '.join(PLATFORMS)}")
    elif platform != "any" and not any(
        n.get("op") == "is platform" and n.get("name") == platform for n in nodes
    ):
        out.append(f"a {platform} rule needs an 'is platform {platform}' check")

    # tests: a pair, well formed; Windows command-line rules include a quoted-path positive
    tests = data.get("tests")
    if not isinstance(tests, dict):
        out.append("needs a 'tests' object with 'positive' and 'negative' lists")
        tests = {}
    for which in ("positive", "negative"):
        events = tests.get(which)
        if isinstance(events, list) and not events:
            out.append(f"needs at least one {which} test event")
        if events is None:
            out.append(f"needs {which} tests")
        else:
            out.extend(_event_problems(events, which))
    positives = tests.get("positive")
    # A rule that can fire on Windows, whatever its label: declared Windows, or any platform
    # with no `is platform` check at all, or with one that names windows.
    named = {n.get("name") for n in nodes if n.get("op") == "is platform"}
    on_windows = platform == "windows" or (platform == "any" and (not named or "windows" in named))
    if on_windows and "event/COMMAND_LINE" in paths and isinstance(positives, list):
        quoted = any(
            isinstance(e, dict)
            and isinstance(e.get("event"), dict)
            and isinstance(e["event"].get("COMMAND_LINE"), str)
            and _QUOTED_EXE.match(e["event"]["COMMAND_LINE"])
            for e in positives
        )
        if not quoted:
            out.append(
                "a Windows rule on the command line needs a positive whose COMMAND_LINE starts "
                'with a quoted full program path, like "C:\\Windows\\System32\\x.exe" args '
                "(real command lines quote the path)"
            )

    if org_dir is None:
        out.extend(_identifier_problems(data))
    return out


# ---- the tree ----


def check_files(files: list[RuleFile]) -> list[Problem]:
    problems = [Problem(rf.rel, msg) for rf in files for msg in check_rule(rf)]
    first_seen: dict[str, str] = {}
    for rf in files:
        name = rf.data.get("name") if isinstance(rf.data, dict) else None
        if isinstance(name, str):
            if name in first_seen:
                other = first_seen[name]
                problems.append(Problem(rf.rel, f"the name {name!r} is also used by {other}"))
            else:
                first_seen[name] = rf.rel
    return problems


# ---- the append-only check against a base commit ----


def _git(root: Path, *args: str, check: bool = True) -> str:
    try:
        done = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            ["git", "-C", str(root), *args],  # noqa: S607 - git from PATH, as in CI
            capture_output=True,
            text=True,
            check=check,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitError(f"git {args[0]} failed: {exc}") from exc
    return done.stdout if done.returncode == 0 else ""


def check_append_only(root: Path, files: list[RuleFile], base: str) -> list[Problem]:
    """Positives are append-only: every positive test event a rule had at `base` must still be
    there. A rule file that did not exist at `base` is new and free."""
    if not _SAFE_REF.match(base) or base.startswith("-"):
        return [Problem("(base)", f"{base!r} is not a usable git reference")]
    try:
        if not _git(root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}", check=False):
            return [Problem("(base)", f"cannot find {base!r}; fetch it first")]
        prefix = _git(root, "rev-parse", "--show-prefix").strip()
    except GitError as exc:
        return [Problem("(base)", str(exc))]
    problems: list[Problem] = []
    for rf in files:
        if not isinstance(rf.data, dict):
            continue
        old_text = _git(root, "show", f"{base}:{prefix}{rf.rel}", check=False)
        if not old_text:
            continue
        try:
            old = json.loads(old_text)
        except ValueError:
            continue
        # Either side may be malformed; that is the contract check's to report, never a crash.
        old_tests = old.get("tests") if isinstance(old, dict) else None
        old_positives = old_tests.get("positive", []) if isinstance(old_tests, dict) else []
        new_tests = rf.data.get("tests")
        new_positives = new_tests.get("positive") if isinstance(new_tests, dict) else None
        if not isinstance(new_positives, list):
            continue
        for event in old_positives if isinstance(old_positives, list) else []:
            if event not in new_positives:
                problems.append(
                    Problem(
                        rf.rel,
                        "a positive test was removed or edited (positives are append-only): "
                        + _summary(event),
                    )
                )
    return problems


def check_tree(root: Path, base: str | None = None) -> list[Problem]:
    files = load_tree(root)
    problems = check_files(files)
    if base is not None:
        problems.extend(check_append_only(root, files, base))
    return problems


# ---- replay ----


def _summary(event: Any) -> str:
    body = event.get("event") if isinstance(event, dict) else None
    if isinstance(body, dict):
        for key in ("COMMAND_LINE", "FILE_PATH", "DOMAIN_NAME"):
            if isinstance(body.get(key), str):
                return f"{key}={body[key][:80]!r}"
    return json.dumps(event)[:80]


def replay_rule(rf: RuleFile) -> list[str]:
    if rf.error or not isinstance(rf.data, dict):
        return ["cannot replay: " + (rf.error or "not a JSON object")]
    detect, tests = rf.data.get("detect"), rf.data.get("tests")
    if not isinstance(detect, dict) or not isinstance(tests, dict):
        return ["cannot replay: needs 'detect' and 'tests'"]
    out: list[str] = []
    for which, want in (("positive", True), ("negative", False)):
        events = tests.get(which)
        for n, event in enumerate(events if isinstance(events, list) else [], start=1):
            try:
                got = fires(detect, event if isinstance(event, dict) else {})
            except re2.error as exc:
                return [*out, f"cannot replay: regex rejected by RE2: {describe_regex_error(exc)}"]
            except (BadRule, UnsupportedOperator) as exc:
                return [*out, f"cannot replay: {type(exc).__name__}: {exc}"]
            if got != want:
                verb = "does not fire on" if want else "fires on"
                out.append(f"the rule {verb} {which} #{n}: {_summary(event)}")
    return out


def replay_tree(root: Path) -> list[Problem]:
    return [Problem(rf.rel, msg) for rf in load_tree(root) for msg in replay_rule(rf)]
