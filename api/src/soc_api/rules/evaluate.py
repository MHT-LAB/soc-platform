"""A local model of the EDR platform's detection rule engine, for replaying test events.

It answers one question: does this rule's `detect` fire on this event? It exists so that CI can
replay every rule's tests with no key and no network. It is deliberately strict: an operator it
does not know is an error, never a silent "no match", so a rule cannot slip past replay by using
something this model does not understand. The platform's own rule tester stays the authority; the
private pipeline replays there too.

Regexes run on Google RE2, the engine family the platform uses, so lookarounds and
backreferences are rejected here as they are there.

Behaviour verified against the platform's rule tester on 2026-11-16 (inline events, no org
changes):
  * is, contains, starts with, ends with: case-sensitive unless `case sensitive` is false.
  * matches: case-INsensitive unless `case sensitive` is true.
  * `not: true` inverts any node; a path that is missing makes a leaf false, so `not` makes it true.
  * exists: the path is present. is tagged: the tag is in `routing/tags`.
  * `event` (one type) or `events` (a list) filter on `routing/event_type`.
  * is platform: `routing/plat` equals the code for windows, linux or macos.
"""

import functools
from collections.abc import Iterator
from typing import Any

import re2

PLATFORM_CODES = {"windows": 0x10000000, "linux": 0x20000000, "macos": 0x30000000}
GROUP_OPS = frozenset({"and", "or"})
LEAF_OPS = frozenset(
    {"matches", "contains", "starts with", "ends with", "is", "exists", "is platform", "is tagged"}
)
SUPPORTED_OPS = GROUP_OPS | LEAF_OPS

_MISSING = object()


class UnsupportedOperator(ValueError):
    """The rule uses an operator this model does not implement."""


class BadRule(ValueError):
    """The rule is malformed (a missing field, a wrong type)."""


@functools.lru_cache(maxsize=1024)
def compile_regex(pattern: str, case_sensitive: bool) -> Any:
    """An RE2 pattern; case-insensitive by prefixing the flag, which RE2 carries to the end of
    the pattern. Raises re2.error on syntax the engine rejects."""
    return re2.compile(pattern if case_sensitive else "(?i)" + pattern)


def describe_regex_error(exc: Exception) -> str:
    """The engine's complaint about a pattern, as text (it reports bytes)."""
    reason = exc.args[0] if exc.args else exc
    return reason.decode(errors="replace") if isinstance(reason, bytes) else str(reason)


def check_regex(pattern: str) -> str | None:
    """None when RE2 accepts the pattern, otherwise the engine's complaint."""
    try:
        re2.compile(pattern)
    except re2.error as exc:
        return describe_regex_error(exc)
    return None


def iter_nodes(detect: Any) -> Iterator[dict[str, Any]]:
    """Every rule node of a detect tree, the root first. Anything that is not an object is skipped
    here; evaluation and validation report it."""
    if isinstance(detect, dict):
        yield detect
        children = detect.get("rules")
        if isinstance(children, list):
            for child in children:
                yield from iter_nodes(child)


def lookup(event: dict[str, Any], path: str) -> Any:
    """The value at a slash path ("event/COMMAND_LINE", "routing/hostname"), or _MISSING."""
    current: Any = event
    for part in path.split("/"):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _flag(node: dict[str, Any], key: str, default: bool) -> bool:
    value = node.get(key, default)
    if not isinstance(value, bool):
        raise BadRule(f"{key!r} must be true or false")
    return value


def _text(node: dict[str, Any], key: str) -> str:
    value = node.get(key)
    if not isinstance(value, str):
        raise BadRule(f"{node.get('op')!r} needs a text {key!r}")
    return value


def _leaf(op: str, node: dict[str, Any], event: dict[str, Any]) -> bool:
    if op == "is platform":
        name = _text(node, "name")
        if name not in PLATFORM_CODES:
            raise BadRule(f"unknown platform {name!r} (use windows, linux or macos)")
        return bool(lookup(event, "routing/plat") == PLATFORM_CODES[name])
    if op == "is tagged":
        tag = _text(node, "tag")
        tags = lookup(event, "routing/tags")
        return isinstance(tags, list) and tag in tags
    path = _text(node, "path")
    value = lookup(event, path)
    if op == "exists":
        return value is not _MISSING
    if op == "matches":
        pattern = _text(node, "re")
        sensitive = _flag(node, "case sensitive", False)
        compiled = compile_regex(pattern, sensitive)
        return isinstance(value, str) and compiled.search(value) is not None
    sensitive = _flag(node, "case sensitive", True)
    want = node.get("value")
    if op == "is" and not isinstance(want, str):
        return value is not _MISSING and bool(value == want)
    if not isinstance(want, str):
        raise BadRule(f"{op!r} needs a text 'value'")
    if not isinstance(value, str):
        return False
    have, wanted = (value, want) if sensitive else (value.lower(), want.lower())
    if op == "is":
        return have == wanted
    if op == "contains":
        return wanted in have
    if op == "starts with":
        return have.startswith(wanted)
    return have.endswith(wanted)  # ends with


def _node(node: Any, event: dict[str, Any]) -> bool:
    if not isinstance(node, dict):
        raise BadRule("a rule node must be an object")
    op = node.get("op")
    if not isinstance(op, str):
        raise BadRule("a rule node has no 'op'")
    if op not in SUPPORTED_OPS:
        raise UnsupportedOperator(op)
    if op in GROUP_OPS:
        children = node.get("rules")
        if not isinstance(children, list) or not children:
            raise BadRule(f"{op!r} needs a non-empty 'rules' list")
        # Every child is evaluated, so a malformed one is reported even after an early answer.
        results = [_node(child, event) for child in children]
        result = all(results) if op == "and" else any(results)
    else:
        result = _leaf(op, node, event)
    return result != _flag(node, "not", False)


def event_types(detect: dict[str, Any]) -> list[str] | None:
    """The event types the rule is limited to, or None when it applies to every event."""
    if "events" in detect:
        types = detect["events"]
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types) or not types:
            raise BadRule("'events' must be a non-empty list of event types")
        return list(types)
    if "event" in detect:
        one = detect["event"]
        if not isinstance(one, str):
            raise BadRule("'event' must be an event type")
        return [one]
    return None


def fires(detect: dict[str, Any], event: dict[str, Any]) -> bool:
    """True when the rule's detect fires on one test event ({"routing": {...}, "event": {...}})."""
    types = event_types(detect)
    if types is not None and lookup(event, "routing/event_type") not in types:
        return False
    return _node(detect, event)
