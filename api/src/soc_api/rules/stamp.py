"""The stamp a deploy puts on every rule it manages, and the one the posture collector checks.

A stamp is a keyed hash (HMAC-SHA256) of the parts of a rule that decide what it does: its
`detect`, its `respond` and whether it is enabled. The deploy writes it as a rule tag
(`git:<12 hex>`). Someone who can only change rules in the vendor's web app, or who holds a
leaked deploy key but not the stamp key, can change a rule but cannot make a matching stamp,
so the change shows as drift. The vendor never sees the key.

Standard library only: this module is shared with the posture collector (E4), which uses
`classify_rule` and `check_manifest` below to say, for each live rule, whether it is still what
the deploy wrote.
"""

import hashlib
import hmac
import json
from typing import Any

TAG_PREFIX = "git:"
STAMP_HEX = 12  # 48 bits: enough to catch a changed rule; the key is what makes it unforgeable
MIN_KEY_CHARS = 32
MANIFEST_NAME = "soc-manifest"

# The manifest is a rule that can never fire: it exists so its comment can hold the list of
# managed names (a rule deleted live is then found missing). Disabled, reports only.
MANIFEST_DETECT: dict[str, Any] = {
    "event": "NEW_PROCESS",
    "op": "is",
    "path": "event/COMMAND_LINE",
    "value": "soc-manifest-this-rule-never-fires",
}
MANIFEST_RESPOND: list[dict[str, Any]] = [{"action": "report", "name": "soc-manifest"}]


def canonical(detect: Any, respond: Any, enabled: bool) -> bytes:
    """The rule's behaviour as bytes, the same for the same rule however the JSON was ordered."""
    body = {"detect": detect, "respond": respond, "enabled": enabled}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _mac(key: str, label: bytes, payload: bytes) -> str:
    if len(key) < MIN_KEY_CHARS:
        raise ValueError(f"the stamp key must be at least {MIN_KEY_CHARS} characters")
    digest = hmac.new(key.encode(), label + b"\0" + payload, hashlib.sha256).hexdigest()
    return digest[:STAMP_HEX]


def stamp_tag(key: str, detect: Any, respond: Any, enabled: bool) -> str:
    """`git:<12 hex>` for a rule."""
    return TAG_PREFIX + _mac(key, b"rule", canonical(detect, respond, enabled))


def manifest_mac(key: str, names: list[str]) -> str:
    """12 hex over the sorted list of managed rule names (the manifest's own check)."""
    payload = json.dumps(sorted(names), separators=(",", ":"), ensure_ascii=False).encode()
    return _mac(key, b"manifest", payload)


def stamp_of(tags: Any) -> str | None:
    """The one `git:` tag in a rule's tags, or None when there is none or more than one."""
    if not isinstance(tags, list):
        return None
    found = [t for t in tags if isinstance(t, str) and t.startswith(TAG_PREFIX)]
    return found[0] if len(found) == 1 else None


def has_stamp_tag(tags: Any) -> bool:
    """True when any tag claims to be a stamp, right or wrong."""
    return isinstance(tags, list) and any(
        isinstance(t, str) and t.startswith(TAG_PREFIX) for t in tags
    )


# What the collector says about one rule (stored with the inventory) and about the manifest.
RULE_OK, RULE_CHANGED, RULE_UNMANAGED = "ok", "changed", "unmanaged"
MANIFEST_OK, MANIFEST_BAD, MANIFEST_ABSENT, MANIFEST_NONE = "ok", "bad", "absent", "none"
MANIFEST_COMMENT_PREFIX = "soc-manifest "


def classify_rule(
    key: str,
    prefixes: tuple[str, ...],
    name: str,
    detect: Any,
    respond: Any,
    enabled: bool,
    tags: Any,
    managed_names: frozenset[str] = frozenset(),
) -> str | None:
    """`ok`, `changed` or `unmanaged` for a rule the deploy manages, None for one it does not.

    * a rule that carries a stamp is managed: `ok` when exactly one stamp is present and it is
      the one this body and flag produce, otherwise `changed` (edited, re-tagged, or given a
      second stamp);
    * a rule without a stamp is `changed` when the (verified) manifest lists it, because its
      stamp was removed; `unmanaged` when its name starts with a managed prefix (made by hand
      where the deploy owns the names); and otherwise not ours.
    """
    if has_stamp_tag(tags):
        try:
            want = stamp_tag(key, detect, respond, enabled)
        except (TypeError, ValueError):
            return RULE_CHANGED
        got = stamp_of(tags)
        return RULE_OK if got is not None and hmac.compare_digest(got, want) else RULE_CHANGED
    if name in managed_names:
        return RULE_CHANGED
    if prefixes and name.startswith(prefixes):
        return RULE_UNMANAGED
    return None


def parse_manifest_comment(key: str, comment: Any) -> list[str] | None:
    """The managed names a manifest comment lists, or None when it is not one this key made."""
    if not isinstance(comment, str) or not comment.startswith(MANIFEST_COMMENT_PREFIX):
        return None
    try:
        body = json.loads(comment[len(MANIFEST_COMMENT_PREFIX) :])
    except ValueError:
        return None
    if not isinstance(body, dict) or body.get("v") != 1:
        return None
    names, mac = body.get("names"), body.get("mac")
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        return None
    if not isinstance(mac, str):
        return None
    try:
        want = manifest_mac(key, names)
    except ValueError:
        return None
    return list(names) if hmac.compare_digest(mac, want) else None


def check_manifest(
    key: str,
    detect: Any,
    respond: Any,
    enabled: bool,
    tags: Any,
    comment: Any,
) -> tuple[str, list[str]]:
    """(`ok` or `bad`, the names it lists). `bad` when the comment is not a valid one for this
    key, or the rule's own body, flag or stamp is not what the deploy writes (the manifest
    can never fire, so a manifest that changed was changed by hand)."""
    names = parse_manifest_comment(key, comment)
    body_ok = (
        detect == MANIFEST_DETECT
        and respond == MANIFEST_RESPOND
        and enabled is False
        and classify_rule(key, (), MANIFEST_NAME, detect, respond, enabled, tags) == RULE_OK
    )
    if names is None or not body_ok:
        return MANIFEST_BAD, []
    return MANIFEST_OK, names
