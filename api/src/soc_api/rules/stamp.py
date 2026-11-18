"""The stamp a deploy puts on every rule it manages, and the one the posture collector checks.

A stamp is a keyed hash (HMAC-SHA256) of the parts of a rule that decide what it does: its
`detect`, its `respond` and whether it is enabled. The deploy writes it as a rule tag
(`git:<12 hex>`). Someone who can only change rules in the vendor's web app, or who holds a
leaked deploy key but not the stamp key, can change a rule but cannot make a matching stamp,
so the change shows as drift. The vendor never sees the key.

Standard library only: this module is shared with the posture collector (E4).
"""

import hashlib
import hmac
import json
from typing import Any

TAG_PREFIX = "git:"
STAMP_HEX = 12  # 48 bits: enough to catch a changed rule; the key is what makes it unforgeable
MIN_KEY_CHARS = 32
MANIFEST_NAME = "soc-manifest"


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
