"""What the rotator remembers between runs: dates, outcomes and one approval. Never a value.

`state.json` is the source of truth for "last rotated". It is written whole, to a temporary
file in the same folder, flushed, then renamed over the old one, so a crash leaves either the
old file or the new one. A file that does not parse is refused (never overwritten): someone
should look at it before the next run replaces it.
"""

import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from soc_api.rotate.keys import ID_RE

STATE_VERSION = 1
MAX_STATE_BYTES = 256 * 1024
OUTCOMES = ("recorded", "rotated", "failed")
APPROVAL_MAX_AGE = timedelta(minutes=30)
HASH_RE = re.compile(r"[0-9a-f]{12}")
VENDOR_ID_RE = re.compile(r"[A-Za-z0-9._-]{8,128}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
STAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class StateError(Exception):
    """The state file is unreadable or not what this version wrote. Names no values."""


@dataclass
class KeyState:
    last_rotated: date
    outcome: str  # recorded (a person did it and said so) | rotated | failed
    revoke_pending: bool = False  # the new key works but the old one is still live
    due_override: date | None = None  # when the tracker's date differs from last + period
    updated: str = ""
    vendor_key_id: str = ""  # the vendor's id for the key now in use (an identifier, not a value)
    old_key_id: str = ""  # the key that must still be revoked when revoke_pending is set


@dataclass
class Approval:
    plan_hash: str
    commit: str
    approved_at: datetime


@dataclass
class State:
    keys: dict[str, KeyState] = field(default_factory=dict)
    approval: Approval | None = None


def stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(STAMP_FORMAT)


def _parse_stamp(text: object) -> datetime:
    if not isinstance(text, str):
        raise StateError("a timestamp is not text")
    try:
        return datetime.strptime(text, STAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        raise StateError("a timestamp is malformed") from None


def _parse_day(text: object) -> date:
    if not isinstance(text, str):
        raise StateError("a date is not text")
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise StateError("a date is malformed") from None


def from_json(doc: Any) -> State:
    if not isinstance(doc, dict) or doc.get("version") != STATE_VERSION:
        raise StateError("not a version 1 state file")
    raw_keys = doc.get("keys")
    if not isinstance(raw_keys, dict):
        raise StateError("keys is not a table")
    keys: dict[str, KeyState] = {}
    for key_id, item in raw_keys.items():
        if not (isinstance(key_id, str) and ID_RE.fullmatch(key_id) and isinstance(item, dict)):
            raise StateError("a key entry is malformed")
        outcome = item.get("outcome")
        pending = item.get("revoke_pending", False)
        if outcome not in OUTCOMES or not isinstance(pending, bool):
            raise StateError("a key entry has a bad outcome or flag")
        override = item.get("due_override")
        vendor_id, old_id = item.get("vendor_key_id", ""), item.get("old_key_id", "")
        for ident in (vendor_id, old_id):
            if not isinstance(ident, str) or (ident and not VENDOR_ID_RE.fullmatch(ident)):
                raise StateError("a vendor key id is malformed")
        keys[key_id] = KeyState(
            last_rotated=_parse_day(item.get("last_rotated")),
            outcome=outcome,
            revoke_pending=pending,
            due_override=_parse_day(override) if override is not None else None,
            updated=str(item.get("updated", ""))[:20],
            vendor_key_id=vendor_id,
            old_key_id=old_id,
        )
    approval = None
    raw = doc.get("approval")
    if raw is not None:
        if not (
            isinstance(raw, dict)
            and isinstance(raw.get("plan_hash"), str)
            and HASH_RE.fullmatch(raw["plan_hash"])
            and isinstance(raw.get("commit"), str)
            and COMMIT_RE.fullmatch(raw["commit"])
        ):
            raise StateError("the approval is malformed")
        approval = Approval(raw["plan_hash"], raw["commit"], _parse_stamp(raw.get("approved_at")))
    return State(keys, approval)


def to_json(state: State) -> dict[str, Any]:
    return {
        "version": STATE_VERSION,
        "keys": {
            key_id: {
                "last_rotated": k.last_rotated.isoformat(),
                "outcome": k.outcome,
                "revoke_pending": k.revoke_pending,
                **({"due_override": k.due_override.isoformat()} if k.due_override else {}),
                **({"vendor_key_id": k.vendor_key_id} if k.vendor_key_id else {}),
                **({"old_key_id": k.old_key_id} if k.old_key_id else {}),
                "updated": k.updated,
            }
            for key_id, k in sorted(state.keys.items())
        },
        "approval": (
            {
                "plan_hash": state.approval.plan_hash,
                "commit": state.approval.commit,
                "approved_at": stamp(state.approval.approved_at),
            }
            if state.approval
            else None
        ),
    }


def load(path: Path) -> State:
    """The saved state, or an empty one when there is no file yet. Anything odd is refused."""
    if not path.exists():
        return State()
    try:
        if path.stat().st_size > MAX_STATE_BYTES:
            raise StateError("the state file is too large")
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise StateError("the state file cannot be read as JSON") from None
    return from_json(doc)


def write_json_atomic(path: Path, doc: dict[str, Any]) -> None:
    """Write whole, flush, rename: mode 600, never a half-written file."""
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if os.geteuid() == 0:
            # The plan container reads these as its own user: a file written by root (the
            # apply runs on the host) keeps the folder's owner instead of becoming root-only.
            folder = path.parent.stat()
            os.fchown(fd, folder.st_uid, folder.st_gid)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def save(path: Path, state: State) -> None:
    write_json_atomic(path, to_json(state))


def approval_problem(
    state: State, plan_hash: str, commit: str, now: datetime, max_age: timedelta = APPROVAL_MAX_AGE
) -> str | None:
    """Why the saved approval does not cover this exact plan right now, or None if it does.
    The apply step (a later build) refuses on any answer but None."""
    a = state.approval
    if a is None:
        return "no_approval"
    if a.commit != commit:
        return "commit_changed"
    if a.plan_hash != plan_hash:
        return "plan_changed"
    if a.approved_at > now + timedelta(minutes=5):
        return "from_the_future"
    if now - a.approved_at > max_age:
        return "expired"
    return None
