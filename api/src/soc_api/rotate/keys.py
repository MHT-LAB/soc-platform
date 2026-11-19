"""Read the key register: one small TOML file per key, from a read-only folder.

The register lives in a private repository, which checks every file in its own CI. This
loader re-checks only what the rotation plan relies on (who the key is, whether it is
automatic or manual, how often it is rotated, whether it is ready), because a wrong period or
method silently moves a due date. A file holds names and references, never a value, and this
loader never prints a file's contents: a problem names the file and the field.
"""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,48}")
VENDOR_RE = re.compile(r"[a-z0-9]{2,32}")
METHODS = ("automatic", "manual", "none")
STANDARD_DAYS, SENSITIVE_DAYS = 90, 30
MAX_FILES = 200
MAX_FILE_BYTES = 64 * 1024
MAX_TEXT = 1200
SHOWN_NAME = 60


def printable(text: str, limit: int = SHOWN_NAME) -> str:
    """Safe for a root terminal and a log line: printable ASCII only, one line, capped."""
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in text)[:limit]


@dataclass(frozen=True)
class KeyFile:
    id: str
    name: str
    vendor: str
    method: str  # automatic | manual | none
    sensitive: bool
    period_days: int | None  # None for a key replaced only on exposure
    ready: bool  # False while the key does not exist yet or its permissions are unconfirmed
    check: str  # manual keys: how a person proves the new key works (shown in the plan)


@dataclass(frozen=True)
class Register:
    keys: dict[str, KeyFile]
    problems: list[str]


def _text(doc: dict[str, Any], field: str, *, limit: int = MAX_TEXT) -> str | None:
    value = doc.get(field)
    if isinstance(value, str) and 0 < len(value.strip()) <= limit:
        return value
    return None


def parse_key(file_name: str, stem: str, doc: dict[str, Any]) -> tuple[KeyFile | None, list[str]]:
    """One file's document: the key, or the problems (field names only, never values)."""
    problems: list[str] = []

    def bad(message: str) -> None:
        problems.append(f"{file_name}: {message}")

    key_id = doc.get("id")
    if not (isinstance(key_id, str) and ID_RE.fullmatch(key_id)):
        bad("id must be lowercase letters, digits and hyphens")
    elif key_id != stem:
        bad("id must equal the file name")
    name = _text(doc, "name", limit=200)
    if name is None:
        bad("name must be non-empty text")
    vendor = doc.get("vendor")
    if not (isinstance(vendor, str) and VENDOR_RE.fullmatch(vendor)):
        bad("vendor must be a short lowercase word")
    method = doc.get("method")
    if method not in METHODS:
        bad("method must be automatic, manual or none")
    sensitive = doc.get("sensitive")
    if not isinstance(sensitive, bool):
        bad("sensitive must be true or false")
    ready = doc.get("ready", True)
    if not isinstance(ready, bool):
        bad("ready must be true or false")
    period = doc.get("period_days")
    if method in ("automatic", "manual") and isinstance(sensitive, bool):
        want = SENSITIVE_DAYS if sensitive else STANDARD_DAYS
        if period != want or isinstance(period, bool):
            bad(f"period_days must be {want} for a {'sensitive' if sensitive else 'standard'} key")
    elif method == "none" and "period_days" in doc:
        bad("period_days is not allowed when method is none")
    check = ""
    manual = doc.get("manual")
    if isinstance(manual, dict):
        check = _text(manual, "check") or ""
    if problems:
        return None, problems
    assert isinstance(key_id, str) and isinstance(name, str)  # noqa: S101 - narrowed above
    assert isinstance(vendor, str) and isinstance(method, str)  # noqa: S101
    assert isinstance(sensitive, bool) and isinstance(ready, bool)  # noqa: S101
    return (
        KeyFile(
            id=key_id,
            name=printable(name),
            vendor=vendor,
            method=method,
            sensitive=sensitive,
            period_days=period if method != "none" and isinstance(period, int) else None,
            ready=ready,
            check=printable(check, 120),
        ),
        [],
    )


def load_register(directory: Path) -> Register:
    """Every key file in the folder. Anything unexpected is a problem, not a skipped file."""
    if not directory.is_dir():
        return Register({}, ["the register folder is missing or is not a folder"])
    problems: list[str] = []
    keys: dict[str, KeyFile] = {}
    entries = sorted(directory.iterdir())
    if len(entries) > MAX_FILES:
        problems.append(f"the register has more than {MAX_FILES} files")
        entries = entries[:MAX_FILES]
    if not entries:
        problems.append("the register has no key files")
    for path in entries:
        shown = printable(path.name, 80)
        if path.is_symlink() or not path.is_file():
            problems.append(f"{shown}: not a plain file")
            continue
        if path.suffix != ".toml":
            problems.append(f"{shown}: only .toml key files belong in the register")
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            problems.append(f"{shown}: larger than {MAX_FILE_BYTES // 1024} KiB")
            continue
        try:
            doc = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            problems.append(f"{shown}: not readable as TOML")
            continue
        key, errs = parse_key(shown, path.stem, doc)
        problems.extend(errs)
        if key is not None:
            keys[key.id] = key
    return Register(keys, problems)
