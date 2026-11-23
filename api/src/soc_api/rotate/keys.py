"""Read the key register: one small TOML file per key, from a read-only folder.

The register lives in a private repository, which checks every file in its own CI. This
loader re-checks only what the rotation plan relies on (who the key is, whether it is
automatic or manual, how often it is rotated, whether it is ready), because a wrong period or
method silently moves a due date. A file holds names and references, never a value, and this
loader never prints a file's contents: a problem names the file and the field.
"""

import fnmatch
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
PERM_RE = re.compile(r"[a-z][a-z_]*(\.[a-z_*]+)+")
ENV_RE = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
ENV_FILE_RE = re.compile(r"env/[a-z0-9-]+\.env")
SERVICE_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")
# Health checks the apply step knows how to run, by name. A key file can never carry a command.
SUPPORTED_CHECKS = ("posture_check",)
# Creating a first key also knows the rules service's login check, and "none" for a file that no
# running service reads: "none" is allowed only when nothing is restarted, so a restarted
# service always gets a real check.
PROVISION_CHECKS = (*SUPPORTED_CHECKS, "rules_plan")
NO_CHECK = "none"
SELF_VENDOR = "self"
GENERATED_CHARSET = "A-Za-z0-9._-"
MIN_GENERATED, MAX_GENERATED = 32, 128
ROTATOR_PROJECT = "SOC-rotated"


def printable(text: str, limit: int = SHOWN_NAME) -> str:
    """Safe for a root terminal and a log line: printable ASCII only, one line, capped."""
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in text)[:limit]


@dataclass(frozen=True)
class ApplySpec:
    """What the apply step needs for one automatic key whose new value goes to one env file."""

    console_name: str
    perms: tuple[str, ...]
    forbidden: tuple[str, ...]
    org_name: str  # the secret that holds the organization id (not a key)
    project: str
    path: str
    secret_name: str  # the one secret that holds this key's value
    grace_minutes: int
    env_file: str
    env_var: str
    restart: tuple[str, ...]
    check: str


@dataclass(frozen=True)
class ConsumerSpec:
    """One env file that holds the stored value, and what to run once it does."""

    env_file: str
    env_var: str
    restart: tuple[str, ...]
    check: str  # a name from PROVISION_CHECKS, or NO_CHECK when nothing is restarted


@dataclass(frozen=True)
class ProvisionSpec:
    """What creating a first key needs. For a vendor key: its console name and exact
    permissions. For a `self` key (a random value, no vendor call): its length. Both: where the
    value is stored and which env files get it. Built only for a key marked not ready."""

    vendor: str  # limacharlie | self
    console_name: str  # "" for a self key
    perms: tuple[str, ...]  # () for a self key
    org_name: str  # the secret that holds the organization id; "" for a self key
    length: int  # 0 for a vendor key
    path: str
    secret_name: str
    consumers: tuple[ConsumerSpec, ...]


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
    apply: ApplySpec | None = None  # set for an automatic key this build can rotate
    apply_note: str = ""  # why not, for an automatic key this build cannot rotate yet
    provision: ProvisionSpec | None = None  # set for a not-ready key this build can create


@dataclass(frozen=True)
class Register:
    keys: dict[str, KeyFile]
    problems: list[str]


def _text(doc: dict[str, Any], field: str, *, limit: int = MAX_TEXT) -> str | None:
    value = doc.get(field)
    if isinstance(value, str) and 0 < len(value.strip()) <= limit:
        return value
    return None


def _strings(value: object) -> tuple[str, ...] | None:
    if isinstance(value, list) and all(isinstance(x, str) and x for x in value):
        return tuple(value)
    return None


def parse_apply(doc: dict[str, Any], ready: bool) -> tuple[ApplySpec | None, str, list[str]]:
    """The apply details of an automatic key: (spec, why-not, safety problems).

    Anything this build simply cannot do yet is a "why-not" (the key is skipped and named).
    A permission set that breaks the safety rules is a problem: the register is refused, as it
    would be by its own CI, because a wrong permission list must never reach a vendor call."""
    scope, store = doc.get("scope"), doc.get("store")
    consumers = doc.get("consumer")
    problems: list[str] = []
    if not isinstance(scope, dict):
        return None, "no scope table", ["scope table is required for a vendor key"]
    perms, forbidden = _strings(scope.get("perms")), _strings(scope.get("forbidden_perms"))
    if perms is None or forbidden is None:
        return None, "perms or forbidden_perms is not a list", ["scope lists are malformed"]
    for perm in perms:
        if not PERM_RE.fullmatch(perm):
            problems.append("scope.perms holds a name that is not a permission")
        for pattern in forbidden:
            if fnmatch.fnmatchcase(perm, pattern):
                problems.append("scope.perms holds a permission the forbidden list refuses")
    if "output.*" not in forbidden or "apikey.*" not in forbidden:
        problems.append("scope.forbidden_perms must refuse output.* and apikey.*")
    if ready and not perms:
        problems.append("scope.perms is empty for a key marked ready")
    if problems:
        return None, "unsafe permissions", problems
    if not ready:
        return None, "not ready", []
    if not isinstance(store, dict) or store.get("kind") != "secrets_manager":
        return None, "the value is not in the secrets manager", []
    names = _strings(store.get("names"))
    if names is None or len(names) != 1 or not NAME_RE.fullmatch(names[0]):
        return None, "this build rotates one stored value per key", []
    project, path = store.get("project"), store.get("path")
    if project != ROTATOR_PROJECT or not (isinstance(path, str) and path.startswith("/")):
        return None, f"the value is not in project {ROTATOR_PROJECT}", []
    org_name = scope.get("org_store_name")
    if not (isinstance(org_name, str) and NAME_RE.fullmatch(org_name)):
        return None, "no org_store_name", []
    if not (isinstance(consumers, list) and len(consumers) == 1 and isinstance(consumers[0], dict)):
        return None, "this build handles exactly one consumer", []
    c = consumers[0]
    if c.get("kind") != "env_file" or c.get("host") != "ct110":
        return None, "this build handles an env file on the host only", []
    if c.get("check") not in SUPPORTED_CHECKS:
        return None, "this build has no such health check yet", []
    if c.get("post_step", "none") != "none":
        return None, "this build has no follow-up step", []
    env_map, restart = c.get("env_map"), _strings(c.get("restart"))
    env_file = c.get("env_file")
    if not (isinstance(env_file, str) and ENV_FILE_RE.fullmatch(env_file)) or restart is None:
        return None, "the consumer's file or services are malformed", []
    if not all(SERVICE_RE.fullmatch(x) for x in restart):
        return None, "the consumer's services are malformed", []
    if not (isinstance(env_map, dict) and list(env_map) == [names[0]]):
        return None, "the consumer must map the stored value to one variable", []
    env_var = env_map[names[0]]
    grace = doc.get("grace_minutes", 10)
    if not (isinstance(env_var, str) and ENV_RE.fullmatch(env_var)):
        return None, "the consumer's variable name is malformed", []
    if not (isinstance(grace, int) and not isinstance(grace, bool) and 0 <= grace <= 120):
        return None, "grace_minutes is not a number from 0 to 120", []
    console = _text(doc, "console_name", limit=64)
    if console is None or not NAME_RE.fullmatch(console):
        return None, "console_name is not a plain name", []
    return (
        ApplySpec(
            console_name=console,
            perms=perms,
            forbidden=forbidden,
            org_name=org_name,
            project=project,
            path=path,
            secret_name=names[0],
            grace_minutes=grace,
            env_file=env_file,
            env_var=env_var,
            restart=restart,
            check=str(c["check"]),
        ),
        "",
        [],
    )


def _consumers(doc: dict[str, Any], secret_name: str) -> tuple[tuple[ConsumerSpec, ...], str]:
    """The env files that get the value: (consumers, why-not). One or two files, each mapping
    the stored value to one variable, none with a follow-up step."""
    raw = doc.get("consumer")
    if not (isinstance(raw, list) and 1 <= len(raw) <= 2 and all(isinstance(c, dict) for c in raw)):
        return (), "this build creates a key for one or two env files"
    out: list[ConsumerSpec] = []
    for c in raw:
        if c.get("kind") != "env_file" or c.get("host") != "ct110":
            return (), "this build handles an env file on the host only"
        if c.get("post_step", "none") != "none":
            return (), "this build has no follow-up step"
        env_file, restart, env_map = c.get("env_file"), _strings(c.get("restart")), c.get("env_map")
        if not (isinstance(env_file, str) and ENV_FILE_RE.fullmatch(env_file)) or restart is None:
            return (), "a consumer's file or services are malformed"
        if not all(SERVICE_RE.fullmatch(x) for x in restart):
            return (), "a consumer's services are malformed"
        if not (isinstance(env_map, dict) and list(env_map) == [secret_name]):
            return (), "each consumer must map the stored value to one variable"
        var, check = env_map[secret_name], c.get("check")
        if not (isinstance(var, str) and ENV_RE.fullmatch(var)):
            return (), "a consumer's variable name is malformed"
        if check not in (*PROVISION_CHECKS, NO_CHECK) or (check == NO_CHECK and restart):
            return (
                (),
                "a consumer needs a health check this build knows"
                " (none only if it restarts nothing)",
            )
        out.append(ConsumerSpec(env_file, var, restart, str(check)))
    if len({c.env_file for c in out}) != len(out):
        return (), "two consumers name the same file"
    return tuple(out), ""


def parse_provision(doc: dict[str, Any], vendor: str) -> tuple[ProvisionSpec | None, str]:
    """The details for creating a first key (spec, why-not). Only called for a key marked not
    ready: a ready key is rotated, never created. A wrong or missing detail is a why-not, so the
    key is listed as not creatable yet instead of the register being refused."""
    store = doc.get("store")
    if not isinstance(store, dict) or store.get("kind") != "secrets_manager":
        return None, "the value is not in the secrets manager"
    names = _strings(store.get("names"))
    if names is None or len(names) != 1 or not NAME_RE.fullmatch(names[0]):
        return None, "this build stores one value per key"
    project, path = store.get("project"), store.get("path")
    if project != ROTATOR_PROJECT or not (isinstance(path, str) and path.startswith("/")):
        return None, f"the value is not in project {ROTATOR_PROJECT}"
    consumers, why = _consumers(doc, names[0])
    if not consumers:
        return None, why
    if vendor == SELF_VENDOR:
        gen = doc.get("generate")
        length = gen.get("length") if isinstance(gen, dict) else None
        if not (
            isinstance(gen, dict)
            and gen.get("kind") == "random"
            and gen.get("charset") == GENERATED_CHARSET
            and isinstance(length, int)
            and not isinstance(length, bool)
            and MIN_GENERATED <= length <= MAX_GENERATED
        ):
            return None, "generate must be a random value of 32 to 128 of A-Za-z0-9._-"
        return ProvisionSpec(vendor, "", (), "", length, path, names[0], consumers), ""
    scope = doc.get("scope")
    perms = _strings(scope.get("perms")) if isinstance(scope, dict) else None
    org_name = scope.get("org_store_name") if isinstance(scope, dict) else None
    console = _text(doc, "console_name", limit=64)
    if not perms or console is None or not NAME_RE.fullmatch(console):
        return None, "perms and console_name are required to create a vendor key"
    if not (isinstance(org_name, str) and NAME_RE.fullmatch(org_name)):
        return None, "no org_store_name"
    return ProvisionSpec(vendor, console, perms, org_name, 0, path, names[0], consumers), ""


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
    spec, why_not, prov = None, "", None
    if method == "automatic" and vendor == "limacharlie" and isinstance(ready, bool):
        spec, why_not, unsafe = parse_apply(doc, ready)
        for message in unsafe:
            bad(message)
    elif method == "automatic":
        why_not = "this build rotates detection-vendor keys only"
    if method == "automatic" and ready is False and vendor in ("limacharlie", SELF_VENDOR):
        prov, _ = parse_provision(doc, vendor)
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
            apply=spec,
            apply_note=why_not,
            provision=prov,
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
