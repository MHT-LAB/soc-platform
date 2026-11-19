"""The rights one attended apply needs, read from standard input and from nowhere else.

The sender (a person at their own machine) pipes `NAME=value` lines, then one blank line, into
`rotate.sh --apply`. Nothing is read from the environment, a file or the command line, and
nothing here ever prints or logs a value: an error names the field, never what was typed.

Fields:
  LC_ROTATOR_KEY            the key that can create and delete keys at the detection vendor
  SECRETS_CLIENT_ID         the rotator's login to the secrets manager (id, secret)
  SECRETS_CLIENT_SECRET
  SECRETS_URL               where that service is, https and a host name only (not secret)
  SECRETS_PROJECT_ID        which project holds the values (not secret)
  SECRETS_ENVIRONMENT       optional, default `dev` (not secret)
"""

import re
from dataclasses import dataclass
from typing import IO

MAX_LINE_CHARS = 1024
ENV_DEFAULT = "dev"

FIELDS: dict[str, re.Pattern[str]] = {
    "LC_ROTATOR_KEY": re.compile(r"[A-Za-z0-9._-]{16,128}"),
    "SECRETS_CLIENT_ID": re.compile(r"[A-Za-z0-9._-]{8,128}"),
    "SECRETS_CLIENT_SECRET": re.compile(r"[A-Za-z0-9._~+/=-]{8,512}"),
    "SECRETS_URL": re.compile(r"https://[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]"),
    "SECRETS_PROJECT_ID": re.compile(r"[A-Za-z0-9-]{8,64}"),
    "SECRETS_ENVIRONMENT": re.compile(r"[a-z0-9-]{1,32}"),
}
REQUIRED = (
    "LC_ROTATOR_KEY",
    "SECRETS_CLIENT_ID",
    "SECRETS_CLIENT_SECRET",
    "SECRETS_URL",
    "SECRETS_PROJECT_ID",
)
FIELD_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]{0,39}")


class RightsError(Exception):
    """Names the field that was wrong. Never the value, never the line."""


class Secret:
    """A value that cannot be printed, logged or formatted by accident.

    The only way to the text is `reveal()`, which only the code that sends it to the vendor or
    writes it to a file calls."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    def __str__(self) -> str:
        return "***"

    def __format__(self, spec: str) -> str:
        return "***"

    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("a Secret is never copied or saved")


@dataclass(frozen=True)
class Rights:
    lc_key: Secret
    client_id: Secret
    client_secret: Secret
    secrets_url: str
    project_id: str
    environment: str


def _shown(name: str) -> str:
    return name if FIELD_NAME_RE.fullmatch(name) else "(unreadable name)"


def read_rights(stream: IO[str]) -> Rights:
    """Read `NAME=value` lines up to the first blank line (or the end of input)."""
    if stream.isatty():
        raise RightsError(
            "rights are read from a pipe on standard input, never typed at a terminal"
        )
    found: dict[str, str] = {}
    # At most one line past the last field: a line beyond the fifth is always unknown or a
    # repeat, so it is refused below and the loop can never read more than that.
    for _ in range(len(FIELDS) + 1):
        line = stream.readline(MAX_LINE_CHARS + 2)
        if line == "" or line.strip("\r\n") == "":
            break
        if len(line) > MAX_LINE_CHARS:
            raise RightsError("a line is too long")
        name, sep, value = line.rstrip("\r\n").partition("=")
        if not sep or name not in FIELDS:
            raise RightsError(f"unknown field {_shown(name)}")
        if name in found:
            raise RightsError(f"{name} is given twice")
        if not FIELDS[name].fullmatch(value):
            raise RightsError(f"{name} is not in the expected form")
        found[name] = value
    missing = [n for n in REQUIRED if n not in found]
    if missing:
        raise RightsError("missing " + ", ".join(missing))
    return Rights(
        lc_key=Secret(found["LC_ROTATOR_KEY"]),
        client_id=Secret(found["SECRETS_CLIENT_ID"]),
        client_secret=Secret(found["SECRETS_CLIENT_SECRET"]),
        secrets_url=found["SECRETS_URL"],
        project_id=found["SECRETS_PROJECT_ID"],
        environment=found.get("SECRETS_ENVIRONMENT", ENV_DEFAULT),
    )
