"""Case data for the console, through the soc_console role's four functions only.

The console runs on the host network and reaches the database on the host's loopback
(127.0.0.1:5432). The role has no table privileges: everything here is a function call,
and what comes back about an alert is cut text, never structure. Each call uses its own
short connection: traffic is a person at a keyboard, and a stale connection cannot
outlive a database restart that way.

Every failure to reach the database is reported as CasesUnavailable with no detail: the
message of a database error can carry the host and user name, and the page must not.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import psycopg
from sqlalchemy.engine import make_url

STATUS_FILTERS = ("active", "open", "acknowledged", "closed", "all")


class CasesUnavailable(Exception):
    """The case database cannot be reached or refused the call."""


def parse_case_id(raw: str) -> str | None:
    """A canonical lower-case UUID, or None. Nothing else ever reaches the database."""
    try:
        parsed = uuid.UUID(raw)
    except ValueError:
        return None
    return str(parsed) if str(parsed) == raw.lower() else None


def fmt_time(value: Any) -> str:
    """A UTC timestamp for a person: from a datetime or the ISO text get_case returns."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return "?"
    if not isinstance(value, datetime):
        return "?"
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


class CaseDb:
    def __init__(self, url: str) -> None:
        sa = make_url(url)
        self._params: dict[str, Any] = {
            "host": sa.host,
            "port": sa.port,
            "dbname": sa.database,
            "user": sa.username,
            "password": sa.password,
            "connect_timeout": 5,
            "autocommit": True,
        }

    def _one(self, query: str, params: tuple[Any, ...]) -> Any:
        try:
            with psycopg.connect(**self._params) as conn:
                row = conn.execute(query, params).fetchone()
        except psycopg.Error as exc:
            raise CasesUnavailable from exc
        return None if row is None else row[0]

    def list_cases(self, status: str = "active", limit: int = 100) -> list[dict[str, Any]]:
        try:
            with psycopg.connect(**self._params) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM list_cases(%s, %s)", (status, limit))
                names = [d.name for d in cur.description or []]
                return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]
        except psycopg.Error as exc:
            raise CasesUnavailable from exc

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        doc = self._one("SELECT get_case(%s)", (case_id,))
        return doc if isinstance(doc, dict) else None

    def ack(self, case_id: str, login: str) -> str:
        return str(self._one("SELECT ack_case(%s, %s)", (case_id, login)))

    def close(self, case_id: str, login: str, note: str) -> str:
        return str(self._one("SELECT close_case(%s, %s, %s)", (case_id, login, note)))
