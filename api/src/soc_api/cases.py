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

# Quick-close verdicts: the stored value and what a person reads. Kept apart so tuning can
# count real false positives without our own tests and admin work. The same set is checked
# in close_case_with_verdict.
VERDICTS = {
    "test": "Our test",
    "authorized_activity": "Our admin work",
    "false_positive": "False positive",
    "duplicate": "Duplicate",
}


def verdict_label(value: Any) -> str:
    """Plain words for a stored verdict; empty for none. The raw value is never shown."""
    return VERDICTS.get(value, "") if isinstance(value, str) else ""


class CasesUnavailable(Exception):
    """The case database cannot be reached or refused the call."""


class BadFilter(Exception):
    """The overview function refused its period or client (the page validates first, so this
    is a client that does not exist)."""


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

    def pipeline_metrics(self) -> list[tuple[str, str, float]]:
        try:
            with psycopg.connect(**self._params) as conn:
                rows = conn.execute("SELECT metric, label, value FROM pipeline_metrics()")
                return [(str(m), str(label), float(v)) for m, label, v in rows.fetchall()]
        except psycopg.Error as exc:
            raise CasesUnavailable from exc

    def console_health(self) -> dict[str, Any]:
        try:
            with psycopg.connect(**self._params) as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM console_health()")
                names = [d.name for d in cur.description or []]
                row = cur.fetchone()
        except psycopg.Error as exc:
            raise CasesUnavailable from exc
        if row is None:
            raise CasesUnavailable
        return dict(zip(names, row, strict=True))

    def ops_overview(self, days: int, client: str) -> dict[str, Any]:
        """The one document behind the overview pages (migration 0012). A refusal by the
        function itself (a period or client it does not know) is BadFilter; anything else is
        CasesUnavailable, with no detail."""
        try:
            with psycopg.connect(**self._params) as conn:
                row = conn.execute("SELECT ops_overview(%s, %s)", (days, client)).fetchone()
        except psycopg.errors.RaiseException as exc:
            raise BadFilter from exc
        except psycopg.Error as exc:
            raise CasesUnavailable from exc
        if row is None or not isinstance(row[0], dict):
            raise CasesUnavailable
        return row[0]

    def rules_metrics(self, client: str) -> dict[str, Any]:
        """The Rules tab's per-rule numbers (migration 0020). Same refusals as ops_overview."""
        try:
            with psycopg.connect(**self._params) as conn:
                row = conn.execute("SELECT rules_metrics(%s)", (client,)).fetchone()
        except psycopg.errors.RaiseException as exc:
            raise BadFilter from exc
        except psycopg.Error as exc:
            raise CasesUnavailable from exc
        if row is None or not isinstance(row[0], dict):
            raise CasesUnavailable
        return row[0]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        doc = self._one("SELECT get_case(%s)", (case_id,))
        return doc if isinstance(doc, dict) else None

    def ack(self, case_id: str, login: str) -> str:
        return str(self._one("SELECT ack_case(%s, %s)", (case_id, login)))

    def close(self, case_id: str, login: str, note: str) -> str:
        return str(self._one("SELECT close_case(%s, %s, %s)", (case_id, login, note)))

    def close_with_verdict(self, case_id: str, login: str, verdict: str, note: str) -> str:
        return str(
            self._one(
                "SELECT close_case_with_verdict(%s, %s, %s, %s)", (case_id, login, verdict, note)
            )
        )
