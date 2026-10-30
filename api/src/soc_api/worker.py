"""The pager worker: alerts become cases, cases become phone pushes, and the SOC
reports on itself.

    python -m soc_api.worker            run (the compose `worker` service)
    python -m soc_api.worker ok-now     send the weekly "SOC OK" push now (a check)

One loop, three jobs, each isolated from the others' failures:

* caser: `assign_cases()` turns new alerts into cases and queues their pages.
* sender: claims due pages, pushes them to ntfy, records the outcome. At most
  `page_cap` pushes per window; the rest wait and one notice says so.
* heartbeat: a weekly "SOC OK" with counts, and a "SOC STALE" push when pages are stuck,
  the caser is behind or the catch-up worker has gone quiet.

The worker has no table privileges. Everything goes through the functions in migration
0002/0003, which never hand back the raw payload. What crosses ntfy's servers (a third
party) is a title, a host name, a time and a case id, built from sanitised database
fields and sent as JSON, never as HTTP headers. The topic is the only secret in a push;
it is never logged and never part of an error code.
"""

import argparse
import http.client
import json
import logging
import re
import signal
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import psycopg
from sqlalchemy.engine import make_url

from soc_api import csrf
from soc_api.cases import parse_case_id
from soc_api.config import Settings, get_settings
from soc_api.logs import configure_logging
from soc_api.text import LC_LINK_PREFIX, clean, safe_link

__all__ = ["LC_LINK_PREFIX", "clean", "safe_link"]  # re-exported for callers and tests

log = logging.getLogger("soc_api.worker")

EASTERN = ZoneInfo("America/New_York")
# A claim is a two-minute lease (migration 0002). One send, with its timeout, must
# finish far inside that, or a slow send could be claimed and pushed a second time.
NTFY_TIMEOUT_SECONDS = 10.0
LATE_AFTER_S = 300.0  # an alert received this long after it was detected is "LATE"
TOPIC_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")

# Only plain HTTP(S): no file:// or ftp:// handler, no redirects, no proxy from the
# environment. The topic is in the request body, so a redirect must never be followed.
_OPENER = urllib.request.OpenerDirector()
for _handler in (
    urllib.request.HTTPHandler(),
    urllib.request.HTTPSHandler(),
    urllib.request.HTTPDefaultErrorHandler(),
    urllib.request.HTTPErrorProcessor(),
    urllib.request.UnknownHandler(),
):
    _OPENER.add_handler(_handler)


# ---- text that crosses ntfy ----


def push_text(
    page: dict[str, Any], late_after_s: float = LATE_AFTER_S
) -> tuple[str, str, int, str | None]:
    """(title, message, ntfy priority, click) for a claimed page.

    "LATE:" marks a first page whose alert reached us long after it was detected (the
    catch-up path after an outage); a re-send says REPEAT instead."""
    rule = re.sub(r"^general\.", "", page.get("rule") or "") or "alert"
    again = "REPEAT: " if page.get("kind") in ("repage1", "repage2") else ""
    lateness = page.get("late_s")
    is_late = (
        not again
        and isinstance(lateness, int | float)
        and not isinstance(lateness, bool)
        and lateness > late_after_s
    )
    title = clean(f"{again}{'LATE: ' if is_late else ''}{page['client_slug']}: {rule}", 80)
    detected = page.get("detected_at")
    when = f"{detected.astimezone(EASTERN):%H:%M} ET" if isinstance(detected, datetime) else "?"
    host = clean(page.get("host"), 64) or "unknown"
    message = clean(f"host {host} · {when} · case {page.get('case_short') or '?'}", 200)
    priority = page.get("priority")
    prio = (
        priority
        if isinstance(priority, int) and not isinstance(priority, bool) and 1 <= priority <= 5
        else 3
    )
    return title, message, prio, safe_link(page.get("link"))


def push_links(
    page: dict[str, Any], base_url: str, ack_key: str, now: datetime
) -> tuple[str | None, list[dict[str, Any]]]:
    """The tap target and the buttons of a push. With the console's address set, a tap opens
    the case page, LimaCharlie becomes a button, and (with the key) so does Acknowledge. The
    vetted LimaCharlie link stays the tap target otherwise."""
    lc = safe_link(page.get("link"))
    case_id = parse_case_id(str(page.get("case_id") or ""))
    if not base_url or case_id is None:
        return lc, []
    actions: list[dict[str, Any]] = []
    if lc:
        actions.append({"action": "view", "label": "LimaCharlie", "url": lc})
    if ack_key:
        expires = csrf.phone_expiry(now)
        token = csrf.make_phone_token(ack_key, case_id, expires)
        url = f"{base_url}/console/case/{case_id}/ack-phone?e={expires}&t={token}"
        actions.append(
            {"action": "http", "label": "Ack", "url": url, "method": "POST", "clear": True}
        )
    return f"{base_url}/console/case/{case_id}", actions


def parse_policy(raw: str) -> dict[str, int]:
    """{"category": 0-5}; anything else is ignored (the severity default applies)."""
    if not raw.strip():
        return {}
    try:
        doc = json.loads(raw)
    except ValueError:
        log.error("policy outcome=unreadable")
        return {}
    if not isinstance(doc, dict):
        log.error("policy outcome=not_an_object")
        return {}
    policy = {
        k: v
        for k, v in doc.items()
        if isinstance(k, str)
        and 0 < len(k) <= 128
        and isinstance(v, int)
        and not isinstance(v, bool)
        and 0 <= v <= 5
    }
    if len(policy) != len(doc):
        log.warning("policy outcome=entries_ignored count=%d", len(doc) - len(policy))
    return policy


# ---- ntfy ----


@dataclass(frozen=True)
class Delivery:
    outcome: str  # sent | retry | fail
    code: str  # short lowercase code, safe to store and log


def classify(status: int) -> Delivery:
    if 200 <= status < 300:
        return Delivery("sent", f"http_{status}")
    if status == 429 or status >= 500:
        return Delivery("retry", f"http_{status}")
    if 300 <= status < 400:
        return Delivery("fail", "redirect")
    return Delivery("fail", f"http_{status}")


class Ntfy:
    """Publish by JSON to the server's root URL. https only (http for local tests)."""

    def __init__(
        self,
        server: str,
        topic: str,
        *,
        timeout: float = NTFY_TIMEOUT_SECONDS,
        allow_http: bool = False,
    ) -> None:
        if not TOPIC_RE.fullmatch(topic):
            raise ValueError("the ntfy topic must be 16-64 letters, digits, - or _")
        parts = urlsplit(server)
        scheme_ok = parts.scheme == "https" or (parts.scheme == "http" and allow_http)
        if not scheme_ok or not parts.hostname or parts.username or parts.password:
            raise ValueError("SOC_NTFY_SERVER must be https://host (no credentials)")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ValueError("SOC_NTFY_SERVER must be a bare host, with no path")
        self._url = f"{parts.scheme}://{parts.netloc}/"
        self._topic = topic
        self._timeout = timeout

    def publish(
        self,
        *,
        title: str,
        message: str,
        priority: int,
        click: str | None = None,
        actions: list[dict[str, Any]] | None = None,
    ) -> Delivery:
        doc: dict[str, Any] = {
            "topic": self._topic,
            "title": title,
            "message": message,
            "priority": priority,
        }
        if click:
            doc["click"] = click
        if actions:
            doc["actions"] = actions
        request = urllib.request.Request(  # noqa: S310 - the opener only speaks HTTP(S)
            self._url,
            data=json.dumps(doc).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with _OPENER.open(request, timeout=self._timeout) as response:
                return classify(response.status)
        except urllib.error.HTTPError as exc:
            return classify(exc.code)
        except TimeoutError:
            return Delivery("retry", "timeout")
        except (OSError, http.client.HTTPException):
            return Delivery("retry", "unreachable")


# ---- the database, through the worker functions only ----


class Db:
    def __init__(self, url: str) -> None:
        sa = make_url(url)
        self._params: dict[str, Any] = {
            "host": sa.host,
            "port": sa.port,
            "dbname": sa.database,
            "user": sa.username,
            "password": sa.password,
            "connect_timeout": 10,
            "autocommit": True,
        }
        self._conn: psycopg.Connection | None = None

    def _run(self, query: str, params: tuple[Any, ...] = ()) -> tuple[list[str], list[Any]]:
        try:
            if self._conn is None or self._conn.closed:
                self._conn = psycopg.connect(**self._params)
            cur = self._conn.execute(query, params)
            names = [d.name for d in cur.description or []]
            return names, cur.fetchall() if cur.description else []
        except psycopg.Error:
            self.close()
            raise

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except psycopg.Error:
                pass
            self._conn = None

    def assign_cases(self, batch: int, policy: dict[str, int]) -> tuple[int, int, int]:
        _, rows = self._run(
            "SELECT * FROM assign_cases(%s, %s::jsonb)", (batch, json.dumps(policy))
        )
        return int(rows[0][0]), int(rows[0][1]), int(rows[0][2])

    def claim_pages(self, batch: int) -> list[dict[str, Any]]:
        names, rows = self._run("SELECT * FROM claim_pages(%s)", (batch,))
        return [dict(zip(names, row, strict=True)) for row in rows]

    def finish_page(self, page_id: Any, outcome: str, code: str) -> str:
        _, rows = self._run("SELECT finish_page(%s, %s, %s)", (page_id, outcome, code))
        return str(rows[0][0])

    def queue_repages(self, first_s: float, second_s: float) -> int:
        _, rows = self._run(
            "SELECT queue_repages(make_interval(secs => %s), make_interval(secs => %s))",
            (first_s, second_s),
        )
        return int(rows[0][0])

    def reconcile_health(self) -> tuple[int, float | None]:
        """(sources with a catch-up cursor, longest seconds any has gone without a good run)."""
        _, rows = self._run("SELECT sources, quiet_s FROM reconcile_health()")
        quiet = rows[0][1]
        return int(rows[0][0]), None if quiet is None else float(quiet)

    def due_page_count(self) -> int:
        _, rows = self._run("SELECT due_page_count()")
        return int(rows[0][0])

    def heartbeat_counts(self, since: datetime) -> dict[str, Any]:
        names, rows = self._run("SELECT * FROM heartbeat_counts(%s)", (since,))
        return dict(zip(names, rows[0], strict=True))

    def state_get(self, key: str) -> str | None:
        _, rows = self._run("SELECT worker_state_get(%s)", (key,))
        return None if rows[0][0] is None else str(rows[0][0])

    def state_set(self, key: str, value: str) -> None:
        self._run("SELECT worker_state_set(%s, %s)", (key, value))


# ---- schedule ----


def last_weekly_slot(now: datetime) -> datetime:
    """The most recent Sunday 18:00 Eastern at or before `now`, in UTC."""
    local = now.astimezone(EASTERN)
    slot = (local - timedelta(days=(local.weekday() - 6) % 7)).replace(
        hour=18, minute=0, second=0, microsecond=0
    )
    if slot > local:
        slot -= timedelta(days=7)
    return slot.astimezone(UTC)


@dataclass(frozen=True)
class Limits:
    case_batch: int = 100
    page_batch: int = 10
    page_cap: int = 10
    cap_window_s: float = 600.0
    stale_after_s: int = 600
    stale_repeat_s: float = 6 * 3600.0
    repage_first_s: float = 900.0
    repage_second_s: float = 3600.0
    stale_check_s: float = 300.0
    reconcile_stale_s: float = 1800.0  # the catch-up worker runs every few minutes
    late_after_s: float = LATE_AFTER_S
    retry_notice_s: float = 60.0  # between tries of a notice that could not be sent


STALE_TEXT = {
    "pages_pending": "A page has been waiting to go out for over 10 minutes.",
    "page_failed": "A page failed to send in the last 24 hours.",
    "caser_behind": "New alerts are not becoming cases (over 10 minutes behind).",
    "db_unreachable": "The pager cannot reach its database (over 10 minutes).",
    "reconcile_quiet": "The catch-up worker has not completed a run in over 30 minutes.",
}


class Worker:
    def __init__(
        self,
        db: Db,
        ntfy: Ntfy,
        policy: dict[str, int],
        *,
        limits: Limits | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        health_file: str | None = None,
        console_base_url: str = "",
        ack_key: str = "",
    ) -> None:
        self.console_base_url = console_base_url
        self.ack_key = ack_key
        self.db = db
        self.ntfy = ntfy
        self.policy = policy
        self.limits = limits or Limits()
        self.clock = clock
        self.health_file = health_file
        self._sends: deque[datetime] = deque()
        self._held_at: datetime | None = None
        self._next_stale_check: datetime | None = None
        self._tried: dict[str, datetime] = {}
        self._db_down_since: datetime | None = None
        self._db_stale_at: datetime | None = None

    # one pass; True when no phase hit a database error
    def tick(self) -> bool:
        ok = True
        for name, phase in (
            ("caser", self._caser),
            ("repages", self._repages),
            ("sender", self._sender),
            ("heartbeat", self._heartbeat),
        ):
            try:
                phase()
            except psycopg.Error as exc:
                log.error("phase=%s outcome=db_error kind=%s", name, type(exc).__name__)
                ok = False
        if ok and self.health_file:
            try:
                Path(self.health_file).touch()
            except OSError:
                log.error("health outcome=cannot_write")
        self._watch_database(ok)
        return ok

    def _watch_database(self, ok: bool) -> None:
        """Every other STALE check needs the database. When it is the database that is
        gone, nothing would page at all, so say so straight to the push server. The
        repeat guard lives in memory: the database cannot hold it."""
        now = self.clock()
        if ok:
            self._db_down_since = None
            return
        if self._db_down_since is None:
            self._db_down_since = now
        down_for = (now - self._db_down_since).total_seconds()
        if down_for <= self.limits.stale_after_s:
            return
        if (
            self._db_stale_at
            and (now - self._db_stale_at).total_seconds() < self.limits.stale_repeat_s
        ):
            return
        if not self._may_try("stale_db_unreachable", now):
            return
        delivery = self.ntfy.publish(
            title="SOC STALE", message=STALE_TEXT["db_unreachable"], priority=5
        )
        log.warning(
            "heartbeat kind=stale reason=db_unreachable outcome=%s code=%s",
            delivery.outcome,
            delivery.code,
        )
        if delivery.outcome == "sent":
            self._db_stale_at = now

    # ---- caser ----

    def _caser(self) -> None:
        while True:
            alerts, cases, pages = self.db.assign_cases(self.limits.case_batch, self.policy)
            if alerts:
                log.info("caser alerts=%d cases=%d pages=%d", alerts, cases, pages)
            if alerts < self.limits.case_batch:
                return

    # ---- re-sends of urgent pages nobody acknowledged ----

    def _repages(self) -> None:
        queued = self.db.queue_repages(self.limits.repage_first_s, self.limits.repage_second_s)
        if queued:
            log.info("repages queued=%d", queued)

    # ---- sender ----

    def _room(self, now: datetime) -> int:
        while self._sends and (now - self._sends[0]).total_seconds() >= self.limits.cap_window_s:
            self._sends.popleft()
        return self.limits.page_cap - len(self._sends)

    def _sender(self) -> None:
        room = self._room(self.clock())
        if room > 0:
            for page in self.db.claim_pages(min(self.limits.page_batch, room)):
                self._send_page(page)
        self._held_notice()

    def _send_page(self, page: dict[str, Any]) -> None:
        try:
            title, message, priority, _ = push_text(page, self.limits.late_after_s)
        except (KeyError, TypeError, ValueError, AttributeError):
            # A page that cannot be described must not crash-loop the worker.
            self.db.finish_page(page["id"], "fail", "bad_page")
            log.error("page outcome=fail code=bad_page id=%s", str(page["id"])[:8])
            return
        now = self.clock()
        click, actions = push_links(page, self.console_base_url, self.ack_key, now)
        self._sends.append(now)
        delivery = self.ntfy.publish(
            title=title, message=message, priority=priority, click=click, actions=actions
        )
        code = delivery.code  # from classify(): a short lowercase code
        self.db.finish_page(page["id"], delivery.outcome, code)
        log.info(
            "page outcome=%s code=%s priority=%d attempts=%d id=%s",
            delivery.outcome,
            code,
            priority,
            page["attempts"],
            str(page["id"])[:8],
        )

    def _held_notice(self) -> None:
        now = self.clock()
        if self._room(now) > 0:
            return
        waiting = self.db.due_page_count()
        if waiting < 1:
            return
        if self._held_at and (now - self._held_at).total_seconds() < self.limits.cap_window_s:
            return
        if not self._may_try("held", now):
            return
        delivery = self.ntfy.publish(
            title="SOC: pages held",
            message=(
                f"{waiting} more pages are waiting (limit {self.limits.page_cap} per "
                f"{int(self.limits.cap_window_s // 60)} min). Check the detection email."
            ),
            priority=3,
        )
        log.info("notice kind=held outcome=%s code=%s", delivery.outcome, delivery.code)
        if delivery.outcome == "sent":
            self._held_at = now

    def _may_try(self, kind: str, now: datetime) -> bool:
        last = self._tried.get(kind)
        if last and (now - last).total_seconds() < self.limits.retry_notice_s:
            return False
        self._tried[kind] = now
        return True

    # ---- heartbeat ----

    def _heartbeat(self) -> None:
        now = self.clock()
        self._weekly_ok(now)
        if self._next_stale_check is None or now >= self._next_stale_check:
            self._next_stale_check = now + timedelta(seconds=self.limits.stale_check_s)
            self._stale(now)

    def ok_message(self, since: datetime) -> str:
        c = self.db.heartbeat_counts(since)
        return (
            f"7d: {c['alerts_received']} alerts, {c['cases_opened']} cases, "
            f"{c['pages_sent']} pages sent, {c['pages_failed']} failed"
        )

    def send_ok(self, since: datetime) -> Delivery:
        return self.ntfy.publish(title="SOC OK", message=self.ok_message(since), priority=2)

    def _weekly_ok(self, now: datetime) -> None:
        due = last_weekly_slot(now)
        recorded = self.db.state_get("weekly_ok")
        try:
            last = datetime.fromisoformat(recorded) if recorded else None
        except ValueError:
            last = None
        if last is None:
            # First run: start counting from this slot instead of announcing at once.
            self.db.state_set("weekly_ok", due.isoformat())
            log.info("heartbeat kind=ok outcome=armed")
            return
        if last >= due or not self._may_try("ok", now):
            return
        delivery = self.send_ok(due - timedelta(days=7))
        log.info("heartbeat kind=ok outcome=%s code=%s", delivery.outcome, delivery.code)
        if delivery.outcome == "sent":
            self.db.state_set("weekly_ok", due.isoformat())

    def _stale(self, now: datetime) -> None:
        c = self.db.heartbeat_counts(now)
        sources, quiet = self.db.reconcile_health()
        after = self.limits.stale_after_s
        firing = {
            "pages_pending": (c["oldest_pending_page_s"] or 0) > after,
            "page_failed": (c["failed_last_24h"] or 0) > 0,
            "caser_behind": (c["oldest_unassigned_alert_s"] or 0) > after,
            "reconcile_quiet": sources > 0 and (quiet or 0) > self.limits.reconcile_stale_s,
        }
        for reason, is_firing in firing.items():
            if not is_firing:
                continue
            recorded = self.db.state_get(f"stale_{reason}")
            try:
                last = datetime.fromisoformat(recorded) if recorded else None
            except ValueError:
                last = None
            if last and (now - last).total_seconds() < self.limits.stale_repeat_s:
                continue
            if not self._may_try(f"stale_{reason}", now):
                continue
            delivery = self.ntfy.publish(title="SOC STALE", message=STALE_TEXT[reason], priority=5)
            log.warning(
                "heartbeat kind=stale reason=%s outcome=%s code=%s",
                reason,
                delivery.outcome,
                delivery.code,
            )
            if delivery.outcome == "sent":
                self.db.state_set(f"stale_{reason}", now.isoformat())

    # ---- the loop ----

    def run(
        self,
        stop: Callable[[], bool],
        tick_seconds: float,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        while not stop():
            self.tick()
            sleep(tick_seconds)


def build(settings: Settings) -> tuple[Db, Ntfy, dict[str, int]]:
    url = settings.worker_database_url.get_secret_value()
    topic = settings.ntfy_topic.get_secret_value()
    if not url or not topic:
        raise ValueError("the worker is not configured (worker.env: topic and database URL)")
    ntfy = Ntfy(settings.ntfy_server, topic, allow_http=settings.env == "dev")
    return Db(url), ntfy, parse_policy(settings.page_policy)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m soc_api.worker")
    parser.add_argument("command", nargs="?", default="run", choices=["run", "ok-now"])
    args = parser.parse_args(argv)
    configure_logging()
    settings = get_settings()
    try:
        db, ntfy, policy = build(settings)
    except ValueError as exc:
        print(exc)  # never echoes a value: the messages above name the setting only
        return 2
    limits = Limits(
        page_cap=settings.page_cap,
        cap_window_s=float(settings.page_cap_window_seconds),
        repage_first_s=float(settings.repage_first_seconds),
        repage_second_s=float(settings.repage_second_seconds),
    )
    worker = Worker(
        db,
        ntfy,
        policy,
        limits=limits,
        health_file=settings.health_file,
        console_base_url=settings.console_base_url,
        ack_key=settings.ack_key.get_secret_value(),
    )
    if args.command == "ok-now":
        try:
            delivery = worker.send_ok(datetime.now(UTC) - timedelta(days=7))
        except psycopg.Error as exc:
            print(f"database error: {type(exc).__name__}")
            return 1
        finally:
            db.close()
        print(f"ok push: {delivery.outcome} ({delivery.code})")
        return 0 if delivery.outcome == "sent" else 1

    stopping = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    log.info("worker outcome=started policy_entries=%d", len(policy))
    worker.run(lambda: stopping, settings.worker_tick_seconds)
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
