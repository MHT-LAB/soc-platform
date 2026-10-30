"""The catch-up (reconcile) worker: detections the webhook never delivered.

    python -m soc_api.reconcile            run (the compose `reconcile` service)
    python -m soc_api.reconcile once       one pass, print the result line, exit
    python -m soc_api.reconcile check      read-only look at the vendor API (counts only)

The detection source's webhook gives up after a few fast retries, so any outage of ours
loses alerts, and after a failure it also skips new ones for a while. This service closes
that gap: every few minutes it asks the source's API for the detections of a time window
and feeds each one through exactly the path a webhook delivery takes (`normalize()` and
`ingest_alert()`, which de-duplicates on the detection id), so a detection both paths
deliver is stored once, whichever came first. Late alerts then page normally, titled LATE.

* Windows: from the cursor minus ten minutes of overlap to a minute ago, cut into hours.
  The cursor (the database keeps it, per source) moves only after a window was fetched
  completely and every kept detection stored; any error leaves it where it was and records
  a short failure code, so the pager's STALE check notices a service that stops making
  progress. Nothing older than a day is fetched, and a first start looks back one hour.
* Only the categories the webhook output sends are kept (SOC_RECONCILE_CATEGORIES).
* The list endpoint gives a summary; a detection that lacks the rule name, the detection
  time or the priority is fetched whole by id first, so a caught-up alert looks like a
  webhook one (same rule, so it groups into the same case).
* The vendor API key is read-only, held only by this container, and never logged: every
  failure here is a short code. The responses are data: size-capped, parsed as JSON,
  cleaned like a webhook body, never executed. https only, no redirects, timeouts.

The database role (soc_reconcile) can call ingest_alert() and the cursor functions and
nothing else.
"""

import argparse
import base64
import binascii
import http.client
import json
import logging
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg

from soc_api.config import Settings, get_settings
from soc_api.ingest import PgStore, StoreUnavailable, normalize
from soc_api.ingest import _clean as clean_doc  # the webhook route cleans the same way
from soc_api.ingest import _reject_constant as reject_constant
from soc_api.logs import configure_logging
from soc_api.worker import Db

log = logging.getLogger("soc_api.reconcile")

OID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SOURCE_RE = re.compile(r"[a-z0-9-]{1,32}")
CATEGORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
DETECT_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,256}")
JWT_RE = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){0,3}")
MAX_CATEGORIES = 50
# A page of detections, and what one decompresses to; the token reply.
MAX_BODY = 8 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
MAX_TOKEN_BODY = 16 * 1024
MAX_TOKEN = 8192
MAX_CURSOR = 2048
TOKEN_REFRESH_S = 45 * 60  # the token lives about an hour
FULL_RECORD_KEYS = ("source_rule", "gen_time", "priority")  # a webhook body has them all
SUMMARY_KEYS = ("detect_id", "cat", "source_rule", "gen_time", "priority", "link", "namespace")


# ---- the vendor API ----


class LcError(Exception):
    """A failure talking to the vendor API; `code` is short, lowercase and safe to log."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_OPENER = urllib.request.OpenerDirector()
for _handler in (
    urllib.request.HTTPHandler(),
    urllib.request.HTTPSHandler(),
    urllib.request.HTTPDefaultErrorHandler(),
    urllib.request.HTTPErrorProcessor(),
    urllib.request.UnknownHandler(),
):
    _OPENER.add_handler(_handler)  # no redirect handler: a 3xx is an error, never followed


def _http_code(status: int) -> str:
    if 300 <= status < 400:
        return "redirect"
    if status in (400, 401, 403, 404, 408, 429):
        return f"http_{status}"
    return "http_4xx" if 400 <= status < 500 else "http_5xx"


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw, parse_constant=reject_constant)
    except (ValueError, RecursionError):
        raise LcError("bad_json") from None


def unwrap(detects: Any) -> list[Any]:
    """The `detects` of a list reply: a list, or base64(gzip(JSON list)) with a size cap."""
    if detects is None or detects == "":
        return []
    if isinstance(detects, list):
        return detects
    if not isinstance(detects, str):
        raise LcError("bad_shape")
    try:
        packed = base64.b64decode(detects, validate=True)
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        data = inflater.decompress(packed, MAX_UNPACKED + 1)
    except (binascii.Error, zlib.error, ValueError):
        raise LcError("bad_payload") from None
    if len(data) > MAX_UNPACKED or inflater.unconsumed_tail:
        raise LcError("too_large")
    parsed = _json(data)
    if not isinstance(parsed, list):
        raise LcError("bad_shape")
    return parsed


def extract_record(resp: Any, detect_id: str) -> tuple[dict[str, Any], str]:
    """The detection inside a by-id reply, and where it was found.

    The reply wraps the record (one level or two, depending on the endpoint's version);
    whichever dict carries the requested id is the record. Anything else is a shape we
    do not know, which is an error, not a guess."""
    candidates: list[tuple[str, Any]] = [("top", resp)]
    for outer in ("detection", "detect", "event"):
        if isinstance(resp, dict) and isinstance(resp.get(outer), dict):
            candidates.append((outer, resp[outer]))
            if isinstance(resp[outer].get("event"), dict):
                candidates.append((f"{outer}.event", resp[outer]["event"]))
    for where, candidate in candidates:
        if isinstance(candidate, dict) and candidate.get("detect_id") == detect_id:
            return candidate, where
    raise LcError("bad_shape")


class LcClient:
    """Just enough of the vendor's REST API: a token for the key, a list of detections for
    a time window, and one detection by id."""

    def __init__(
        self,
        oid: str,
        key: str,
        *,
        api_url: str = "https://api.limacharlie.io",
        jwt_url: str = "https://jwt.limacharlie.io",
        allow_http: bool = False,
        timeout: float = 20.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not OID_RE.fullmatch(oid):
            raise ValueError("the organization id is malformed")
        self.oid = oid
        self._key = key
        self.api_url = api_url.rstrip("/")
        self.jwt_url = jwt_url
        self.allow_http = allow_http
        self.timeout = timeout
        self._clock = clock
        self._jwt: str | None = None
        self._jwt_at = 0.0

    def _fetch(
        self,
        method: str,
        url: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        max_bytes = MAX_BODY if max_bytes is None else max_bytes
        scheme = urllib.parse.urlsplit(url).scheme
        if scheme != "https" and not (self.allow_http and scheme == "http"):
            raise LcError("bad_url")
        request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)  # noqa: S310 - scheme checked above
        try:
            with _OPENER.open(request, timeout=self.timeout) as resp:
                raw: bytes = resp.read(max_bytes + 1)
        except urllib.error.HTTPError as exc:
            exc.close()  # the error is also an open response; release its socket
            raise LcError(_http_code(exc.code)) from None
        except urllib.error.URLError as exc:
            raise LcError(
                "timeout" if isinstance(exc.reason, TimeoutError) else "network"
            ) from None
        except TimeoutError:
            raise LcError("timeout") from None
        except (OSError, http.client.HTTPException):
            raise LcError("network") from None
        if len(raw) > max_bytes:
            raise LcError("too_large")
        return raw

    def _refresh(self) -> None:
        body = urllib.parse.urlencode({"oid": self.oid, "secret": self._key}).encode()
        try:
            raw = self._fetch(
                "POST",
                self.jwt_url,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                max_bytes=MAX_TOKEN_BODY,
            )
        except LcError as exc:
            raise LcError(f"jwt_{exc.code}") from None
        doc = _json(raw)
        token = doc.get("jwt") if isinstance(doc, dict) else None
        if not isinstance(token, str) or len(token) > MAX_TOKEN or not JWT_RE.fullmatch(token):
            raise LcError("jwt_bad_shape")  # it goes into a header: nothing but token characters
        self._jwt, self._jwt_at = token, self._clock()

    def _get(self, path: str, query: dict[str, str]) -> Any:
        url = f"{self.api_url}/v1/{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        for attempt in (0, 1):
            if self._jwt is None or self._clock() - self._jwt_at > TOKEN_REFRESH_S:
                self._refresh()
            try:
                raw = self._fetch(
                    "GET",
                    url,
                    headers={"Authorization": f"Bearer {self._jwt}", "Accept": "application/json"},
                )
            except LcError as exc:
                if exc.code == "http_401" and attempt == 0:
                    self._jwt = None  # expired or revoked early: one new token, one retry
                    continue
                raise
            return _json(raw)
        raise LcError("http_401")  # not reached

    def list_detections(
        self, start: int, end: int, *, max_pages: int, max_items: int
    ) -> Iterator[Any]:
        """Every item of every page for [start, end] (epoch seconds), unfiltered."""
        cursor, seen, items = "-", set[str](), 0
        for _ in range(max_pages):
            query = {
                "start": str(start),
                "end": str(end),
                "cursor": cursor,
                "is_compressed": "true",
            }
            resp = self._get(f"insight/{self.oid}/detections", query)
            if not isinstance(resp, dict):
                raise LcError("bad_shape")
            for item in unwrap(resp.get("detects")):
                items += 1
                if items > max_items:
                    raise LcError("too_many_items")
                yield item
            nxt = resp.get("next_cursor")
            if not isinstance(nxt, str) or not nxt:
                return
            if len(nxt) > MAX_CURSOR or nxt == cursor or nxt in seen:
                raise LcError("bad_cursor")
            seen.add(cursor)
            cursor = nxt
        raise LcError("too_many_pages")

    def get_detection(self, detect_id: str) -> tuple[dict[str, Any], str] | None:
        """The whole record of one detection and where in the reply it was; None if the
        source no longer has it (or the id is not a plain identifier)."""
        if not DETECT_ID_RE.fullmatch(detect_id):
            return None
        try:
            resp = self._get(f"insight/{self.oid}/detections/{urllib.parse.quote(detect_id)}", {})
        except LcError as exc:
            if exc.code == "http_404":
                return None
            raise
        return extract_record(resp, detect_id)


# ---- configuration ----


def parse_categories(raw: str) -> tuple[str, ...]:
    names = tuple(dict.fromkeys(n.strip() for n in raw.split(",") if n.strip()))
    if not names or len(names) > MAX_CATEGORIES:
        raise ValueError(f"SOC_RECONCILE_CATEGORIES must list 1-{MAX_CATEGORIES} categories")
    if not all(CATEGORY_RE.fullmatch(n) for n in names):
        raise ValueError("SOC_RECONCILE_CATEGORIES has a malformed category name")
    return names


def _service_url(setting: str, value: str, allow_http: bool) -> str:
    parts = urllib.parse.urlsplit(value)
    ok_scheme = parts.scheme == "https" or (allow_http and parts.scheme == "http")
    if (
        not ok_scheme
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise ValueError(f"{setting} must be a bare https address")
    return value.rstrip("/")


@dataclass(frozen=True)
class Config:
    oid: str
    key: str
    source: str
    categories: tuple[str, ...]
    db_url: str
    api_url: str
    jwt_url: str
    allow_http: bool
    interval_s: float
    first_lookback_s: int
    health_file: str

    @staticmethod
    def from_settings(s: Settings, *, need_db: bool = True) -> "Config":
        """Everything the service needs, or a ValueError that names a setting (never a value)."""
        key = s.reconcile_lc_key.get_secret_value()
        db_url = s.reconcile_database_url.get_secret_value()
        if not key:
            raise ValueError("SOC_RECONCILE_LC_KEY is missing (env/reconcile-lc.env)")
        if not OID_RE.fullmatch(s.reconcile_lc_oid):
            raise ValueError("SOC_RECONCILE_LC_OID is missing or malformed (env/reconcile-lc.env)")
        if not SOURCE_RE.fullmatch(s.reconcile_source):
            raise ValueError("SOC_RECONCILE_SOURCE is missing or malformed (env/reconcile-lc.env)")
        if need_db and not db_url:
            raise ValueError("SOC_RECONCILE_DATABASE_URL is missing (env/reconcile-db.env)")
        allow_http = s.env == "dev"
        return Config(
            oid=s.reconcile_lc_oid,
            key=key,
            source=s.reconcile_source,
            categories=parse_categories(s.reconcile_categories),
            db_url=db_url,
            api_url=_service_url("SOC_RECONCILE_API_URL", s.reconcile_api_url, allow_http),
            jwt_url=_service_url("SOC_RECONCILE_JWT_URL", s.reconcile_jwt_url, allow_http),
            allow_http=allow_http,
            interval_s=s.reconcile_interval_seconds,
            first_lookback_s=s.reconcile_first_lookback_seconds,
            health_file=s.reconcile_health_file,
        )

    def client(self) -> LcClient:
        return LcClient(
            self.oid,
            self.key,
            api_url=self.api_url,
            jwt_url=self.jwt_url,
            allow_http=self.allow_http,
        )


# ---- the database side ----


class CursorDb(Db):
    """The three cursor functions, as soc_reconcile."""

    def get(self, source: str) -> datetime | None:
        _, rows = self._run("SELECT reconcile_cursor_get(%s)", (source,))
        return rows[0][0]  # type: ignore[no-any-return]

    def advance(self, source: str, when: datetime) -> None:
        self._run("SELECT reconcile_cursor_advance(%s, %s)", (source, when))

    def fail(self, source: str, code: str) -> None:
        self._run("SELECT reconcile_cursor_fail(%s, %s)", (source, code))


# ---- the service ----


@dataclass(frozen=True)
class Limits:
    overlap_s: int = 600  # each run re-reads this much before the cursor
    lag_s: int = 60  # the newest minute is left to the webhook
    chunk_s: int = 3600  # a window; the cursor moves after each
    chunk_overlap_s: int = 5  # neighbouring windows share their edge
    max_lookback_s: int = 86400
    max_windows: int = 8  # per run; a longer gap takes a few runs
    max_pages: int = 50
    max_items: int = 5000  # per window
    max_enrich: int = 200  # whole-record fetches per run
    done_cache: int = 5000  # detection ids already handled, so overlaps cost nothing


@dataclass
class Counts:
    windows: int = 0
    listed: int = 0
    kept: int = 0
    inserted: int = 0
    duplicate: int = 0
    skipped: int = 0
    malformed: int = 0
    enriched: int = 0
    degraded: int = 0

    def line(self) -> str:
        return " ".join(f"{k}={v}" for k, v in vars(self).items())


class Reconciler:
    def __init__(
        self,
        lc: LcClient,
        store: PgStore,
        cursor: CursorDb,
        *,
        source: str,
        categories: tuple[str, ...],
        first_lookback_s: int = 3600,
        interval_s: float = 300.0,
        limits: Limits | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        health_file: str | None = None,
    ) -> None:
        self.lc = lc
        self.store = store
        self.cursor = cursor
        self.source = source
        self.categories = frozenset(categories)
        self.first_lookback_s = first_lookback_s
        self.interval_s = interval_s
        self.limits = limits or Limits()
        self.clock = clock
        self.health_file = health_file
        self.counts = Counts()
        self._done: OrderedDict[str, None] = OrderedDict()

    # -- planning --

    def plan(self, now: datetime, cursor: datetime | None) -> list[tuple[int, int]]:
        lim = self.limits
        end = int((now - timedelta(seconds=lim.lag_s)).timestamp())
        if cursor is None:
            start = end - self.first_lookback_s
        else:
            start = int(cursor.timestamp()) - lim.overlap_s
            floor = int(now.timestamp()) - lim.max_lookback_s
            if start < floor:
                log.warning(
                    "reconcile gap seconds=%d fetched=%d", floor - start, lim.max_lookback_s
                )
                start = floor
        windows: list[tuple[int, int]] = []
        if start >= end:
            return windows
        a = start
        while len(windows) < lim.max_windows:
            b = min(a + lim.chunk_s, end)
            windows.append((a, b))
            if b >= end:
                break
            a = b - lim.chunk_overlap_s
        return windows

    # -- one pass --

    def run_once(self) -> Counts:
        self.counts = Counts()
        now = self.clock()
        for a, b in self.plan(now, self.cursor.get(self.source)):
            self._window(a, b)
            self.cursor.advance(self.source, datetime.fromtimestamp(b, UTC))
            self.counts.windows += 1
        return self.counts

    def _remember(self, detect_id: str) -> None:
        self._done[detect_id] = None
        while len(self._done) > self.limits.done_cache:
            self._done.popitem(last=False)

    def _window(self, start: int, end: int) -> None:
        c, lim = self.counts, self.limits
        incomplete: str | None = None
        items = self.lc.list_detections(
            start, end, max_pages=lim.max_pages, max_items=lim.max_items
        )
        for item in items:
            c.listed += 1
            if not isinstance(item, dict):
                c.malformed += 1
                continue
            category, detect_id = item.get("cat"), item.get("detect_id")
            if not isinstance(category, str) or category not in self.categories:
                c.skipped += 1
                continue
            if not isinstance(detect_id, str) or not DETECT_ID_RE.fullmatch(detect_id):
                c.malformed += 1
                continue
            c.kept += 1
            if detect_id in self._done:
                c.duplicate += 1
                continue
            doc = item
            if any(k not in item for k in FULL_RECORD_KEYS):
                if c.enriched >= lim.max_enrich:
                    incomplete = "enrich_limit"
                    continue
                try:
                    found = self.lc.get_detection(detect_id)
                except LcError as exc:
                    incomplete = incomplete or exc.code  # retried next run; keep going
                    continue
                if found is None:
                    c.degraded += 1  # the source no longer has it: store what the list gave
                else:
                    doc = found[0]
                    c.enriched += 1
            self._store(doc, detect_id)
        if incomplete:
            raise LcError(incomplete)

    def _store(self, doc: dict[str, Any], detect_id: str) -> None:
        c = self.counts
        try:
            cleaned = clean_doc(doc)
            body = json.dumps(cleaned, separators=(",", ":")).encode()
            result = self.store.insert(self.source, normalize(cleaned, body))
        except (ValueError, TypeError, RecursionError):
            c.malformed += 1
            self._remember(detect_id)
            return
        if result == "inserted":
            c.inserted += 1
        elif result == "duplicate":
            c.duplicate += 1
        elif result == "unknown_source":
            raise LcError("unknown_source")
        else:  # invalid_payload, invalid_event_id: permanent, not worth another try
            c.malformed += 1
        self._remember(detect_id)

    # -- the loop --

    def _touch_health(self) -> None:
        if self.health_file:
            try:
                Path(self.health_file).touch()
            except OSError:
                log.error("health outcome=cannot_write")

    def _record_failure(self, code: str) -> None:
        try:
            self.cursor.fail(self.source, code)
        except psycopg.Error as exc:
            log.error("reconcile cursor outcome=db_error kind=%s", type(exc).__name__)

    def cycle(self) -> bool:
        """One pass with every failure turned into a code, a log line and a cursor note."""
        try:
            counts = self.run_once()
        except LcError as exc:
            code = exc.code
        except StoreUnavailable:
            code = "db_unavailable"
        except psycopg.Error:
            code = "db_error"
        except Exception as exc:  # the loop must outlive anything the vendor sends
            log.error("reconcile outcome=error code=internal kind=%s", type(exc).__name__)
            self._record_failure("internal")
            return False
        else:
            log.info("reconcile outcome=ok %s", counts.line())
            self._touch_health()
            return True
        self._record_failure(code)
        log.warning("reconcile outcome=error code=%s %s", code, self.counts.line())
        self._touch_health()  # alive, if not succeeding: the pager's STALE check covers that
        return False

    def run(
        self,
        should_stop: Callable[[], bool],
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        next_at = 0.0
        while not should_stop():
            if monotonic() >= next_at:
                self.cycle()
                next_at = monotonic() + self.interval_s
            sleep(1.0)


# ---- the read-only look ----


def _present(records: list[dict[str, Any]]) -> str:
    def has(record: dict[str, Any], key: str) -> bool:
        if key == "routing.hostname":
            routing = record.get("routing")
            return isinstance(routing, dict) and isinstance(routing.get("hostname"), str)
        return key in record

    keys = (*SUMMARY_KEYS, "routing.hostname")
    return " ".join(f"{k}={sum(has(r, k) for r in records)}" for k in keys)


def check(cfg: Config, minutes: int) -> int:
    """Ask the vendor API for the last `minutes` and say what shape came back. Counts only:
    no detection content, no identifiers, no key. Writes nothing."""
    end = int(time.time())
    try:
        lim = Limits()
        listed = list(
            cfg.client().list_detections(
                end - minutes * 60, end, max_pages=lim.max_pages, max_items=lim.max_items
            )
        )
        records = [r for r in listed if isinstance(r, dict)]
        kept = [r for r in records if r.get("cat") in cfg.categories]
        lc = cfg.client()
        fetched: list[dict[str, Any]] = []
        where: dict[str, int] = {}
        for record in kept[:3]:
            detect_id = record.get("detect_id")
            found = lc.get_detection(detect_id) if isinstance(detect_id, str) else None
            if found:
                fetched.append(found[0])
                where[found[1]] = where.get(found[1], 0) + 1
    except LcError as exc:
        print(f"check failed: {exc.code}")
        return 1
    print(f"check ok: auth=ok window={minutes}m listed={len(listed)} matching={len(kept)}")
    print(f"listed fields ({len(records)} records): {_present(records)}")
    if fetched:
        print(f"whole records ({len(fetched)} fetched): {_present(fetched)}")
        print("whole record found at: " + ", ".join(f"{k}={v}" for k, v in sorted(where.items())))
    elif kept:
        print("whole records: none could be fetched by id")
    return 0


# ---- the command line ----


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m soc_api.reconcile")
    parser.add_argument("command", nargs="?", default="run", choices=["run", "once", "check"])
    parser.add_argument("--minutes", type=int, default=60)
    args = parser.parse_args(argv)
    configure_logging()
    try:
        cfg = Config.from_settings(get_settings(), need_db=args.command != "check")
    except ValueError as exc:
        print(exc)  # names a setting, never a value
        return 2
    if args.command == "check":
        if not 5 <= args.minutes <= 1440:
            print("--minutes must be between 5 and 1440")
            return 2
        return check(cfg, args.minutes)

    store, cursor = PgStore(cfg.db_url), CursorDb(cfg.db_url)
    reconciler = Reconciler(
        cfg.client(),
        store,
        cursor,
        source=cfg.source,
        categories=cfg.categories,
        first_lookback_s=cfg.first_lookback_s,
        interval_s=cfg.interval_s,
        health_file=cfg.health_file,
    )
    try:
        if args.command == "once":
            return 0 if reconciler.cycle() else 1
        stopping = False

        def request_stop(_signum: int, _frame: object) -> None:
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        log.info("reconcile outcome=started categories=%d", len(cfg.categories))
        reconciler.run(lambda: stopping)
        return 0
    finally:
        cursor.close()
        store.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
