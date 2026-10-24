"""POST /ingest/{source}: signed webhook deliveries from the EDR platform.

This is the one route on the public app that takes input from the internet, so it
stays small and every step is a separate, tested control (design note I1):

  path/method -> rate limit -> content type + size cap -> HMAC over the raw bytes
  -> JSON parse -> gen_time window -> store via ingest_alert() -> fixed reply

The database role used here can call ingest_alert() and nothing else, so even a
bug in this file cannot read or change stored data. Nothing from the payload is
ever executed, rendered or passed on as instructions; it is stored as data.
"""

import hashlib
import hmac
import json
import logging
import re
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DataError
from starlette.concurrency import run_in_threadpool

from soc_api.config import Settings

log = logging.getLogger("soc_api.ingest")

SOURCE_RE = re.compile(r"^[a-z0-9-]{1,32}$")
SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_BODY = 256 * 1024
MIN_SECRET_LEN = 16
SIGNATURE_HEADER = "lc-signature"

# Every refusal body is fixed: nothing in a reply depends on what the caller sent.
_NOT_FOUND = {"detail": "Not Found"}  # identical to the framework's own 404
_OK = {"status": "ok"}


def parse_secrets(raw: str) -> dict[str, list[bytes]]:
    """Parse SOC_INGEST_SECRETS. Fails closed; errors never echo the value."""
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("SOC_INGEST_SECRETS is not valid JSON") from None
    if not isinstance(data, dict):
        raise ValueError("SOC_INGEST_SECRETS must be a JSON object")
    out: dict[str, list[bytes]] = {}
    for source, secrets in data.items():
        if not isinstance(source, str) or not SOURCE_RE.match(source):
            raise ValueError("SOC_INGEST_SECRETS has an invalid source name")
        if (
            not isinstance(secrets, list)
            or not 1 <= len(secrets) <= 2
            or not all(isinstance(s, str) and len(s) >= MIN_SECRET_LEN for s in secrets)
        ):
            raise ValueError(
                f"SOC_INGEST_SECRETS: source {source!r} needs 1-2 secrets of "
                f"{MIN_SECRET_LEN}+ characters"
            )
        out[source] = [s.encode() for s in secrets]
    return out


def signature_matches(secrets: list[bytes], body: bytes, header: str | None) -> bool:
    """HMAC-SHA256, lowercase hex, over the raw body. Checks every secret, no early exit."""
    if header is None or not SIGNATURE_RE.match(header):
        return False
    given = header.encode()
    ok = False
    for secret in secrets:
        expected = hmac.new(secret, body, hashlib.sha256).hexdigest().encode()
        ok |= hmac.compare_digest(expected, given)
    return ok


class RateLimiter:
    """Fixed-window counters in memory. One container, so this resets on restart."""

    def __init__(
        self,
        window: float = 60.0,
        max_keys: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window = window
        self._max_keys = max_keys
        self._clock = clock
        self._hits: OrderedDict[str, tuple[float, int]] = OrderedDict()

    def hit(self, key: str, limit: int, cost: int = 1) -> bool:
        """Count `cost` against `key`. True while the key is within `limit`."""
        now = self._clock()
        start, count = self._hits.get(key, (now, 0))
        if now - start >= self._window:
            start, count = now, 0
        count += cost
        self._hits[key] = (start, count)
        self._hits.move_to_end(key)
        while len(self._hits) > self._max_keys:
            self._hits.popitem(last=False)
        return count <= limit

    def refund(self, key: str, cost: int = 1) -> None:
        """Give back `cost` for `key` (never below zero)."""
        if key in self._hits:
            start, count = self._hits[key]
            self._hits[key] = (start, max(count - cost, 0))


@dataclass
class Alert:
    """An alert in the shape ingest_alert() takes. Text is length-capped by the database."""

    tenant: str | None
    event_id: str
    rule: str | None
    severity: str
    summary: str | None
    actor: str | None
    mitre: str | None
    detected_at: datetime | None
    raw: str  # compact JSON of the parsed payload


class StoreUnavailable(Exception):
    """The database is down or not configured; the caller should retry later."""


class AlertStore(Protocol):
    def insert(self, source: str, alert: Alert) -> str: ...


class PgStore:
    """Calls ingest_alert() as soc_ingest. That function is the only thing the role can do."""

    def __init__(self, url: str) -> None:
        self._engine: Engine = create_engine(
            url,
            pool_size=5,
            max_overflow=0,
            pool_timeout=3,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 3, "options": "-c statement_timeout=5000"},
        )

    def close(self) -> None:
        self._engine.dispose()

    def insert(self, source: str, alert: Alert) -> str:
        try:
            with self._engine.begin() as conn:
                return str(
                    conn.execute(
                        text(
                            "SELECT ingest_alert(CAST(:source AS text), CAST(:tenant AS text), "
                            "CAST(:event_id AS text), CAST(:rule AS text), "
                            "CAST(:severity AS text), CAST(:summary AS text), "
                            "CAST(:actor AS text), CAST(:mitre AS text), "
                            "CAST(:detected_at AS timestamptz), CAST(:raw AS jsonb))"
                        ),
                        {
                            "source": source,
                            "tenant": alert.tenant,
                            "event_id": alert.event_id,
                            "rule": alert.rule,
                            "severity": alert.severity,
                            "summary": alert.summary,
                            "actor": alert.actor,
                            "mitre": alert.mitre,
                            "detected_at": alert.detected_at,
                            "raw": alert.raw,
                        },
                    ).scalar_one()
                )
        except DataError:
            # The database refused the content itself (for example a NUL in a
            # JSON string). That is the sender's problem, not an outage.
            return "invalid_payload"
        except Exception as exc:
            raise StoreUnavailable from exc


class NoStore:
    def insert(self, source: str, alert: Alert) -> str:
        raise StoreUnavailable


_SEVERITY = ("info", "info", "low", "low", "medium", "medium", "high", "high")


def _text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    return value.replace("\x00", "")[:limit] or None


_LONE_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _clean(value: Any) -> Any:
    """Replace what PostgreSQL cannot store (NUL, unpaired UTF-16 surrogates) with U+FFFD.

    An attacker on an endpoint can put either into a file name or command line; refusing
    the delivery would let them make their own detection disappear, so it is stored with
    the character replaced instead.
    """
    if isinstance(value, str):
        return _LONE_SURROGATE.sub("\ufffd", value.replace("\x00", "\ufffd"))
    if isinstance(value, dict):
        return {_clean(k): _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _reject_constant(name: str) -> None:
    raise ValueError(name)  # NaN / Infinity are not JSON and PostgreSQL's jsonb refuses them


def normalize(doc: dict[str, Any], body: bytes) -> Alert:
    """Map an LC `detect` delivery to an alert. Unknown shapes still store (raw is kept)."""
    detect_id = doc.get("detect_id")
    if isinstance(detect_id, str) and 1 <= len(detect_id) <= 256 and "\x00" not in detect_id:
        event_id = detect_id
    else:
        event_id = hashlib.sha256(body).hexdigest()  # no stable id: dedupe on the exact bytes

    routing = doc.get("routing")
    oid = routing.get("oid") if isinstance(routing, dict) else None
    mtd = doc.get("detect_mtd")
    summary = _text(mtd.get("description"), 2000) if isinstance(mtd, dict) else None

    priority = doc.get("priority")
    if isinstance(priority, int) and not isinstance(priority, bool):
        severity = "critical" if priority >= 8 else _SEVERITY[max(priority, 0)]
    else:
        severity = "medium"

    gen_time = doc.get("gen_time")
    detected_at = None
    if isinstance(gen_time, int) and not isinstance(gen_time, bool):
        detected_at = datetime.fromtimestamp(gen_time / 1000, UTC)

    return Alert(
        tenant=_text(oid, 256),
        event_id=event_id,
        rule=_text(doc.get("source_rule"), 256),
        severity=severity,
        summary=summary or _text(doc.get("cat"), 2000),
        actor=_text(doc.get("author"), 512),
        mitre=None,
        detected_at=detected_at,
        raw=json.dumps(doc, separators=(",", ":")),
    )


def _client_ip(request: Request) -> str:
    # Only meaningful because cloudflared is the one way to reach this app
    # (the host port is loopback). The console app has no ingest route at all.
    value = request.headers.get("cf-connecting-ip", "")
    return value if re.fullmatch(r"[0-9a-fA-F:.]{1,45}", value) else "unknown"


def _reply(status: int, body: dict[str, str], **headers: str) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=headers or None)


def build_router(settings: Settings, store: AlertStore | None = None) -> APIRouter:
    secrets = parse_secrets(settings.ingest_secrets.get_secret_value())
    # Our own copy of each configured name. Once a request matches, this copy is what
    # gets logged and used, never the string from the URL.
    configured = {name: name for name in secrets}
    if store is None:
        url = settings.ingest_database_url.get_secret_value()
        store = PgStore(url) if url else NoStore()
    limiter = RateLimiter()
    router = APIRouter()
    db: AlertStore = store

    def outcome(code: str, status: int, source: str | None, request_id: str, size: int) -> None:
        # Never the body, headers, query string or any secret. `source` is always
        # None or our own copy of a configured name, so a caller cannot choose
        # what ends up in the log.
        log.info(
            "ingest outcome=%s status=%d source=%s request_id=%s size=%d",
            code,
            status,
            source or "-",
            request_id,
            size,
        )

    # Every method is routed so that a non-POST is the same 404 as any unknown path.
    @router.api_route(
        "/ingest/{source}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
        include_in_schema=False,
    )
    async def ingest(source: str, request: Request) -> Response:
        request_id = uuid.uuid4().hex[:12]
        ip = _client_ip(request)
        not_found = JSONResponse(_NOT_FOUND, status_code=404)

        if not limiter.hit(f"ip:{ip}", settings.ingest_rate_per_ip):
            outcome("rate_limited", 429, None, request_id, 0)
            return _reply(429, {"detail": "Too Many Requests"}, **{"Retry-After": "60"})

        if request.method != "POST" or not SOURCE_RE.match(source) or source not in configured:
            outcome("not_found", 404, None, request_id, 0)
            return not_found
        source = configured[source]

        if not limiter.hit(f"src:{source}", settings.ingest_rate_per_source):
            outcome("rate_limited", 429, source, request_id, 0)
            return _reply(429, {"detail": "Too Many Requests"}, **{"Retry-After": "60"})

        content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            outcome("bad_content_type", 415, source, request_id, 0)
            return _reply(415, {"detail": "Unsupported Media Type"})

        declared = request.headers.get("content-length")
        if declared is not None and (
            not re.fullmatch(r"[0-9]{1,12}", declared) or int(declared) > MAX_BODY
        ):
            outcome("too_large", 413, source, request_id, 0)
            return _reply(413, {"detail": "Payload Too Large"})

        # Read the stream ourselves and stop at the cap: Content-Length can lie,
        # and chunked bodies have none.
        chunks = bytearray()
        async for chunk in request.stream():
            chunks += chunk
            if len(chunks) > MAX_BODY:
                outcome("too_large", 413, source, request_id, len(chunks))
                return _reply(413, {"detail": "Payload Too Large"})
        body = bytes(chunks)

        if not signature_matches(secrets[source], body, request.headers.get(SIGNATURE_HEADER)):
            # A failed attempt costs double against both buckets.
            limiter.hit(f"ip:{ip}", settings.ingest_rate_per_ip)
            limiter.hit(f"src:{source}", settings.ingest_rate_per_source)
            outcome("bad_signature", 401, source, request_id, len(body))
            return _reply(401, {"detail": "Unauthorized"})
        # The per-IP bucket is for unauthenticated noise. A burst of real detections
        # (an incident, a noisy rule) comes from the EDR's few egress IPs and must not
        # be refused for it; the per-source bucket still bounds authenticated traffic.
        limiter.refund(f"ip:{ip}")

        try:
            doc = _clean(json.loads(body, parse_constant=_reject_constant))
        except (ValueError, RecursionError):
            outcome("bad_json", 400, source, request_id, len(body))
            return _reply(400, {"detail": "Bad Request"})
        if not isinstance(doc, dict):
            outcome("bad_json", 400, source, request_id, len(body))
            return _reply(400, {"detail": "Bad Request"})

        # gen_time is inside the signed body, so the window is authenticated.
        gen_time = doc.get("gen_time")
        now_ms = time.time() * 1000
        if (
            not isinstance(gen_time, int)
            or isinstance(gen_time, bool)
            or gen_time < now_ms - settings.ingest_max_age_seconds * 1000
            or gen_time > now_ms + settings.ingest_max_future_seconds * 1000
        ):
            outcome("stale_or_future", 400, source, request_id, len(body))
            return _reply(400, {"detail": "Bad Request"})

        try:
            result = await run_in_threadpool(db.insert, source, normalize(doc, body))
        except StoreUnavailable:
            outcome("db_unavailable", 503, source, request_id, len(body))
            return _reply(503, {"detail": "Service Unavailable"}, **{"Retry-After": "60"})

        if result in ("inserted", "duplicate"):
            # A duplicate is answered exactly like a first delivery: no oracle.
            outcome(result, 200, source, request_id, len(body))
            return JSONResponse(_OK)
        if result in ("invalid_event_id", "invalid_payload"):
            outcome(result, 400, source, request_id, len(body))
            return _reply(400, {"detail": "Bad Request"})
        # unknown_source: configured here but not in the database. Not stored,
        # so not a 200.
        outcome(result, 503, source, request_id, len(body))
        return _reply(503, {"detail": "Service Unavailable"}, **{"Retry-After": "60"})

    return router
