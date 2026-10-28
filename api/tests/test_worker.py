"""The pager worker: text that crosses ntfy, the ntfy client, the schedule, and the loop
against a real database and a local fake ntfy server."""

import json
import logging
import socket
import threading
import time
from collections import deque
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from conftest import ROLE_PASSWORD, TestDb
from test_worker_db import Fixture

from soc_api import worker as w
from soc_api.config import Settings

TOPIC = "sec-" + "a1" * 14
LINK = "https://app.limacharlie.io/orgs/o/sensors/s/timeline?time=1"


# ---- a fake ntfy server ----


class FakeNtfy:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.statuses: deque[int] = deque()
        self.default = 200
        self.delay = 0.0
        self.location: str | None = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("content-length") or 0))
                outer.requests.append(
                    {
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": body,
                    }
                )
                time.sleep(outer.delay)
                status = outer.statuses.popleft() if outer.statuses else outer.default
                self.send_response(status)
                if outer.location:
                    self.send_header("Location", outer.location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def pushes(self) -> list[dict[str, Any]]:
        return [json.loads(r["body"]) for r in self.requests]

    def titles(self) -> list[str]:
        return [p["title"] for p in self.pushes]


@pytest.fixture
def ntfy_server() -> Iterator[FakeNtfy]:
    fake = FakeNtfy()
    yield fake
    fake.server.shutdown()
    fake.server.server_close()


def client(fake: FakeNtfy, **kw: Any) -> w.Ntfy:
    return w.Ntfy(fake.url, TOPIC, allow_http=True, timeout=kw.pop("timeout", 3.0), **kw)


# ---- text ----


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain text", "plain text"),
        ("two\nlines\r\nhere", "two lines here"),
        ("tab\tand   spaces", "tab and spaces"),
        ("nul\x00and\x1besc", "nulandesc"),
        ("bidi‮evil⁦x", "bidievilx"),
        ("zero​width", "zerowidth"),
        ("  padded  ", "padded"),
        ("", ""),
        (None, ""),
        ("x" * 500, "x" * 80),
        ("ünïcode ok", "ünïcode ok"),
    ],
)
def test_clean_makes_plain_single_line_text(raw: str | None, expected: str) -> None:
    assert w.clean(raw, 80) == expected


@pytest.mark.parametrize(
    ("link", "ok"),
    [
        (LINK, True),
        ("http://app.limacharlie.io/x", False),
        ("https://app.limacharlie.io.evil.example/x", False),
        ("https://evil.example/https://app.limacharlie.io/", False),
        (LINK + " x", False),
        (LINK + "\n", False),
        (LINK + "é", False),
        (LINK + "a" * 600, False),
        ("javascript:alert(1)", False),
        ("", False),
        (None, False),
    ],
)
def test_only_a_plain_limacharlie_https_link_is_kept(link: str | None, ok: bool) -> None:
    assert w.safe_link(link) == (link if ok else None)


def page(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "00000000-0000-4000-8000-0000000000aa",
        "priority": 5,
        "attempts": 1,
        "client_slug": "client-a",
        "rule": "general.Rule One",
        "host": "host-1",
        "link": LINK,
        "case_short": "abcd1234",
        "detected_at": datetime(2026, 7, 1, 18, 5, tzinfo=UTC),
    }
    return {**base, **kw}


def test_push_text_names_client_rule_host_time_and_case() -> None:
    title, message, priority, click = w.push_text(page())
    assert title == "client-a: Rule One"
    assert message == "host host-1 · 14:05 ET · case abcd1234"
    assert (priority, click) == (5, LINK)


def test_push_time_follows_daylight_saving() -> None:
    _, summer, _, _ = w.push_text(page(detected_at=datetime(2026, 7, 1, 18, 5, tzinfo=UTC)))
    _, winter, _, _ = w.push_text(page(detected_at=datetime(2026, 1, 15, 18, 5, tzinfo=UTC)))
    assert "14:05 ET" in summer and "13:05 ET" in winter


def test_push_text_survives_missing_fields() -> None:
    title, message, priority, click = w.push_text(
        page(rule=None, host=None, link=None, detected_at=None, priority=None)
    )
    assert title == "client-a: alert"
    assert message == "host unknown · ? · case abcd1234"
    assert (priority, click) == (3, None)


def test_push_text_cuts_long_values() -> None:
    title, message, _, _ = w.push_text(page(rule="r" * 500, host="h" * 500))
    assert len(title) <= 80 and len(message) <= 200 and "h" * 65 not in message


@pytest.mark.parametrize("priority", [0, 6, -1, True, "5", 2.5])
def test_a_bad_priority_becomes_3(priority: Any) -> None:
    assert w.push_text(page(priority=priority))[2] == 3


# ---- the ntfy client ----


def test_the_topic_must_look_like_a_topic() -> None:
    for bad in ("", "short", "has space " * 3, "x" * 65, "semi;colon-aaaaaaaaaaaa", "é" * 20):
        with pytest.raises(ValueError, match="topic"):
            w.Ntfy("https://ntfy.sh", bad)


@pytest.mark.parametrize(
    "server",
    [
        "http://ntfy.sh",  # cleartext
        "ftp://ntfy.sh",
        "file:///etc/passwd",
        "https://user:pw@example.com",
        "https://ntfy.sh/topic",
        "https://ntfy.sh/?x=1",
        "https://",
        "",
        "ntfy.sh",
    ],
)
def test_the_server_must_be_a_bare_https_host(server: str) -> None:
    with pytest.raises(ValueError, match="SOC_NTFY_SERVER"):
        w.Ntfy(server, TOPIC)


def test_plain_http_is_only_for_tests() -> None:
    w.Ntfy("http://127.0.0.1:9", TOPIC, allow_http=True)
    w.Ntfy("https://ntfy.sh", TOPIC)
    w.Ntfy("https://ntfy.sh/", TOPIC)


def test_prod_settings_refuse_a_cleartext_server_and_dev_settings_allow_it() -> None:
    base: dict[str, Any] = {
        "worker_database_url": "postgresql+psycopg://u:p@h/d",
        "ntfy_topic": TOPIC,
        "ntfy_server": "http://127.0.0.1:1",
    }
    with pytest.raises(ValueError, match="SOC_NTFY_SERVER"):
        w.build(Settings(env="prod", **base))
    w.build(Settings(env="dev", **base))


def test_publish_sends_one_json_post_to_the_root_and_nothing_else(ntfy_server: FakeNtfy) -> None:
    result = client(ntfy_server).publish(title="T", message="M", priority=4, click=LINK)
    assert result == w.Delivery("sent", "http_200")
    [req] = ntfy_server.requests
    assert req["path"] == "/"  # the topic is in the body, never in the URL
    assert req["headers"]["content-type"] == "application/json"
    assert set(req["headers"]) <= {
        "host",
        "accept-encoding",
        "content-type",
        "content-length",
        "user-agent",
        "connection",
    }
    assert json.loads(req["body"]) == {
        "topic": TOPIC,
        "title": "T",
        "message": "M",
        "priority": 4,
        "click": LINK,
    }


def test_publish_leaves_out_click_when_there_is_none(ntfy_server: FakeNtfy) -> None:
    client(ntfy_server).publish(title="T", message="M", priority=3)
    assert "click" not in ntfy_server.pushes[0]


def test_injection_strings_arrive_as_plain_json_values(ntfy_server: FakeNtfy) -> None:
    rule = 'x\r\nX-Evil: 1\x00"}, {"topic": "other'
    host = '", "topic": "other", "x": "'
    title, message, priority, click = w.push_text(page(rule=rule, host=host))
    client(ntfy_server).publish(title=title, message=message, priority=priority, click=click)
    [req] = ntfy_server.requests
    assert "x-evil" not in req["headers"]
    doc = json.loads(req["body"])
    assert doc["topic"] == TOPIC
    assert set(doc) == {"topic", "title", "message", "priority", "click"}
    assert "\r" not in doc["title"] and "\n" not in doc["title"] and "\x00" not in doc["title"]


@pytest.mark.parametrize(
    ("status", "outcome", "code"),
    [
        (200, "sent", "http_200"),
        (204, "sent", "http_204"),
        (400, "fail", "http_400"),
        (401, "fail", "http_401"),
        (403, "fail", "http_403"),
        (404, "fail", "http_404"),
        (429, "retry", "http_429"),
        (500, "retry", "http_500"),
        (503, "retry", "http_503"),
    ],
)
def test_the_status_decides_sent_retry_or_fail(
    ntfy_server: FakeNtfy, status: int, outcome: str, code: str
) -> None:
    ntfy_server.default = status
    assert client(ntfy_server).publish(title="T", message="M", priority=3) == w.Delivery(
        outcome, code
    )


def test_a_redirect_is_not_followed_and_fails(ntfy_server: FakeNtfy) -> None:
    other = FakeNtfy()
    try:
        ntfy_server.default = 302
        ntfy_server.location = other.url + "/stolen"
        result = client(ntfy_server).publish(title="T", message="M", priority=3)
        time.sleep(0.2)
        assert result == w.Delivery("fail", "redirect")
        assert other.requests == []  # the topic never reached the redirect target
    finally:
        other.server.shutdown()
        other.server.server_close()


def test_a_slow_server_is_a_retryable_timeout(ntfy_server: FakeNtfy) -> None:
    ntfy_server.delay = 1.5
    start = time.monotonic()
    result = client(ntfy_server, timeout=0.4).publish(title="T", message="M", priority=3)
    assert result == w.Delivery("retry", "timeout")
    assert time.monotonic() - start < 1.2


def test_an_unreachable_server_is_retryable() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    result = w.Ntfy(f"http://127.0.0.1:{port}", TOPIC, allow_http=True, timeout=1).publish(
        title="T", message="M", priority=3
    )
    assert result == w.Delivery("retry", "unreachable")


def test_the_send_timeout_is_far_inside_the_claim_lease() -> None:
    # claim_pages leases a page for two minutes; one send must be long over by then.
    assert w.NTFY_TIMEOUT_SECONDS * 3 < 120


# ---- the policy and the schedule ----


def test_the_policy_keeps_only_whole_numbers_0_to_5() -> None:
    raw = json.dumps({"A": 5, "B": 0, "C": 6, "D": -1, "E": "3", "F": 2.5, "G": True, "H": None})
    assert w.parse_policy(raw) == {"A": 5, "B": 0}


@pytest.mark.parametrize("raw", ["", "  ", "{", "[1]", "null", '"x"'])
def test_an_unusable_policy_means_the_severity_defaults(raw: str) -> None:
    assert w.parse_policy(raw) == {}


def utc(*a: int) -> datetime:
    return datetime(*a, tzinfo=UTC)


@pytest.mark.parametrize(
    ("now", "slot"),
    [
        # Sunday 2026-11-01 is the day clocks go back (EDT -> EST); 18:00 is EST = 23:00 UTC.
        (utc(2026, 11, 1, 23, 0), utc(2026, 11, 1, 23, 0)),
        (utc(2026, 11, 1, 22, 59), utc(2026, 10, 25, 22, 0)),  # last week's slot was EDT
        (utc(2026, 11, 3, 12, 0), utc(2026, 11, 1, 23, 0)),
        (utc(2026, 11, 8, 22, 59), utc(2026, 11, 1, 23, 0)),
        (utc(2026, 11, 8, 23, 0), utc(2026, 11, 8, 23, 0)),
        (utc(2026, 7, 5, 22, 0), utc(2026, 7, 5, 22, 0)),  # July: EDT = 22:00 UTC
        (utc(2026, 7, 5, 21, 59), utc(2026, 6, 28, 22, 0)),
        (utc(2026, 3, 8, 22, 0), utc(2026, 3, 8, 22, 0)),  # DST starts 2026-03-08: slot is EDT
        (utc(2026, 3, 8, 21, 59), utc(2026, 3, 1, 23, 0)),  # and the week before it was EST
    ],
)
def test_the_weekly_slot_is_sunday_6pm_eastern(now: datetime, slot: datetime) -> None:
    assert w.last_weekly_slot(now) == slot


# ---- the loop, against a real database ----


class Clock:
    def __init__(self) -> None:
        self.now = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


OPEN: list[w.Db] = []


@pytest.fixture(autouse=True)
def fresh_settings() -> Iterator[None]:
    from soc_api import config

    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()
    while OPEN:
        OPEN.pop().close()


def make_worker(
    fx: Fixture,
    fake: FakeNtfy,
    *,
    policy: dict[str, int] | None = None,
    limits: w.Limits | None = None,
    clock: Clock | None = None,
    health: Path | None = None,
) -> w.Worker:
    db = w.Db(fx.db.sqlalchemy_url("soc_worker", ROLE_PASSWORD))
    OPEN.append(db)
    return w.Worker(
        db,
        client(fake),
        policy or {},
        limits=limits,
        clock=clock or Clock(),
        health_file=str(health) if health else None,
    )


def notification(fx: Fixture) -> list[tuple[Any, ...]]:
    return fx.rows("SELECT status, attempts, last_error FROM notification ORDER BY created_at, id")


def test_an_alert_becomes_one_case_and_one_push(fx: Fixture, ntfy_server: FakeNtfy) -> None:
    fx.alert(rule="general.Rule One", host="host-1", severity="high")
    worker = make_worker(fx, ntfy_server)
    assert worker.tick() is True
    [push] = ntfy_server.pushes
    assert push["topic"] == TOPIC and push["title"] == "client-a: Rule One"
    assert push["priority"] == 5 and push["click"] == LINK
    assert push["message"].startswith("host host-1 · ") and " ET · case " in push["message"]
    assert notification(fx) == [("sent", 1, None)]
    worker.tick()
    worker.tick()
    assert len(ntfy_server.requests) == 1  # nothing is sent twice


def test_the_policy_decides_how_loud_and_whether(fx: Fixture, ntfy_server: FakeNtfy) -> None:
    fx.alert(host="h1", cat="LOUD")
    fx.alert(host="h2", cat="OFF")
    fx.alert(host="h3", cat="OTHER")
    make_worker(fx, ntfy_server, policy={"LOUD": 5, "OFF": 0}).tick()
    assert sorted(p["priority"] for p in ntfy_server.pushes) == [3, 5]
    assert fx.one("SELECT count(*) FROM soc_case")[0] == 3


def test_a_server_error_is_retried_on_the_schedule_and_then_delivered(
    fx: Fixture, ntfy_server: FakeNtfy
) -> None:
    fx.alert()
    ntfy_server.statuses.extend([503])
    worker = make_worker(fx, ntfy_server)
    worker.tick()
    assert notification(fx) == [("pending", 1, "http_503")]
    wait = fx.one("SELECT extract(epoch FROM next_attempt_at - now()) FROM notification")[0]
    assert 6 <= float(wait) <= 10  # the first back-off
    worker.tick()
    assert len(ntfy_server.requests) == 1  # not due yet
    fx.run("UPDATE notification SET next_attempt_at = now() - interval '1 second'")
    worker.tick()
    assert notification(fx) == [("sent", 2, None)]
    assert len(ntfy_server.requests) == 2


def test_a_client_error_stops_at_once_and_raises_a_stale_push(
    fx: Fixture, ntfy_server: FakeNtfy
) -> None:
    fx.alert()
    ntfy_server.statuses.extend([400])
    clock = Clock()
    worker = make_worker(fx, ntfy_server, clock=clock)
    worker.tick()
    assert notification(fx) == [("failed", 1, "http_400")]
    # The same pass sees the failed page: one STALE push, generic text only.
    assert ntfy_server.titles() == ["client-a: Rule One", "SOC STALE"]
    assert ntfy_server.pushes[-1]["priority"] == 5
    assert ntfy_server.pushes[-1]["message"] == w.STALE_TEXT["page_failed"]
    count = len(ntfy_server.requests)
    clock.advance(seconds=301)
    worker.tick()
    assert len(ntfy_server.requests) == count  # once per 6 hours, not every check
    clock.advance(hours=6)
    worker.tick()
    assert len(ntfy_server.requests) == count + 1


def test_the_topic_is_never_logged_or_stored(
    fx: Fixture, ntfy_server: FakeNtfy, caplog: pytest.LogCaptureFixture
) -> None:
    fx.alert()
    ntfy_server.statuses.extend([500])
    worker = make_worker(fx, ntfy_server)
    with caplog.at_level(logging.DEBUG, logger="soc_api"):
        worker.tick()
        fx.run("UPDATE notification SET next_attempt_at = now() - interval '1 second'")
        worker.tick()
    logged = "\n".join(r.getMessage() + str(r.__dict__) for r in caplog.records)
    assert "worker" in logged or "page outcome" in logged
    assert TOPIC not in logged and ROLE_PASSWORD not in logged
    stored = fx.rows("SELECT to_jsonb(n)::text FROM notification n")
    assert all(TOPIC not in str(r) for r in stored)


def test_a_flood_is_capped_and_one_notice_says_so(fx: Fixture, ntfy_server: FakeNtfy) -> None:
    for i in range(15):
        fx.alert(host=f"host-{i}", age_min=20 - i * 0.1)
    clock = Clock()
    limits = w.Limits(page_cap=10, cap_window_s=600)
    worker = make_worker(fx, ntfy_server, clock=clock, limits=limits)
    worker.tick()
    pages = [t for t in ntfy_server.titles() if t != "SOC: pages held"]
    held = [p for p in ntfy_server.pushes if p["title"] == "SOC: pages held"]
    assert len(pages) == 10
    assert len(held) == 1 and held[0]["message"].startswith("5 more pages are waiting")
    assert "client-a" not in held[0]["message"]
    for _ in range(3):
        clock.advance(seconds=60)
        worker.tick()
    assert len(ntfy_server.requests) == 11  # still held, still one notice
    clock.advance(seconds=600)
    worker.tick()
    assert len([t for t in ntfy_server.titles() if t != "SOC: pages held"]) == 15
    assert fx.one("SELECT count(*) FROM notification WHERE status = 'sent'")[0] == 15


def test_failed_attempts_count_toward_the_cap_too(fx: Fixture, ntfy_server: FakeNtfy) -> None:
    for i in range(6):
        fx.alert(host=f"host-{i}")
    ntfy_server.default = 503
    clock = Clock()
    worker = make_worker(fx, ntfy_server, clock=clock, limits=w.Limits(page_cap=3))

    def page_sends() -> int:
        return len([t for t in ntfy_server.titles() if t != "SOC: pages held"])

    worker.tick()
    assert page_sends() == 3
    clock.advance(seconds=30)
    worker.tick()
    assert page_sends() == 3  # three more are due, but three attempts already used the cap
    clock.advance(seconds=600)
    worker.tick()
    assert page_sends() > 3


def test_the_weekly_ok_is_armed_first_then_sent_once_per_slot(
    fx: Fixture, ntfy_server: FakeNtfy
) -> None:
    fx.alert()
    clock = Clock()
    worker = make_worker(fx, ntfy_server, clock=clock)
    worker.tick()
    assert "SOC OK" not in ntfy_server.titles()  # armed, not announced
    worker.tick()
    assert "SOC OK" not in ntfy_server.titles()
    clock.now = w.last_weekly_slot(clock.now + timedelta(days=7)) + timedelta(minutes=5)
    worker.tick()
    oks = [p for p in ntfy_server.pushes if p["title"] == "SOC OK"]
    assert len(oks) == 1 and oks[0]["priority"] == 2
    assert oks[0]["message"] == "7d: 1 alerts, 1 cases, 1 pages sent, 0 failed"
    worker.tick()
    clock.advance(hours=3)
    worker.tick()
    assert len([p for p in ntfy_server.pushes if p["title"] == "SOC OK"]) == 1


def test_a_weekly_ok_that_could_not_be_sent_is_tried_again(
    fx: Fixture, ntfy_server: FakeNtfy
) -> None:
    clock = Clock()
    worker = make_worker(fx, ntfy_server, clock=clock)
    worker.tick()
    clock.now = w.last_weekly_slot(clock.now + timedelta(days=7)) + timedelta(minutes=5)
    ntfy_server.statuses.extend([500])
    worker.tick()
    assert ntfy_server.titles() == ["SOC OK"]  # tried, failed
    worker.tick()
    assert len(ntfy_server.requests) == 1  # not again within a minute
    clock.advance(seconds=61)
    worker.tick()
    assert ntfy_server.titles() == ["SOC OK", "SOC OK"]
    clock.advance(seconds=61)
    worker.tick()
    assert len(ntfy_server.requests) == 2  # sent, so done for this slot


def test_a_page_stuck_for_ten_minutes_raises_stale(fx: Fixture, ntfy_server: FakeNtfy) -> None:
    fx.alert(host="h1")
    ntfy_server.default = 503
    clock = Clock()
    worker = make_worker(fx, ntfy_server, clock=clock)
    worker.tick()
    ntfy_server.default = 200
    fx.run("UPDATE notification SET created_at = now() - interval '11 minutes'")
    clock.advance(seconds=301)
    worker.tick()
    stale = [p for p in ntfy_server.pushes if p["title"] == "SOC STALE"]
    assert [p["message"] for p in stale] == [w.STALE_TEXT["pages_pending"]]


def test_a_caser_that_is_behind_raises_stale(fx: Fixture, ntfy_server: FakeNtfy) -> None:
    clock = Clock()
    worker = make_worker(fx, ntfy_server, clock=clock)
    worker.tick()
    fx.alert(age_min=15)
    # Leave the alert without a case: stop the caser for this check.
    worker._caser = lambda: None  # type: ignore[method-assign]
    worker._sender = lambda: None  # type: ignore[method-assign]
    clock.advance(seconds=301)
    worker.tick()
    assert [p["message"] for p in ntfy_server.pushes if p["title"] == "SOC STALE"] == [
        w.STALE_TEXT["caser_behind"]
    ]


def test_the_health_file_is_touched_only_when_every_phase_worked(
    fx: Fixture, ntfy_server: FakeNtfy, tmp_path: Path
) -> None:
    health = tmp_path / "health"
    good = make_worker(fx, ntfy_server, health=health)
    assert good.tick() is True and health.exists()
    health.unlink()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    bad_db = w.Db(f"postgresql+psycopg://soc_worker:x@127.0.0.1:{port}/nope")
    OPEN.append(bad_db)
    bad = w.Worker(
        bad_db,
        client(ntfy_server),
        {},
        health_file=str(health),
    )
    assert bad.tick() is False and not health.exists()


def test_a_database_outage_does_not_stop_the_loop_and_it_recovers(
    fx: Fixture, ntfy_server: FakeNtfy
) -> None:
    fx.alert()
    worker = make_worker(fx, ntfy_server)
    worker.db._params["port"] = 1  # nothing listens there
    assert worker.tick() is False
    worker.db._params["port"] = int(fx.db.params.get("port", "5432"))
    assert worker.tick() is True
    assert len(ntfy_server.requests) == 1


def test_a_page_that_cannot_be_described_fails_instead_of_looping(
    ntfy_server: FakeNtfy,
) -> None:
    calls: list[tuple[Any, ...]] = []

    class FakeDb:
        def claim_pages(self, batch: int) -> list[dict[str, Any]]:
            return [{"id": "11111111-1111-4111-8111-111111111111", "attempts": 1}]

        def finish_page(self, *args: Any) -> str:
            calls.append(args)
            return "failed"

        def due_page_count(self) -> int:
            return 0

    worker = w.Worker(FakeDb(), client(ntfy_server), {})  # type: ignore[arg-type]
    worker._sender()
    assert calls == [("11111111-1111-4111-8111-111111111111", "fail", "bad_page")]
    assert ntfy_server.requests == []


def test_the_run_loop_ticks_until_told_to_stop(fx: Fixture, ntfy_server: FakeNtfy) -> None:
    worker = make_worker(fx, ntfy_server)
    ticks: list[int] = []
    worker.tick = lambda: ticks.append(1) or True  # type: ignore[method-assign]
    sleeps: list[float] = []
    worker.run(lambda: len(ticks) >= 3, 5.0, sleep=sleeps.append)
    assert len(ticks) == 3 and sleeps == [5.0, 5.0, 5.0]


# ---- the command line ----


def configure(monkeypatch: pytest.MonkeyPatch, fx: Fixture, fake: FakeNtfy, **extra: str) -> None:
    from soc_api import config

    config.get_settings.cache_clear()
    env = {
        "SOC_ENV": "dev",
        "SOC_WORKER_DATABASE_URL": fx.db.sqlalchemy_url("soc_worker", ROLE_PASSWORD),
        "SOC_NTFY_TOPIC": TOPIC,
        "SOC_NTFY_SERVER": fake.url,
        **extra,
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def test_ok_now_sends_the_ok_push_and_says_so(
    fx: Fixture,
    ntfy_server: FakeNtfy,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure(monkeypatch, fx, ntfy_server)
    assert w.main(["ok-now"]) == 0
    out = capsys.readouterr().out
    assert out.strip() == "ok push: sent (http_200)" and TOPIC not in out
    assert ntfy_server.titles() == ["SOC OK"]


def test_ok_now_fails_loudly_when_the_push_does_not_go(
    fx: Fixture,
    ntfy_server: FakeNtfy,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ntfy_server.default = 400
    configure(monkeypatch, fx, ntfy_server)
    assert w.main(["ok-now"]) == 1
    assert "fail (http_400)" in capsys.readouterr().out


@pytest.mark.parametrize("missing", ["SOC_NTFY_TOPIC", "SOC_WORKER_DATABASE_URL"])
def test_an_unconfigured_worker_says_so_and_prints_no_value(
    fx: Fixture,
    ntfy_server: FakeNtfy,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    missing: str,
) -> None:
    configure(monkeypatch, fx, ntfy_server)
    monkeypatch.delenv(missing)
    assert w.main(["run"]) == 2
    out = capsys.readouterr().out
    assert "not configured" in out and TOPIC not in out and ROLE_PASSWORD not in out


def test_a_malformed_topic_is_refused_without_echoing_it(
    fx: Fixture,
    ntfy_server: FakeNtfy,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure(monkeypatch, fx, ntfy_server, SOC_NTFY_TOPIC="bad topic with spaces!!")
    assert w.main(["run"]) == 2
    out = capsys.readouterr().out
    assert "topic" in out and "bad topic" not in out
