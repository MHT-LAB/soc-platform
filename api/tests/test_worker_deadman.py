"""The dead-man's switch: the worker calls an outside monitor after each good pass, at most
once a minute, without ever blocking, failing or slowing a pass, and never logging the URL.
A local fake server stands in for the monitor; the database is a stub."""

import logging
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from test_worker import TOPIC

from soc_api import worker as w
from soc_api.config import Settings

PING_PATH = "/ping/s3cr3t-token-0a1b2c"


class FakeMonitor:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []
        self.status = 200
        self.delay = 0.0
        self.location: str | None = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outer.requests.append((self.command, self.path))
                time.sleep(outer.delay)
                self.send_response(outer.status)
                if outer.location:
                    self.send_header("Location", outer.location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: object) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}{PING_PATH}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def monitor() -> Iterator[FakeMonitor]:
    m = FakeMonitor()
    yield m
    m.stop()


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# ---- the URL ----


@pytest.mark.parametrize(
    "bad",
    [
        "http://hc.example.com/ping/x",  # https only
        "ftp://hc.example.com/ping/x",
        "https://",
        "https:///ping/x",
        "https://user:pw" + "@hc.example.com/ping/x",
        "https://hc.example.com/ping/with space",
        "https://hc.example.com/ping/\r\nHost: evil",
        "https://hc.example.com/" + "x" * 600,
        "hc.example.com/ping/x",
        "",
    ],
)
def test_only_an_https_url_with_a_host_and_no_credentials_is_accepted(bad: str) -> None:
    with pytest.raises(ValueError, match="SOC_WORKER_DEADMAN_URL") as caught:
        w.Deadman(bad)
    assert bad.strip() == "" or bad not in str(caught.value)  # the message names the setting only


def test_a_good_https_url_is_accepted() -> None:
    w.Deadman("https://hc.example.com/ping/0a1b2c3d-0000-4000-8000-0123456789ab")
    w.Deadman("https://hc.example.com:8443/ping/x?create=1")


# ---- pinging ----


def test_a_ping_is_a_get_to_the_url(monitor: FakeMonitor) -> None:
    d = w.Deadman(monitor.url, allow_http=True)
    assert d.ping() is True
    d.wait(5)
    assert monitor.requests == [("GET", PING_PATH)]


def test_at_most_one_ping_a_minute(monitor: FakeMonitor) -> None:
    clock = Clock()
    d = w.Deadman(monitor.url, allow_http=True, clock=clock)
    assert d.ping() is True
    d.wait(5)
    for _ in range(5):  # five ticks of five seconds
        clock.now += 5
        assert d.ping() is False
    clock.now += 40  # 65 s after the first
    assert d.ping() is True
    d.wait(5)
    assert len(monitor.requests) == 2


def test_a_slow_monitor_never_holds_up_the_caller(
    monitor: FakeMonitor, caplog: pytest.LogCaptureFixture
) -> None:
    monitor.delay = 2.0
    d = w.Deadman(monitor.url, allow_http=True, timeout=0.3)
    with caplog.at_level(logging.INFO, logger="soc_api.worker"):
        started = time.monotonic()
        assert d.ping() is True
        assert time.monotonic() - started < 0.2  # returned at once; the request is in flight
        d.wait(5)
    assert "deadman outcome=failed code=timeout" in caplog.text


def test_a_ping_in_flight_is_not_doubled_even_when_a_minute_has_passed(
    monitor: FakeMonitor,
) -> None:
    monitor.delay = 0.6
    clock = Clock()
    d = w.Deadman(monitor.url, allow_http=True, timeout=2.0, clock=clock)
    assert d.ping() is True
    clock.now += 120
    assert d.ping() is False  # the first is still waiting on the monitor
    d.wait(5)
    clock.now += 120
    assert d.ping() is True
    d.wait(5)


def test_failures_are_logged_as_codes_and_the_url_never_appears(
    monitor: FakeMonitor, caplog: pytest.LogCaptureFixture
) -> None:
    clock = Clock()
    d = w.Deadman(monitor.url, allow_http=True, clock=clock)
    with caplog.at_level(logging.DEBUG):
        monitor.status = 500
        d.ping()
        d.wait(5)
        clock.now += 61
        monitor.status = 200
        d.ping()
        d.wait(5)
        clock.now += 61
        dead = w.Deadman(f"http://127.0.0.1:1{PING_PATH}", allow_http=True, clock=clock)
        dead.ping()
        dead.wait(5)
    assert "deadman outcome=failed code=http_500" in caplog.text
    assert "deadman outcome=recovered" in caplog.text
    assert "deadman outcome=failed code=unreachable" in caplog.text
    everything = caplog.text + "".join(str(r.__dict__) for r in caplog.records)
    assert PING_PATH not in everything and "s3cr3t" not in everything


def test_a_redirect_is_not_followed(monitor: FakeMonitor, caplog: pytest.LogCaptureFixture) -> None:
    other = FakeMonitor()
    try:
        monitor.status = 302
        monitor.location = other.url
        d = w.Deadman(monitor.url, allow_http=True)
        with caplog.at_level(logging.WARNING):
            d.ping()
            d.wait(5)
        assert other.requests == []
        assert "code=redirect" in caplog.text
    finally:
        other.stop()


# ---- in the worker ----


class StubDb:
    """Just enough of Db for a pass that does nothing."""

    def __init__(self) -> None:
        self.down = False

    def _check(self) -> None:
        if self.down:
            import psycopg

            raise psycopg.OperationalError("down")

    def assign_cases(self, *_: Any) -> tuple[int, int, int]:
        self._check()
        return 0, 0, 0

    def queue_repages(self, *_: Any) -> int:
        self._check()
        return 0

    def claim_pages(self, *_: Any) -> list[dict[str, Any]]:
        self._check()
        return []

    def held_summary(self) -> tuple[int, int, str | None]:
        return 0, 0, None

    def state_get(self, _: str) -> str | None:
        self._check()
        return None

    def state_set(self, *_: str) -> None:
        self._check()

    def heartbeat_counts(self, *_: Any) -> dict[str, Any]:
        self._check()
        return {
            "oldest_pending_page_s": 0,
            "failed_last_24h": 0,
            "oldest_unassigned_alert_s": 0,
        }

    def reconcile_health(self) -> tuple[int, float | None]:
        return 0, None

    def backup_health(self) -> tuple[float, int | None]:
        return 0.0, None

    def posture_health(self) -> tuple[int, float | None]:
        return 0, None

    def rules_drift_health(self) -> int:
        return 0

    def reconcile_gap_s(self) -> int:
        return 0


def worker(db: StubDb, deadman: w.Deadman | None) -> w.Worker:
    ntfy = w.Ntfy("http://127.0.0.1:1", TOPIC, allow_http=True)  # never used by an idle pass
    return w.Worker(db, ntfy, {}, deadman=deadman)  # type: ignore[arg-type]


def test_a_good_pass_pings_and_a_failed_pass_does_not(monitor: FakeMonitor) -> None:
    clock = Clock()
    db = StubDb()
    d = w.Deadman(monitor.url, allow_http=True, clock=clock)
    wk = worker(db, d)
    assert wk.tick() is True
    d.wait(5)
    assert len(monitor.requests) == 1
    clock.now += 61
    db.down = True
    assert wk.tick() is False  # the database is gone: the pass is not good
    d.wait(5)
    assert len(monitor.requests) == 1  # no ping: the monitor's silence is the alarm
    clock.now += 61
    db.down = False
    assert wk.tick() is True
    d.wait(5)
    assert len(monitor.requests) == 2


def test_a_dead_or_slow_monitor_never_fails_or_slows_a_pass(monitor: FakeMonitor) -> None:
    monitor.delay = 2.0
    d = w.Deadman(monitor.url, allow_http=True, timeout=0.3)
    wk = worker(StubDb(), d)
    started = time.monotonic()
    assert wk.tick() is True
    assert time.monotonic() - started < 0.5
    d.wait(5)
    dead = w.Deadman(f"http://127.0.0.1:1{PING_PATH}", allow_http=True)
    assert worker(StubDb(), dead).tick() is True
    dead.wait(5)


def test_without_a_url_nothing_is_sent_and_a_pass_works(monitor: FakeMonitor) -> None:
    assert worker(StubDb(), None).tick() is True
    assert monitor.requests == []


def test_build_deadman_reads_the_setting(monitor: FakeMonitor) -> None:
    assert w.build_deadman(Settings(env="dev")) is None
    ok = w.build_deadman(Settings(env="dev", worker_deadman_url=monitor.url))  # type: ignore[arg-type]
    assert ok is not None
    # http is for local development only: in prod the same URL is refused.
    prod = Settings(
        env="prod",
        console_users="a@example.com",
        worker_deadman_url=monitor.url,  # type: ignore[arg-type]
    )
    assert w.build_deadman(prod) is None


def test_a_bad_url_does_not_stop_the_worker_and_is_never_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    bad = "http://hc.example.com/ping/s3cr3t-token"
    settings = Settings(
        env="prod",
        console_users="a@example.com",
        worker_deadman_url=bad,  # type: ignore[arg-type]
    )
    with caplog.at_level(logging.INFO, logger="soc_api.worker"):
        assert w.build_deadman(settings) is None
    assert "deadman outcome=invalid_url" in caplog.text
    assert "s3cr3t" not in caplog.text and "hc.example.com" not in caplog.text


def test_the_setting_never_shows_in_a_repr() -> None:
    settings = Settings(env="dev", worker_deadman_url="https://hc.example.com/ping/s3cr3t")  # type: ignore[arg-type]
    assert "s3cr3t" not in repr(settings)
