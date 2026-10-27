"""soc_api.selftest: a signed synthetic detection the real route accepts, with
nothing secret in its output."""

import json
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from soc_api import selftest
from soc_api.config import Settings
from soc_api.ingest import SIGNATURE_HEADER, Alert, StoreUnavailable, build_router

SECRET = "s3cret-" + "x" * 40  # noqa: S105 - throwaway test value
SOURCE = "lc-selftest0123456"


class FakeStore:
    def __init__(self) -> None:
        self.rows: dict[str, Alert] = {}

    def insert(self, source: str, alert: Alert) -> str:
        if alert.event_id in self.rows:
            return "duplicate"
        self.rows[alert.event_id] = alert
        return "inserted"


def make_client(store: Any) -> TestClient:
    settings = Settings(
        env="dev",
        ingest_secrets=json.dumps({SOURCE: [SECRET, "next-" + "y" * 40]}),  # type: ignore[arg-type]
    )
    app = FastAPI()
    app.include_router(build_router(settings, store))
    return TestClient(app)


@contextmanager
def serve(client: TestClient) -> Iterator[str]:
    """Expose the in-process app on a real local port, so selftest's own HTTP client is used."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            resp = client.post(
                self.path,
                content=body,
                headers={
                    "content-type": self.headers.get("content-type", ""),
                    SIGNATURE_HEADER: self.headers.get(SIGNATURE_HEADER, ""),
                },
            )
            self.send_response(resp.status_code)
            self.end_headers()

        def log_message(self, *args: object) -> None:  # silence
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_INGEST_SECRETS", json.dumps({SOURCE: [SECRET, "next-" + "y" * 40]}))


def test_the_real_route_accepts_the_selftest_and_stores_it_once(
    env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    store = FakeStore()
    with serve(make_client(store)) as url:
        assert selftest.main(["--url", url, "--repeat"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 2
    assert out[0] == out[1]
    assert out[0].startswith("status=200 detect_id=selftest-")
    # two deliveries of the same body, one stored row
    assert len(store.rows) == 1
    alert = next(iter(store.rows.values()))
    assert alert.rule == selftest.SELFTEST_RULE
    assert alert.tenant == selftest.SELFTEST_OID  # matches no real source: lands in Unassigned


def test_each_run_uses_a_new_detection_id(env: None, capsys: pytest.CaptureFixture[str]) -> None:
    store = FakeStore()
    with serve(make_client(store)) as url:
        assert selftest.main(["--url", url]) == 0
        assert selftest.main(["--url", url]) == 0
    capsys.readouterr()
    assert len(store.rows) == 2


def test_output_never_contains_the_secret_signature_or_body(
    env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    store = FakeStore()
    with serve(make_client(store)) as url:
        selftest.main(["--url", url, "--repeat"])
    out = capsys.readouterr()
    text = out.out + out.err
    body = selftest.build_body("x", 1).decode()
    assert SECRET not in text
    assert "next-" not in text
    assert SOURCE not in text
    assert "soc-selftest" not in text  # the rule name is body content
    assert body[:20] not in text
    assert set(text.split()) <= {t for t in text.split() if t.startswith(("status=", "detect_id="))}


def test_a_wrong_secret_is_reported_as_401_and_exits_nonzero(
    env: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = FakeStore()
    with serve(make_client(store)) as url:
        monkeypatch.setenv("SOC_INGEST_SECRETS", json.dumps({SOURCE: ["z" * 40]}))
        assert selftest.main(["--url", url]) == 1
    assert capsys.readouterr().out.startswith("status=401 ")
    assert store.rows == {}


def test_a_database_outage_shows_as_503(env: None, capsys: pytest.CaptureFixture[str]) -> None:
    class Down:
        def insert(self, source: str, alert: Alert) -> str:
            raise StoreUnavailable

    with serve(make_client(Down())) as url:
        assert selftest.main(["--url", url]) == 1
    assert capsys.readouterr().out.startswith("status=503 ")


def test_an_unreachable_app_is_reported_without_details(
    env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert selftest.main(["--url", "http://127.0.0.1:1"]) == 1
    assert capsys.readouterr().out.startswith("status=unreachable ")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x", "127.0.0.1:8080", "http://"])
def test_only_http_urls_are_accepted(
    env: None, url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert selftest.main(["--url", url]) == 2
    assert "http(s)" in capsys.readouterr().out


def test_without_secrets_it_says_where_to_run_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SOC_INGEST_SECRETS", raising=False)
    assert selftest.main([]) == 2
    assert "inside the api container" in capsys.readouterr().out


def test_unknown_source_is_refused_without_sending(
    env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert selftest.main(["--source", "nope"]) == 2
    assert "not configured" in capsys.readouterr().out


def test_a_malformed_secrets_setting_does_not_echo_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOC_INGEST_SECRETS", '{"a": "' + SECRET)
    assert selftest.main([]) == 2
    out = capsys.readouterr().out
    assert SECRET not in out


@pytest.mark.parametrize("url", ["file:///etc/hosts", "data:,hello"])
def test_post_itself_cannot_open_anything_but_http(url: str) -> None:
    # Even called directly, past main()'s scheme check, nothing is read.
    assert selftest.post(url, b"{}", "0" * 64) == "unreachable"


def test_a_redirect_is_not_followed(env: None, capsys: pytest.CaptureFixture[str]) -> None:
    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            # 303 is the redirect urllib follows for a POST (as a GET).
            self.send_response(303)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Redirect)
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert selftest.main(["--url", f"http://127.0.0.1:{server.server_port}"]) == 1
    finally:
        server.shutdown()
        server.server_close()
    assert capsys.readouterr().out.startswith("status=303 ")
