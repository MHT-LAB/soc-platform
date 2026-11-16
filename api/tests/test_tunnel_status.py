"""The edge tunnel probe: what the console says about cloudflared's /ready.

(The sensor fleet is no longer fetched from the EDR platform; see test_console_fleet.py.)
"""

import asyncio

import httpx2
import pytest

from soc_api import status
from soc_api.config import Settings


@pytest.mark.parametrize(
    "payload",
    [{"readyConnections": None}, ["a", "list"], {"readyConnections": "many"}, {"status": 200}],
)
def test_tunnel_status_tolerates_odd_ready_payloads(
    payload: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_client = httpx2.AsyncClient
    transport = httpx2.MockTransport(lambda _: httpx2.Response(200, json=payload))
    monkeypatch.setattr(
        status.httpx2, "AsyncClient", lambda **kw: real_client(transport=transport, **kw)
    )
    result = asyncio.run(status.tunnel_status(Settings()))
    assert result.state == "unknown" and result.detail == "unexpected response"


def ready_response(monkeypatch: pytest.MonkeyPatch, response: httpx2.Response) -> None:
    real_client = httpx2.AsyncClient
    transport = httpx2.MockTransport(lambda _: response)
    monkeypatch.setattr(
        status.httpx2, "AsyncClient", lambda **kw: real_client(transport=transport, **kw)
    )


def test_tunnel_status_reads_cloudflared_text_plain_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """cloudflared's /ready sends JSON without a JSON content type (seen on CT 110)."""
    body = (
        b'{"status":200,"readyConnections":4,"connectorId":"00000000-0000-0000-0000-000000000000"}'
    )
    ready_response(
        monkeypatch,
        httpx2.Response(200, content=body, headers={"content-type": "text/plain; charset=utf-8"}),
    )
    result = asyncio.run(status.tunnel_status(Settings()))
    assert (result.state, result.connections) == ("up", 4)


def test_tunnel_status_non_json_body_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    ready_response(monkeypatch, httpx2.Response(200, content=b"<html>proxy</html>"))
    assert asyncio.run(status.tunnel_status(Settings())).state == "unknown"


def test_tunnel_status_zero_connections_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b'{"status":503,"readyConnections":0}'
    ready_response(monkeypatch, httpx2.Response(503, content=body))
    result = asyncio.run(status.tunnel_status(Settings()))
    assert (result.state, result.detail) == ("down", "HTTP 503")
