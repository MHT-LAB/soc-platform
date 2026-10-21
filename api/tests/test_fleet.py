"""Regression tests for the sensor fleet lookup.

The first version asked for online sensors with a parameter the API doesn't
know. The API ignored it and returned every sensor, so the console showed the
whole fleet as online. These tests pin the real contract with a fake API.
"""

import asyncio

import httpx2
import pytest
from pydantic import SecretStr

from soc_api import status
from soc_api.config import Settings

OID = "00000000-0000-0000-0000-000000000000"

SENSORS = [
    {"sid": "s1", "hostname": "ws-demo-01", "plat": 0x20000000, "alive": "2026-10-17 18:00:00"},
    {"sid": "s2", "hostname": "ws-demo-02", "plat": 0x10000000, "alive": "2026-10-16 09:00:00"},
    {"sid": "s3", "hostname": "gw-demo", "plat": 0x0A000000, "alive": "2026-10-17 18:01:00"},
    {"sid": "s4", "hostname": "ext-yara", "plat": 0x90000000, "alive": "2026-10-17 18:02:00"},
    {"sid": "s5", "hostname": "legacy-feed", "plat": 0x80000000, "alive": "2026-10-17 04:00:00"},
]
ONLINE = {"s1", "s3", "s4"}


def fake_api(seen: list[httpx2.Request]) -> httpx2.MockTransport:
    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        if request.url.host == "jwt.limacharlie.io":
            return httpx2.Response(200, json={"jwt": "test-token"})
        assert request.headers["Authorization"] == "Bearer test-token"
        rows = SENSORS
        if request.url.params.get("is_online_only") == "true":
            rows = [s for s in SENSORS if s["sid"] in ONLINE]
        # Two pages, to prove pagination is followed.
        if "continuation_token" in request.url.params:
            return httpx2.Response(200, json={"sensors": rows[2:]})
        return httpx2.Response(200, json={"sensors": rows[:2], "continuation_token": "p2"})

    return httpx2.MockTransport(handler)


@pytest.fixture(autouse=True)
def no_cache() -> None:
    status._fleet_cache = None


def settings() -> Settings:
    return Settings(lc_oid=OID, lc_api_key=SecretStr("test-key"))


def test_online_state_comes_from_the_online_only_query() -> None:
    seen: list[httpx2.Request] = []
    fleet = asyncio.run(status.sensor_fleet(settings(), transport=fake_api(seen)))
    by_name = {s.hostname: s for s in fleet.sensors}

    assert by_name["ws-demo-01"].online is True
    assert by_name["gw-demo"].online is True
    assert by_name["ws-demo-02"].online is False
    assert by_name["legacy-feed"].online is False
    assert fleet.online == 2
    assert any(r.url.params.get("is_online_only") == "true" for r in seen)


def test_extension_sensors_hidden_and_platforms_named() -> None:
    fleet = asyncio.run(status.sensor_fleet(settings(), transport=fake_api([])))
    by_name = {s.hostname: s for s in fleet.sensors}
    assert "ext-yara" not in by_name
    assert by_name["gw-demo"].platform == "Syslog (CEF)"
    assert by_name["legacy-feed"].platform == "Syslog (text)"
    assert status.platform_name(0x12345678) == "Adapter 0x12345678"


def test_api_failure_reports_error_without_leaking_body() -> None:
    def broken(_: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(401, text="secret-looking body")

    fleet = asyncio.run(status.sensor_fleet(settings(), transport=httpx2.MockTransport(broken)))
    assert fleet.configured and fleet.error == "HTTPStatusError"
    assert "secret" not in fleet.error


def test_unconfigured_without_key() -> None:
    fleet = asyncio.run(status.sensor_fleet(Settings()))
    assert fleet.configured is False


def run_fleet(handler: object) -> status.Fleet:
    transport = httpx2.MockTransport(handler)  # type: ignore[arg-type]
    return asyncio.run(status.sensor_fleet(settings(), transport=transport))


def test_odd_sensor_values_degrade_instead_of_raising() -> None:
    rows = [
        {"sid": "s1", "hostname": "ws-demo-01", "plat": None, "alive": "2026-10-17 18:00:00"},
        {"sid": ["not", "hashable"], "hostname": "ws-demo-02", "plat": "linux"},
        {"sid": "s3", "hostname": "gw-demo", "plat": [1]},
        "not an object",
    ]

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "jwt.limacharlie.io":
            return httpx2.Response(200, json={"jwt": "test-token"})
        return httpx2.Response(200, json={"sensors": rows})

    fleet = run_fleet(handler)
    assert fleet.error == "" and len(fleet.sensors) == 3
    assert {s.platform for s in fleet.sensors} == {"Adapter 0x00000000"}


def test_unexpected_response_shape_is_an_error_light_not_a_crash() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "jwt.limacharlie.io":
            return httpx2.Response(200, json={"jwt": "test-token"})
        return httpx2.Response(200, json=["a", "list"])

    fleet = run_fleet(handler)
    assert fleet.configured and fleet.error == "ValueError"


def test_non_object_token_response_is_an_error_light() -> None:
    fleet = run_fleet(lambda _: httpx2.Response(200, json=["no", "jwt"]))
    assert fleet.configured and fleet.error == "TypeError"


def test_fleet_is_marked_partial_when_pagination_hits_the_cap() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "jwt.limacharlie.io":
            return httpx2.Response(200, json={"jwt": "test-token"})
        return httpx2.Response(
            200,
            json={"sensors": [{"sid": "s1", "hostname": "ws-demo-01"}], "continuation_token": "x"},
        )

    fleet = run_fleet(handler)
    assert fleet.partial is True and fleet.error == ""


def test_complete_fleet_is_not_partial() -> None:
    fleet = asyncio.run(status.sensor_fleet(settings(), transport=fake_api([])))
    assert fleet.partial is False


@pytest.mark.parametrize(
    "payload", [{"readyConnections": None}, ["a", "list"], {"readyConnections": "many"}]
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
