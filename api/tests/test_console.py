import pytest
from fastapi.testclient import TestClient

from soc_api import status
from soc_api.config import Settings
from soc_api.console import CONSOLE_CSP
from soc_api.main import create_app

TAILNET = {"Tailscale-User-Login": "operator@example.com"}


@pytest.fixture
def fake_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    async def tunnel(_: Settings) -> status.TunnelStatus:
        return status.TunnelStatus("up", 4)

    async def fleet(_: Settings) -> status.Fleet:
        return status.Fleet(
            configured=True,
            sensors=[
                # Hostnames come from endpoints, so they are attacker-controlled.
                status.Sensor("<script>alert(1)</script>", "Linux", True, "2026-10-17 18:00:00"),
                status.Sensor("ws-demo-02", "Windows", False, "2026-10-16 09:12:00"),
            ],
        )

    monkeypatch.setattr(status, "tunnel_status", tunnel)
    monkeypatch.setattr(status, "sensor_fleet", fleet)


def client(**overrides: str) -> TestClient:
    return TestClient(create_app(Settings(version="edge", git_sha="a" * 40, **overrides)))


def test_console_refuses_requests_without_tailnet_identity(fake_probes: None) -> None:
    for path in ("/console", "/console/console.css"):
        assert client().get(path).status_code == 403


def test_console_allowlist_is_enforced(fake_probes: None) -> None:
    c = client(console_users="someone-else@example.com")
    assert c.get("/console", headers=TAILNET).status_code == 403
    c = client(console_users="Operator@Example.com")
    assert c.get("/console", headers=TAILNET).status_code == 200


def test_console_renders_live_state(fake_probes: None) -> None:
    r = client().get("/console", headers=TAILNET)
    assert r.status_code == 200
    assert "4 connections" in r.text
    assert "1/2" in r.text
    assert "operator@example.com" in r.text


def test_console_escapes_sensor_hostnames(fake_probes: None) -> None:
    r = client().get("/console", headers=TAILNET)
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;" in r.text


def test_console_has_its_own_strict_csp(fake_probes: None) -> None:
    r = client().get("/console", headers=TAILNET)
    assert r.headers["Content-Security-Policy"] == CONSOLE_CSP
    assert "script-src" not in CONSOLE_CSP  # no scripts allowed at all
    assert (
        client().get("/healthz").headers["Content-Security-Policy"].startswith("default-src 'none'")
    )


def test_unconfigured_fleet_shows_setup_state(monkeypatch: pytest.MonkeyPatch) -> None:
    async def tunnel(_: Settings) -> status.TunnelStatus:
        return status.TunnelStatus("unknown", 0, "ConnectError")

    monkeypatch.setattr(status, "tunnel_status", tunnel)
    r = client().get("/console", headers=TAILNET)
    assert r.status_code == 200
    assert "Connect the EDR platform" in r.text
    assert "UNKNOWN" in r.text
