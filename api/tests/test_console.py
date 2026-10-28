from typing import Literal

import pytest
from fastapi.testclient import TestClient

from soc_api import status
from soc_api.config import Settings
from soc_api.console import CONSOLE_CSP
from soc_api.main import create_app, create_console_app

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
    return TestClient(create_console_app(Settings(version="edge", git_sha="a" * 40, **overrides)))


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


def test_partial_fleet_is_flagged_on_the_console(monkeypatch: pytest.MonkeyPatch) -> None:
    async def tunnel(_: Settings) -> status.TunnelStatus:
        return status.TunnelStatus("up", 4)

    async def fleet(_: Settings) -> status.Fleet:
        return status.Fleet(
            configured=True,
            sensors=[status.Sensor("ws-demo-01", "Linux", True, "2026-10-17 18:00:00")],
            partial=True,
        )

    monkeypatch.setattr(status, "tunnel_status", tunnel)
    monkeypatch.setattr(status, "sensor_fleet", fleet)
    r = client().get("/console", headers=TAILNET)
    assert r.status_code == 200
    assert "Partial fleet" in r.text and "1/1+" in r.text


# --- identity: a forged Tailscale-User-Login header must not get anyone in ----------


def prod_client(users: str = "operator@example.com") -> TestClient:
    settings = Settings(env="prod", console_users=users, version="edge", git_sha="a" * 40)
    return TestClient(create_console_app(settings))


def test_forged_login_header_is_refused_in_prod(fake_probes: None) -> None:
    c = prod_client()
    forged = [
        "attacker@example.com",
        "operator@example.org",
        "evil-operator@example.com",
        "attacker@example.com, operator@example.com",
        "operator@example.com,attacker@example.com",
    ]
    for login in forged:
        r = c.get("/console", headers={"Tailscale-User-Login": login})
        assert r.status_code == 403, login
        assert "not on the console allowlist" in r.text
    assert c.get("/console").status_code == 403
    assert c.get("/console", headers={"Tailscale-User-Login": "  "}).status_code == 403
    assert (
        c.get("/console/console.css", headers={"Tailscale-User-Login": forged[0]}).status_code
        == 403
    )


def test_allowlisted_login_gets_in_ignoring_case_and_spaces(fake_probes: None) -> None:
    c = prod_client("Operator@Example.com , second@example.com")
    for login in ("operator@example.com", "OPERATOR@EXAMPLE.COM", "second@example.com"):
        assert c.get("/console", headers={"Tailscale-User-Login": login}).status_code == 200


# --- isolation: the public app has no console, whatever the request says -------------


def public_client(env: Literal["dev", "prod"] = "prod") -> TestClient:
    settings = Settings(
        env=env, console_users="operator@example.com", version="edge", git_sha="a" * 40
    )
    return TestClient(create_app(settings))


def test_public_app_has_no_console_even_with_a_forged_identity(fake_probes: None) -> None:
    for env in ("prod", "dev"):
        c = public_client(env)
        for path in ("/console", "/console/", "/console/console.css"):
            for headers in ({}, TAILNET, {"Tailscale-User-Login": "operator@example.com"}):
                r = c.get(path, headers=headers)
                assert r.status_code == 404, (env, path)
                assert "Operations" not in r.text and "operator@example.com" not in r.text


def test_public_app_routes_are_exactly_the_public_ones() -> None:
    # dev exposes /openapi.json, which lists every route the app really has.
    r = public_client("dev").get("/openapi.json")
    assert set(r.json()["paths"]) == {"/healthz", "/version"}


def test_console_app_serves_only_console_and_healthz() -> None:
    settings = Settings(env="dev", version="edge", git_sha="a" * 40)
    r = TestClient(create_console_app(settings)).get("/openapi.json")
    assert set(r.json()["paths"]) == {
        "/healthz",
        "/console",
        "/console/console.css",
        "/console/cases",
        "/console/case/{case_id}",
        "/console/case/{case_id}/ack",
        "/console/case/{case_id}/ack-phone",
        "/console/case/{case_id}/close",
    }
    assert prod_client().get("/version").status_code == 404
