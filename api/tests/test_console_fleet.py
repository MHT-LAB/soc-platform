"""The System page's sensor panel reads the database, never the EDR platform (R19).

The console runs on the host network, so it is the one container that sees the host's LAN and
loopback services. It used to hold a read-only EDR key and call the EDR API on every page view.
The posture collector already stores the same fleet, so the console now reads those rows (the
document behind the Fleet tab) and holds no key. These tests use a fake database, so they need
no Postgres.
"""

import copy
import re
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient
from test_ops_overview_unit import doc

from soc_api import console as console_module
from soc_api import overview as ov
from soc_api import status
from soc_api.cases import CasesUnavailable
from soc_api.config import Settings
from soc_api.main import create_console_app

TAILNET = {"Tailscale-User-Login": "operator@example.com"}
SRC = Path(__file__).resolve().parents[1] / "src" / "soc_api"
COMPOSE = Path(__file__).resolve().parents[2] / "deploy" / "compose.yml"


def sensor(host: str, plat: str, online: bool, seen: int, isolated: bool = False) -> dict[str, Any]:
    return {
        "hostname": host,
        "platform": plat,
        "version": "1",
        "online": online,
        "isolated": isolated,
        "last_seen_age_s": seen,
        "updated_age_s": 40,
    }


FLEET = [
    # Hostnames come from endpoints, so they are attacker-controlled.
    sensor("<script>alert(1)</script>", "linux", True, 4),
    sensor("ws-demo-02", "windows", False, 10800),
]


class FakeDb:
    """Stands in for CaseDb: the two calls the System page makes."""

    def __init__(self, data: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self.data = data if data is not None else doc(fleet=copy.deepcopy(FLEET))
        self.error = error
        self.overview_calls: list[tuple[int, str]] = []

    def console_health(self) -> dict[str, Any]:
        health: dict[str, Any] = self.data["health"]
        return health

    def rules_metrics(self, client: str) -> dict[str, Any]:
        return {"rules": [], "tactics": [], "deployed_at": None}

    def ops_overview(self, days: int, client: str) -> dict[str, Any]:
        self.overview_calls.append((days, client))
        if self.error:
            raise self.error
        return self.data


@pytest.fixture
def no_tunnel(monkeypatch: pytest.MonkeyPatch) -> None:
    async def tunnel(_: Settings) -> status.TunnelStatus:
        return status.TunnelStatus("up", 4)

    monkeypatch.setattr(status, "tunnel_status", tunnel)


@pytest.fixture
def no_outbound(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Any HTTP request made through httpx2 (what the console would use to call the EDR
    platform) fails the test and is recorded. Only the test client's own request to the
    in-process app (host "testserver") goes through. The tunnel probe is faked by `no_tunnel`."""
    calls: list[str] = []
    real_async, real_sync = httpx2.AsyncClient.send, httpx2.Client.send

    def refuse_async(self: Any, request: httpx2.Request, **kw: Any) -> Any:
        if request.url.host == "testserver":
            return real_async(self, request, **kw)
        calls.append(str(request.url))
        raise AssertionError(f"the console made an outbound call: {request.url}")

    def refuse_sync(self: Any, request: httpx2.Request, **kw: Any) -> Any:
        if request.url.host == "testserver":
            return real_sync(self, request, **kw)
        calls.append(str(request.url))
        raise AssertionError(f"the console made an outbound call: {request.url}")

    monkeypatch.setattr(httpx2.AsyncClient, "send", refuse_async)
    monkeypatch.setattr(httpx2.Client, "send", refuse_sync)
    return calls


def page(monkeypatch: pytest.MonkeyPatch, fake: FakeDb) -> Any:
    monkeypatch.setattr(console_module, "case_db", lambda _settings: fake)
    app = create_console_app(Settings(version="edge", git_sha="a" * 40))
    return TestClient(app).get("/console", headers=TAILNET)


# ---- the page shows what the collector stored, and calls nothing ----


def test_the_system_page_shows_the_posture_collectors_sensors_and_calls_no_one(
    monkeypatch: pytest.MonkeyPatch, no_tunnel: None, no_outbound: list[str]
) -> None:
    fake = FakeDb()
    r = page(monkeypatch, fake)
    assert r.status_code == 200
    assert no_outbound == []
    assert fake.overview_calls == [(1, "all")]  # the cheapest window, whole organization
    assert "ws-demo-02" in r.text and "offline" in r.text and "3h 00m" in r.text
    assert "1/2" in r.text  # the summary tile
    assert "1 of 2 reporting" in r.text  # the pipeline's Sources stage
    assert "last good run 1m ago" in r.text  # posture_quiet_s 100 in the shared test document
    assert "Connect the EDR platform" not in r.text
    assert "Sensor list out of date" not in r.text


def test_hostnames_from_endpoints_are_still_escaped(
    monkeypatch: pytest.MonkeyPatch, no_tunnel: None
) -> None:
    r = page(monkeypatch, FakeDb())
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;" in r.text


def test_a_control_character_in_a_hostname_is_shown_as_a_code_not_sent_raw(
    monkeypatch: pytest.MonkeyPatch, no_tunnel: None
) -> None:
    fleet = [sensor("ws‮gpj.exe", "windows", True, 5)]  # right-to-left override
    r = page(monkeypatch, FakeDb(doc(fleet=fleet)))
    assert "‮" not in r.text and "⟦U+202E⟧" in r.text


def test_an_out_of_date_list_is_flagged_with_the_pagers_own_limit(
    monkeypatch: pytest.MonkeyPatch, no_tunnel: None
) -> None:
    data = doc(fleet=copy.deepcopy(FLEET))
    data["health"]["posture_quiet_s"] = 5 * 3600.0
    r = page(monkeypatch, FakeDb(data))
    assert "Sensor list out of date" in r.text and "OUT OF DATE" in r.text
    assert "last good run 5h 00m ago" in r.text
    assert "list 5h 00m old" in r.text  # the pipeline's Sources stage is "unknown", not up


def test_a_collector_that_has_never_run_says_so(
    monkeypatch: pytest.MonkeyPatch, no_tunnel: None
) -> None:
    data = doc(fleet=[])
    data["health"].update(posture_runs=0, posture_quiet_s=None)
    r = page(monkeypatch, FakeDb(data))
    assert r.status_code == 200
    assert "No sensor data yet" in r.text and "posture collector has not reported" in r.text
    assert "UNKNOWN" not in r.text.split("Sensors reporting")[1][:200]


def test_an_unreachable_database_degrades_the_panel_not_the_page(
    monkeypatch: pytest.MonkeyPatch, no_tunnel: None
) -> None:
    r = page(monkeypatch, FakeDb(error=CasesUnavailable()))
    assert r.status_code == 200
    assert "read the sensor data" in r.text  # "Couldn't read ..." (the apostrophe is escaped)
    assert "The database cannot be reached" in r.text
    assert "4 connections" in r.text  # the tunnel tile still works


def test_isolated_and_quiet_sensors_get_their_own_words() -> None:
    fleet = [
        sensor("ws-iso", "windows", True, 3, isolated=True),
        sensor("gw-syslog", "Syslog (CEF)", False, 7200),
    ]
    result = ov.system_fleet(doc(fleet=fleet))
    by_host = {s.hostname: s for s in result.sensors}
    assert (by_host["ws-iso"].state, by_host["ws-iso"].label) == ("warn", "isolated")
    assert by_host["ws-iso"].online is True
    assert by_host["gw-syslog"].state == "warn" and "quiet" in by_host["gw-syslog"].label
    assert by_host["gw-syslog"].online is False


def test_the_overview_health_list_is_unchanged_by_sharing_the_stale_check() -> None:
    data = doc(fleet=copy.deepcopy(FLEET))
    assert ov.stale_firing(data)["posture_quiet"] is False
    data["health"]["posture_quiet_s"] = 5 * 3600.0
    assert ov.stale_firing(data)["posture_quiet"] is True
    rows = {r["name"]: r for r in ov.health(data)}
    assert rows["Endpoint sensors"]["state"] == "down"


# ---- the console really has no key and no way to call out ----


def test_the_console_service_is_given_no_edr_key_file() -> None:
    lines = COMPOSE.read_text().splitlines()
    start = lines.index("  console:")
    end = next(i for i in range(start + 1, len(lines)) if re.match(r"^  [a-z][\w-]*:$", lines[i]))
    code = "\n".join(line for line in lines[start:end] if not line.lstrip().startswith("#"))
    assert "env/console.env" in code and "env/console-db.env" in code
    assert "lc.env" not in code and "SOC_LC_" not in code


def test_only_the_collectors_know_the_edr_api_addresses() -> None:
    """The posture and catch-up workers (and their settings) are the only code that may name
    the EDR API or its token service. The console's status module no longer does."""
    allowed = {"config.py", "reconcile.py"}
    offenders = [
        p.name
        for p in sorted(SRC.glob("*.py"))
        if p.name not in allowed and re.search(r"(api|jwt)\.limacharlie\.io", p.read_text())
    ]
    assert offenders == []
    assert not hasattr(status, "sensor_fleet")
    assert "lc_api_key" not in Settings.model_fields and "lc_oid" not in Settings.model_fields


def test_a_leftover_edr_key_in_the_environment_does_not_break_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guard for the rollout, not a fix: a host that still has the old file can deploy this
    build first and delete the file afterwards. Unknown SOC_* variables are ignored."""
    monkeypatch.setenv("SOC_LC_API_KEY", "leftover-secret")
    monkeypatch.setenv("SOC_LC_OID", "00000000-0000-0000-0000-000000000000")
    create_console_app(Settings(version="edge", git_sha="a" * 40))
