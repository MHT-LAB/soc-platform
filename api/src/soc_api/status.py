"""Live status gathered for the console.

Every probe has a short timeout and returns a result instead of raising, so a
slow or broken dependency shows up as a red light on the console rather than
breaking the page.
"""

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx2

from soc_api.config import Settings

PROBE_TIMEOUT = 3.0
FLEET_CACHE_SECONDS = 60

LC_JWT_URL = "https://jwt.limacharlie.io"
LC_API = "https://api.limacharlie.io/v1"

# Platform codes from LimaCharlie's SDK (go-limacharlie identification.go).
# Codes not listed here display as "Adapter" with the hex code.
PLATFORMS = {
    0x10000000: "Windows",
    0x20000000: "Linux",
    0x30000000: "macOS",
    0x40000000: "iOS",
    0x50000000: "Android",
    0x60000000: "ChromeOS",
    0x70000000: "VPN",
    0x80000000: "Syslog (text)",
    0x90000000: "JSON adapter",
    0x0A000000: "Syslog (CEF)",
    0x1A000000: "Email adapter",
}


def platform_name(code: int) -> str:
    return PLATFORMS.get(code, f"Adapter 0x{code:08X}")


@dataclass
class TunnelStatus:
    state: str  # "up" | "down" | "unknown"
    connections: int = 0
    detail: str = ""


@dataclass
class Sensor:
    hostname: str
    platform: str
    online: bool
    last_seen: str


@dataclass
class Fleet:
    configured: bool
    sensors: list[Sensor] = field(default_factory=list)
    error: str = ""
    checked_at: float = 0.0

    @property
    def online(self) -> int:
        return sum(1 for s in self.sensors if s.online)


async def tunnel_status(settings: Settings) -> TunnelStatus:
    """Ask cloudflared how many edge connections it holds."""
    try:
        async with httpx2.AsyncClient(timeout=PROBE_TIMEOUT) as client:
            r = await client.get(settings.tunnel_ready_url)
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        n = int(body.get("readyConnections", 0))
        if r.status_code == 200 and n > 0:
            return TunnelStatus("up", n)
        return TunnelStatus("down", n, f"HTTP {r.status_code}")
    except (httpx2.HTTPError, ValueError) as exc:
        return TunnelStatus("unknown", 0, type(exc).__name__)


_fleet_cache: Fleet | None = None


async def _list_sensors(
    client: httpx2.AsyncClient, oid: str, headers: dict[str, str], online_only: bool
) -> list[dict[str, object]]:
    """All pages of GET /sensors/{oid}. The online filter is `is_online_only`;
    unknown parameters are silently ignored by the API, so a wrong name returns
    every sensor (a bug this project shipped once; see test_fleet.py)."""
    out: list[dict[str, object]] = []
    params: dict[str, str] = {"is_online_only": "true"} if online_only else {}
    for _ in range(50):  # hard stop on runaway pagination
        r = await client.get(f"{LC_API}/sensors/{oid}", headers=headers, params=params)
        r.raise_for_status()
        body = r.json()
        out.extend(body.get("sensors", []))
        token = body.get("continuation_token")
        if not token:
            break
        params = {**params, "continuation_token": token}
    return out


async def sensor_fleet(
    settings: Settings, transport: httpx2.AsyncBaseTransport | None = None
) -> Fleet:
    """Sensors from the EDR platform, read-only, cached for a minute."""
    global _fleet_cache
    if not settings.lc_oid or not settings.lc_api_key.get_secret_value():
        return Fleet(configured=False)
    if _fleet_cache and time.monotonic() - _fleet_cache.checked_at < FLEET_CACHE_SECONDS:
        return _fleet_cache

    oid = settings.lc_oid
    try:
        async with httpx2.AsyncClient(timeout=PROBE_TIMEOUT * 2, transport=transport) as client:
            tok = await client.post(
                LC_JWT_URL,
                data={"oid": oid, "secret": settings.lc_api_key.get_secret_value()},
            )
            tok.raise_for_status()
            headers = {"Authorization": f"Bearer {tok.json()['jwt']}"}
            everyone = await _list_sensors(client, oid, headers, online_only=False)
            online = await _list_sensors(client, oid, headers, online_only=True)
    except (httpx2.HTTPError, KeyError, ValueError) as exc:
        # Never echo response bodies: they could contain tokens or tenant data.
        return Fleet(configured=True, error=type(exc).__name__)

    online_ids = {s.get("sid") for s in online}
    sensors = []
    for s in everyone:
        hostname = str(s.get("hostname", "?"))
        if hostname.startswith("ext-"):
            continue  # the platform's own extension service sensors, not sources
        sensors.append(
            Sensor(
                hostname=hostname,
                platform=platform_name(int(str(s.get("plat", 0)))),
                online=s.get("sid") in online_ids,
                last_seen=str(s.get("alive", "")),
            )
        )
    sensors.sort(key=lambda s: (not s.online, s.hostname))
    _fleet_cache = Fleet(configured=True, sensors=sensors, checked_at=time.monotonic())
    return _fleet_cache


def utc_now() -> str:
    return datetime.now(UTC).strftime("%H:%M UTC · %a %b %d")
