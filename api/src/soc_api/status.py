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

# Platform codes reported by the EDR platform's sensor API.
PLATFORMS = {
    0x10000000: "Windows",
    0x20000000: "Linux",
    0x30000000: "macOS",
    0x80000000: "Adapter",
    0x90000000: "Extension",
}


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


async def sensor_fleet(settings: Settings) -> Fleet:
    """Endpoint sensors from the EDR platform, read-only, cached for a minute."""
    global _fleet_cache
    if not settings.lc_oid or not settings.lc_api_key.get_secret_value():
        return Fleet(configured=False)
    if _fleet_cache and time.monotonic() - _fleet_cache.checked_at < FLEET_CACHE_SECONDS:
        return _fleet_cache

    try:
        async with httpx2.AsyncClient(timeout=PROBE_TIMEOUT * 2) as client:
            tok = await client.post(
                "https://jwt.limacharlie.io",
                data={"oid": settings.lc_oid, "secret": settings.lc_api_key.get_secret_value()},
            )
            tok.raise_for_status()
            headers = {"Authorization": f"Bearer {tok.json()['jwt']}"}
            base = f"https://api.limacharlie.io/v1/sensors/{settings.lc_oid}"
            everyone = await client.get(base, headers=headers)
            online = await client.get(base, headers=headers, params={"is_online": "true"})
            everyone.raise_for_status()
            online.raise_for_status()
    except (httpx2.HTTPError, KeyError, ValueError) as exc:
        # Never echo response bodies: they could contain tokens or tenant data.
        return Fleet(configured=True, error=type(exc).__name__)

    online_ids = {s.get("sid") for s in online.json().get("sensors", [])}
    sensors = []
    for s in everyone.json().get("sensors", []):
        platform = PLATFORMS.get(int(s.get("plat", 0)), "Other")
        if platform == "Extension":
            continue  # platform-internal service sensors, not endpoints
        sensors.append(
            Sensor(
                hostname=str(s.get("hostname", "?")),
                platform=platform,
                online=s.get("sid") in online_ids,
                last_seen=str(s.get("alive", "")),
            )
        )
    sensors.sort(key=lambda s: (not s.online, s.hostname))
    _fleet_cache = Fleet(configured=True, sensors=sensors, checked_at=time.monotonic())
    return _fleet_cache


def utc_now() -> str:
    return datetime.now(UTC).strftime("%H:%M UTC · %a %b %d")
