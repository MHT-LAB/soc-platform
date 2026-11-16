"""Live status gathered for the console.

Every probe has a short timeout and returns a result instead of raising, so a
slow or broken dependency shows up as a red light on the console rather than
breaking the page.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx2

from soc_api.config import Settings

PROBE_TIMEOUT = 3.0

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


def as_int(value: object, default: int = 0) -> int:
    """Best-effort int for values from outside APIs. Odd data (None, a list, text)
    becomes the default instead of an exception, so it shows up as a red or
    unknown light rather than a 500."""
    if isinstance(value, int | float | str):
        try:
            return int(value)
        except (ValueError, OverflowError):
            pass
    return default


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
    last_seen: str  # how long ago, in words ("3m", "1h 52m", "never")
    state: str = ""  # colour class: up, warn or down
    label: str = ""  # the words on the chip


@dataclass
class Fleet:
    """The sensor panel. It comes from the posture collector's rows in the database (the same
    data as the Fleet tab); the console holds no EDR key and calls no EDR API."""

    configured: bool
    sensors: list[Sensor] = field(default_factory=list)
    error: str = ""
    # Why the panel is empty when `configured` is False.
    setup_note: str = ""
    # How long ago the collector's last good run was, in words, and whether that is older
    # than the pager's own limit (the sensor list may then be wrong).
    posture_age: str = ""
    stale: bool = False

    @property
    def online(self) -> int:
        return sum(1 for s in self.sensors if s.online)


async def tunnel_status(settings: Settings) -> TunnelStatus:
    """Ask cloudflared how many edge connections it holds."""
    try:
        async with httpx2.AsyncClient(timeout=PROBE_TIMEOUT) as client:
            r = await client.get(settings.tunnel_ready_url)
        # cloudflared sends its JSON as text/plain, so parse the body whatever the
        # content type says (a body that isn't JSON raises ValueError: unknown).
        body = r.json()
        # A 200 with a body we can't read says nothing about the tunnel: unknown, not down.
        n = as_int(body.get("readyConnections"), -1) if isinstance(body, dict) else -1
        if n < 0:
            return TunnelStatus("unknown", 0, "unexpected response")
        if r.status_code == 200 and n > 0:
            return TunnelStatus("up", n)
        return TunnelStatus("down", n, f"HTTP {r.status_code}")
    except (httpx2.HTTPError, ValueError) as exc:
        return TunnelStatus("unknown", 0, type(exc).__name__)


def utc_now() -> str:
    return datetime.now(UTC).strftime("%H:%M UTC · %a %b %d")
