"""The living signal flow: sensors on the left, alerts flowing into cases, paged or quiet.

Drawn the way the original console mockup draws it: a fleet panel (one icon per sensor,
grouped), then bars joined by bands whose widths follow the real counts for the selected
period. Everything here is arithmetic on the one document ops_overview() returns; no
figure is invented and no source slug is ever read (the database does not return one).

The page carries only server-built SVG. The motion is a CSS animation on dashed lines
(console.css), switched off under prefers-reduced-motion; there is no script and no style
attribute. Every number that reaches an attribute is computed here with a fixed format.

Sensor kinds, until clients and sites exist: endpoints (square), network sensors (diamond:
syslog and VPN adapters) and vendor feeds (triangle: every other adapter, such as email).
A sensor's state is one of three:

* up: reporting.
* quiet: an adapter or syslog source that has sent no message for longer than the posture
  interval. Rare-event sources (a router's system log) are healthy when quiet, so this is
  amber, never red.
* down: an endpoint that stopped reporting. Red on the tiles, health list and Fleet tab.
"""

import re
from typing import Any

from soc_api.status import platform_name

# What the platform name of a sensor says about its kind. Names come from
# status.PLATFORMS and the posture collector ("Windows", "Syslog (CEF)", "Email adapter",
# "Adapter 0x...", or "Unknown" when the vendor sent no platform).
ENDPOINT_PLATFORMS = frozenset(
    {"windows", "linux", "macos", "ios", "android", "chromeos", "unknown"}
)

KINDS = ("endpoint", "network", "feed")
KIND_WORDS = {
    "endpoint": ("endpoint", "endpoints", "Endpoints"),
    "network": ("network sensor", "network sensors", "Network sensors"),
    "feed": ("vendor feed", "vendor feeds", "Vendor feeds"),
}
SHAPES = {"endpoint": "M3 3h12v12H3z", "network": "M9 1l8 8-8 8-8-8z", "feed": "M9 2l8 14H1z"}

# canvas and stage geometry (the mockup's 1120-wide canvas)
WIDTH, HEIGHT = 1120, 400
PANEL_X, PANEL_Y, PANEL_W, PANEL_H = 16, 16, 270, 368
COLS = {"alerts": 340, "cases": 540, "lane": 740, "incidents": 940}
BAR_W = 10
MAX_BAR = 200.0
MIN_BAR = 6.0
MIN_FEED = 3.0
CENTER_Y = 190.0
LANE_TOP = 90.0
LANE_GAP = 40.0
ICONS_PER_GROUP = 20
ICONS_PER_ROW = 10


def kind_of(platform: Any) -> str:
    name = str(platform or "").strip().lower()
    if name in ENDPOINT_PLATFORMS:
        return "endpoint"
    if name.startswith("syslog") or name == "vpn":
        return "network"
    return "feed"


ORIGIN_KINDS = (*KINDS, "unknown")
_PLAT_RE = re.compile(r"[0-9]{1,10}")
FEED_WORDS = {
    "endpoint": "from endpoints",
    "network": "from network",
    "feed": "from vendor feeds",
    "unknown": "from other",
}


def origin_kind(plat: Any) -> str:
    """Where an alert came from, from the platform code in its own routing: 'endpoint',
    'network', 'feed' (any other adapter) or 'unknown' (no usable code). This is the Python
    twin of the CASE in ops_overview() (migration 0016); a test makes them agree. A code is
    a whole number of at most ten digits (as a number or as the text the database sees)."""
    text = str(plat) if isinstance(plat, int) and not isinstance(plat, bool) else plat
    if not isinstance(text, str) or not _PLAT_RE.fullmatch(text):
        return "unknown"
    return kind_of(platform_name(int(text)))


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _ago(seconds: Any) -> str:
    s = _num(seconds)
    if s is None:
        return "never"
    n = max(int(s), 0)
    if n < 60:
        return f"{n}s"
    if n < 3600:
        return f"{n // 60}m"
    if n < 86400:
        return f"{n // 3600}h {(n % 3600) // 60:02d}m"
    return f"{n // 86400}d"


def sensor_state(row: dict[str, Any]) -> str:
    """'up', 'quiet' (an adapter with no message lately) or 'down' (an endpoint that stopped)."""
    if row.get("online"):
        return "up"
    return "down" if kind_of(row.get("platform")) == "endpoint" else "quiet"


def sensors(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Every sensor with its kind, state and the words for it, problems first."""
    out = []
    for row in data.get("fleet") or []:
        kind = kind_of(row.get("platform"))
        state = sensor_state(row)
        seen = _ago(row.get("last_seen_age_s"))
        if state == "up":
            words = "online, isolated" if row.get("isolated") else "online"
        elif state == "quiet":
            words = f"quiet · last message {seen} ago"
        else:
            words = f"offline · last seen {seen} ago"
        out.append(
            {
                "kind": kind,
                "state": state,
                "isolated": bool(row.get("isolated")),
                "hostname": str(row.get("hostname") or ""),
                "platform": str(row.get("platform") or ""),
                "seen_s": _num(row.get("last_seen_age_s")),
                "seen": seen,
                "words": words,
                "version": str(row.get("version") or ""),
                "updated_age_s": row.get("updated_age_s"),
            }
        )
    out.sort(key=lambda s: (s["state"] == "up", s["hostname"]))
    return out


def summary(data: dict[str, Any]) -> dict[str, int | float | None]:
    """Counts by kind and state, for the tile and the health list. A document with no
    fleet list (older or partial) falls back to the plain online/total numbers, all
    counted as endpoints."""
    rows = sensors(data)
    h = data.get("health", {})
    if not rows and _count(h.get("sensors_total")):
        total, online = _count(h["sensors_total"]), _count(h.get("sensors_online"))
        return {
            "endpoints": total,
            "endpoints_online": online,
            "sources": 0,
            "sources_quiet": 0,
            "longest_quiet_s": None,
        }
    endpoints = [s for s in rows if s["kind"] == "endpoint"]
    sources = [s for s in rows if s["kind"] != "endpoint"]
    quiet = [s["seen_s"] for s in sources if s["state"] == "quiet" and s["seen_s"] is not None]
    return {
        "endpoints": len(endpoints),
        "endpoints_online": sum(1 for s in endpoints if s["state"] == "up"),
        "sources": len(sources),
        "sources_quiet": sum(1 for s in sources if s["state"] == "quiet"),
        "longest_quiet_s": max(quiet) if quiet else None,
    }


# ---- the fleet panel ----


def _plural(kind: str, n: int) -> str:
    one, many, _ = KIND_WORDS[kind]
    return f"{n} {one if n == 1 else many}"


def groups(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One group per kind, laid out inside the panel."""
    out = []
    y = PANEL_Y + 44.0
    for kind in KINDS:
        members = [s for s in rows if s["kind"] == kind]
        shown = members[:ICONS_PER_GROUP]
        problems = [s for s in members if s["state"] != "up"]
        parts = [_plural(kind, len(members))]
        offline = sum(1 for s in members if s["state"] == "down")
        quiet = sum(1 for s in members if s["state"] == "quiet")
        if offline:
            parts.append(f"{offline} offline")
        if quiet:
            parts.append(f"{quiet} quiet")
        icons = []
        for i, s in enumerate(shown):
            icons.append(
                {
                    "x": f"{PANEL_X + 14 + (i % ICONS_PER_ROW) * 24}",
                    "y": f"{y + 26 + (i // ICONS_PER_ROW) * 24:.0f}",
                    "d": SHAPES[kind],
                    "on": s["state"] == "up",
                    "title": f"{KIND_WORDS[kind][0]} · {s['platform']} · {s['words']}",
                    "host": s["hostname"],
                }
            )
        rows_used = max((len(shown) + ICONS_PER_ROW - 1) // ICONS_PER_ROW, 1)
        height = 26 + rows_used * 24 + 10
        out.append(
            {
                "kind": kind,
                "name": KIND_WORDS[kind][2],
                "count": " · ".join(parts) if members else "none enrolled",
                "problem": bool(offline or quiet),
                "more": f"+{len(members) - len(shown)} more" if len(members) > len(shown) else "",
                "more_x": f"{PANEL_X + 14}",
                "more_y": f"{y + 26 + rows_used * 24 + 2:.0f}",
                "icons": icons,
                "y": f"{y:.0f}",
                "mid_y": y + 7,
                "has_up": any(s["state"] == "up" for s in members),
                "any": bool(members),
                "n_problems": len(problems),
                "origin": "",
                "origin_zero": False,
            }
        )
        y += height + 12
    return out


# ---- the bands ----


def _band(xa: float, a0: float, a1: float, xb: float, b0: float, b1: float) -> str:
    m = (xa + xb) / 2
    return (
        f"M{xa:.1f} {a0:.1f} C{m:.1f} {a0:.1f} {m:.1f} {b0:.1f} {xb:.1f} {b0:.1f} "
        f"L{xb:.1f} {b1:.1f} C{m:.1f} {b1:.1f} {m:.1f} {a1:.1f} {xa:.1f} {a1:.1f} Z"
    )


def _mid(xa: float, a0: float, a1: float, xb: float, b0: float, b1: float) -> str:
    m = (xa + xb) / 2
    ya, yb = (a0 + a1) / 2, (b0 + b1) / 2
    return f"M{xa:.1f} {ya:.1f} C{m:.1f} {ya:.1f} {m:.1f} {yb:.1f} {xb:.1f} {yb:.1f}"


def origins(data: dict[str, Any]) -> dict[str, int] | None:
    """Alert counts by origin kind for the period, or None for a document that has none."""
    raw = data.get("origins")
    if not isinstance(raw, dict):
        return None
    return {k: _count(raw.get(k)) for k in ORIGIN_KINDS}


def feed_curves(
    data: dict[str, Any], grp: list[dict[str, Any]], xa: float, a0: float, ha: float
) -> tuple[list[dict[str, Any]], dict[str, str] | None, str]:
    """The curves from the fleet groups into "alerts in".

    With the period's alert counts by origin, each group's curve is a band whose thickness
    follows that group's share of the alerts (at least MIN_FEED while it has any), stacked
    on the left edge of the alerts bar, with a "N from endpoints" label on the group. A
    group that sent none is a dashed hairline. Alerts of unknown origin get a small grey
    curve from the foot of the panel, labelled "other", only when there are any. Without the
    counts (an older document) each group with sensors gets one plain dashed curve.
    Also returns the words for the drawing's text description."""
    x0 = float(PANEL_X + PANEL_W)
    counts = origins(data)
    if counts is None:
        out = []
        active = [g for g in grp if g["any"]]
        for i, grp_ in enumerate(active):
            ty = a0 + ha * (i + 0.5) / len(active)
            out.append(
                {
                    "d": _curve(x0, grp_["mid_y"], xa, ty),
                    "kind": grp_["kind"],
                    "on": grp_["has_up"],
                }
            )
        return out, None, ""

    total = sum(counts.values())
    shown = [k for k in ORIGIN_KINDS if counts[k] or (k != "unknown" and _group(grp, k)["any"])]
    thick = {k: max(counts[k] / total * ha, MIN_FEED) if counts[k] else 0.0 for k in shown}
    stack = sum(thick.values())
    y = CENTER_Y - stack / 2
    out = []
    unknown_label = ""
    for k in shown:
        g = _group(grp, k) if k != "unknown" else None
        sy = g["mid_y"] if g else PANEL_Y + PANEL_H - 14.0
        w = thick[k]
        n = counts[k]
        label = f"{n:,} {FEED_WORDS[k]}"
        if g:
            g["origin"] = label
            g["origin_zero"] = not n
        else:
            unknown_label = label
        on = bool(g["has_up"]) if g else False
        if n:
            out.append(
                {
                    "d": _band(x0, sy - w / 2, sy + w / 2, xa, y, y + w),
                    "mid": _mid(x0, sy - w / 2, sy + w / 2, xa, y, y + w),
                    "kind": k,
                    "on": on,
                    "zero": False,
                    "w": f"{w:.1f}",
                }
            )
        else:
            out.append({"d": _curve(x0, sy, xa, y), "kind": k, "on": on, "zero": True})
        y += w
    other = None
    if counts["unknown"]:
        other = {
            "x": f"{PANEL_X + PANEL_W - 14}",
            "y": f"{PANEL_Y + PANEL_H - 10}",
            "text": unknown_label,
        }
    words = ", ".join(f"{counts[k]:,} {FEED_WORDS[k]}" for k in ORIGIN_KINDS if counts[k])
    return out, other, (f" By origin: {words}." if words else "")


def _group(grp: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    return next(g for g in grp if g["kind"] == kind)


def _curve(xa: float, ya: float, xb: float, yb: float) -> str:
    m = (xa + xb) / 2
    return f"M{xa:.1f} {ya:.1f} C{m:.1f} {ya:.1f} {m:.1f} {yb:.1f} {xb:.1f} {yb:.1f}"


def _period_words(days: int) -> str:
    return "today" if days == 1 else f"{days} days"


def build(data: dict[str, Any]) -> dict[str, Any]:
    """Everything the template draws."""
    totals = data["totals"]
    f = data["flow"]
    days = _count(data.get("period_days")) or 7
    alerts = _count(totals["alerts_in"])
    cases = _count(totals["cases"])
    by_lane: dict[str, int] = {}
    for row in data.get("funnel") or []:
        lane = str(row.get("lane"))
        by_lane[lane] = by_lane.get(lane, 0) + _count(row.get("n"))
    paged = min(by_lane.get("paged", 0), cases)
    quiet = max(cases - paged, 0)
    vendor = min(by_lane.get("vendor", 0), quiet)

    scale = MAX_BAR / max(alerts, cases, 1)
    hp = max(paged * scale, MIN_BAR) if paged else 0.0
    hq = max(quiet * scale, MIN_BAR) if quiet else 0.0
    hc = max(cases * scale, MIN_BAR, hp + hq)
    ha = max(alerts * scale, MIN_BAR, hc)

    xa, xc, xl, xi = (float(COLS[k]) for k in ("alerts", "cases", "lane", "incidents"))
    a0 = CENTER_Y - ha / 2
    c0 = CENTER_Y - hc / 2
    p0 = LANE_TOP
    q0 = LANE_TOP + hp + (LANE_GAP if hp else 0.0)
    bars = [
        {"x": f"{xa:.0f}", "y": f"{a0:.1f}", "h": f"{ha:.1f}", "cls": "bar", "zero": not alerts},
        {"x": f"{xc:.0f}", "y": f"{c0:.1f}", "h": f"{hc:.1f}", "cls": "bar", "zero": not cases},
    ]
    if hp:
        bars.append(
            {"x": f"{xl:.0f}", "y": f"{p0:.1f}", "h": f"{hp:.1f}", "cls": "bar", "zero": False}
        )
    if hq:
        bars.append(
            {
                "x": f"{xl:.0f}",
                "y": f"{q0:.1f}",
                "h": f"{hq:.1f}",
                "cls": "bar quiet",
                "zero": False,
            }
        )

    bands = [
        {
            "d": _band(xa + BAR_W, a0, a0 + ha, xc, c0, c0 + hc),
            "mid": _mid(xa + BAR_W, a0, a0 + ha, xc, c0, c0 + hc),
            "cls": "alerts",
            "speed": "s1",
            "still": not cases,
        }
    ]
    if hp:
        bands.append(
            {
                "d": _band(xc + BAR_W, c0, c0 + hp, xl, p0, p0 + hp),
                "mid": _mid(xc + BAR_W, c0, c0 + hp, xl, p0, p0 + hp),
                "cls": "paged",
                "speed": "s2",
                "still": False,
            }
        )
    if hq:
        bands.append(
            {
                "d": _band(xc + BAR_W, c0 + hp, c0 + hp + hq, xl, q0, q0 + hq),
                "mid": _mid(xc + BAR_W, c0 + hp, c0 + hp + hq, xl, q0, q0 + hq),
                "cls": "quiet",
                "speed": "s3",
                "still": False,
            }
        )

    # Incidents are not a concept in the data yet: drawn dashed, with the sprint that
    # delivers them, as the old box flow drew triage and respond.
    inc_h = 24.0
    inc_y = (p0 + hp / 2 if hp else LANE_TOP + 12) - inc_h / 2
    incident = {
        "x": f"{xi:.0f}",
        "y": f"{inc_y:.1f}",
        "h": f"{inc_h:.0f}",
        "d": _mid(xl + BAR_W, p0, p0 + max(hp, 2.0), xi, inc_y, inc_y + inc_h),
    }

    p95 = _num(f.get("pager_p95_s"))
    if _count(f.get("pager_n")) and p95 is not None:
        paged_sub = f"to a human · p95 {p95:.1f} s"
    else:
        paged_sub = "to a human · none sent yet"
    quiet_sub = "logged, nobody paged" + (f" · {vendor} vendor" if vendor else "")

    def label(x: float, y: float, num: int, title: str, sub: str, cls: str) -> dict[str, str]:
        return {
            "x": f"{x:.0f}",
            "y": f"{y:.0f}",
            "num": f"{num:,}",
            "title": title,
            "sub": sub,
            "cls": cls,
        }

    labels = [
        label(
            xa + 18, a0 + ha + 14, alerts, "ALERTS IN", f"every source, {_period_words(days)}", "lg"
        ),
        label(xc + 18, 14, cases, "CASES", "alerts grouped into cases", "lg"),
        label(xl + 18, 14, paged, "PAGED", paged_sub, "lg"),
    ]
    if hq:
        labels.append(label(xl + 18, q0 + 2, quiet, "QUIET LANE", quiet_sub, "sm"))
    elif not quiet:
        labels.append(label(xl + 18, 214, 0, "QUIET LANE", quiet_sub, "sm"))
    incident_label = {"x": f"{xi + 18:.0f}", "y": "14", "title": "INCIDENTS", "sub": "Sprint 5 / 9"}

    rows = sensors(data)
    grp = groups(rows)
    feeds, other, origin_text = feed_curves(data, grp, xa, a0, ha)
    on = sum(1 for s in rows if s["state"] == "up")
    return {
        "width": WIDTH,
        "height": HEIGHT,
        "panel": {"x": PANEL_X, "y": PANEL_Y, "w": PANEL_W, "h": PANEL_H},
        "reporting": f"{on} of {len(rows)} reporting" if rows else "no sensor data yet",
        "all_up": bool(rows) and on == len(rows),
        "groups": grp,
        "feeds": feeds,
        "other": other,
        "bars": bars,
        "bands": bands,
        "labels": labels,
        "incident": incident,
        "incident_label": incident_label,
        "aria": (
            f"Signal flow for {_period_words(days)}: {alerts:,} alerts in, {cases:,} cases, "
            f"{paged:,} paged to a human, {quiet:,} in the quiet lane; {on} of {len(rows)} "
            f"sensors reporting.{origin_text}"
        ),
    }
