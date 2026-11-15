"""What the Ops Overview pages show, worked out from the one document ops_overview() returns.

The database gives plain numbers and cut text (migration 0012). This module decides what they
mean: which dot is green, amber or red, how a bar is drawn, how an age reads. It never
invents a figure: a number the database could not give is shown as "none yet" or not at
all, and the parts of the platform that are not built are named with the sprint that
delivers them. Nothing here reads a source's slug; the database never returns one.

Charts are server-rendered SVG: the page carries no chart library. Every number that
reaches an attribute is computed here and formatted with a fixed format, never taken as
text from the document.
"""

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from soc_api.banner import LIMITS
from soc_api.worker import stale_reasons

# Period as the URL says it -> (days, label). Anything else is refused by the route.
PERIODS = {"1": (1, "Today"), "7": (7, "7 days"), "30": (30, "30 days")}
DEFAULT_PERIOD = "7"
CLIENT_RE = re.compile(r"^[a-z0-9-]{1,64}$")

LANES = ("paged", "quiet", "vendor")
STATUSES = ("open", "acknowledged", "closed")

# The ATT&CK enterprise tactics, in kill-chain order. A tactic named in an alert is drawn
# only when it is one of these (after lower-casing and dropping punctuation); anything else
# is counted under "Other".
TACTICS = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
TACTIC_ALIASES = {
    "privilege esc": "Privilege Escalation",
    "command & control": "Command and Control",
}


def tactic_key(text: str) -> str:
    return re.sub(r"[^a-z0-9& ]+", " ", text.lower()).strip()


TACTIC_BY_KEY = {tactic_key(t): t for t in TACTICS} | TACTIC_ALIASES


def count(value: Any) -> int:
    """A count from the document: an int, else 0."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def dur(seconds: Any) -> str:
    """A length of time for a person: 4s, 12m 05s, 1h 52m, 3d 4h. 'none' when unknown."""
    s = number(seconds)
    if s is None:
        return "none"
    s = max(int(s), 0)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60:02d}m"
    return f"{s // 86400}d {(s % 86400) // 3600}h"


def ago(seconds: Any) -> str:
    """How long ago, as the mockup writes it: 4s, 12m, 1h 52m, 3d. 'never' when unknown."""
    s = number(seconds)
    if s is None:
        return "never"
    s = max(int(s), 0)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60:02d}m"
    return f"{s // 86400}d"


def utc_label(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%d %H:%M UTC")


def f1(value: float) -> str:
    return f"{value:.1f}"


# ---- filters ----


def parse_filters(period: str, client: str) -> tuple[str, int, str]:
    """(period key, days, client). Raises ValueError for anything outside the fixed sets
    or the slug syntax; whether the client exists is the database's answer."""
    if period not in PERIODS:
        raise ValueError("period")
    if client != "all" and not CLIENT_RE.fullmatch(client):
        raise ValueError("client")
    return period, PERIODS[period][0], client


def keep_query(period: str, client: str) -> str:
    """The query string that carries the filters from one tab to the next ('' for the
    defaults). Both parts are validated before they get here."""
    parts = []
    if period != DEFAULT_PERIOD:
        parts.append(f"period={period}")
    if client != "all":
        parts.append("client=" + quote(client, safe=""))
    return "?" + "&".join(parts) if parts else ""


def filter_links(period: str, client: str, clients: list[str], path: str) -> dict[str, Any]:
    # The template writes the leading "/" itself, so a link is always a path on this
    # site (never a javascript: or off-site URL); only the rest comes from here.
    def url(p: str, c: str) -> str:
        return path.lstrip("/") + keep_query(p, c)

    return {
        "periods": [
            {"label": label, "url": url(key, client), "on": key == period}
            for key, (_, label) in PERIODS.items()
        ],
        "clients": [{"label": "All clients", "url": url(period, "all"), "on": client == "all"}]
        + [{"label": c, "url": url(period, c), "on": c == client} for c in clients],
    }


# ---- the pieces ----


def title_line(data: dict[str, Any]) -> str:
    t = data["totals"]
    return (
        f"{count(t['alerts_in']):,} alerts in, {count(t['pages']):,} pages to a human, "
        f"{count(t['cases']):,} cases."
    )


def flow(data: dict[str, Any]) -> dict[str, Any]:
    """The signal-flow diagram: five nodes, each with the figures the database has. The two
    that are not built are drawn dashed and say which sprint delivers them."""
    f, h, t = data["flow"], data["health"], data["totals"]
    sensors_total, sensors_online = count(h["sensors_total"]), count(h["sensors_online"])
    p95 = number(f["pager_p95_s"])
    if sensors_total:
        sensor_line = f"{sensors_online} of {sensors_total} sensors reporting"
    else:
        sensor_line = "no sensor data yet"
    if count(f["pager_n"]):
        page_sub = f"p95 {f1(p95 or 0.0)} s created to sent"
    else:
        page_sub = "no page sent in this period"
    failed = count(f["pages_failed"])
    nodes: list[dict[str, Any]] = [
        {
            "title": "SOURCES",
            "big": f"{count(f['sources_enabled'])} of {count(f['sources_total'])}",
            "label": "enabled",
            "lines": [sensor_line],
            "planned": False,
        },
        {
            "title": "INGEST",
            "big": f"{count(t['alerts_in']):,}",
            "label": "alerts in",
            "lines": [
                f"newest {ago(f['last_alert_age_s'])} ago"
                if f["last_alert_age_s"] is not None
                else "no alert yet",
                f"catch-up last ran {ago(h['reconcile_quiet_s'])} ago"
                if count(h["reconcile_sources"])
                else "catch-up not set up",
                f"{count(t['cases'])} cases opened",
            ],
            "planned": False,
        },
        {
            "title": "PAGE",
            "big": f"{count(t['pages']):,}",
            "label": "pages to a human",
            "lines": [page_sub, f"{failed} failed" if failed else "none failed"],
            "planned": False,
        },
        {
            "title": "TRIAGE",
            "big": "Sprint 5",
            "label": "not built yet",
            "lines": ["LLM analyst"],
            "planned": True,
        },
        {
            "title": "RESPOND",
            "big": "Sprint 9",
            "label": "not built yet",
            "lines": ["guarded response"],
            "planned": True,
        },
    ]
    width, gap, x0 = 180, 50, 10
    for i, node in enumerate(nodes):
        node["x"] = x0 + i * (width + gap)
        node["cx"] = node["x"] + width // 2
    links = [
        {"d": f"M{nodes[i]['x'] + width} 110 L{nodes[i + 1]['x']} 110", "planned": i >= 2}
        for i in range(len(nodes) - 1)
    ]
    meta = (
        f"newest alert {ago(f['last_alert_age_s'])} ago · "
        + (
            f"catch-up ran {ago(h['reconcile_quiet_s'])} ago"
            if count(h["reconcile_sources"])
            else "catch-up not set up"
        )
        + " · "
        + (f"pager p95 {f1(p95)} s" if count(f["pager_n"]) and p95 is not None else "no pages yet")
    )
    return {"nodes": nodes, "links": links, "width": width, "meta": meta}


def lane_class(lane: Any) -> str:
    return lane if isinstance(lane, str) and lane in LANES else "other"


def queue(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for c in data["queue"]:
        verdict = c.get("verdict")
        rows.append(
            {
                "id": str(c["id"]),
                "short": str(c["id"])[:8],
                "severity": c["severity"],
                "status": c["status"],
                "summary": c.get("summary") or c.get("rule") or "",
                "host": c.get("host") or "",
                "lane": lane_class(c.get("lane")),
                "lane_label": str(c.get("lane") or "")
                if lane_class(c.get("lane")) != "other"
                else "other",
                # The analyst is not built. A case with no verdict is "not analyzed", never
                # "clean".
                "verdict": verdict if isinstance(verdict, str) and verdict else None,
                "age": ago(c.get("age_s")),
            }
        )
    return rows


def tactics(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Tactic counts, biggest first. Empty when no alert carries a hint."""
    totals: dict[str, int] = {}
    best: dict[str, tuple[int, str]] = {}
    for row in data["tactics"]:
        name = TACTIC_BY_KEY.get(tactic_key(str(row["tactic"])), "Other")
        n = count(row["n"])
        totals[name] = totals.get(name, 0) + n
        technique = row.get("technique")
        if technique and n > best.get(name, (0, ""))[0]:
            best[name] = (n, str(technique))
    top = max(totals.values(), default=0)
    return [
        {
            "name": name,
            "n": n,
            "tech": best.get(name, (0, ""))[1],
            "pct": f1(n / top * 100),
        }
        for name, n in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def funnel(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Cases opened in the period, by lane and then status, as segments of a bar."""
    by_lane: dict[str, dict[str, int]] = {}
    for row in data["funnel"]:
        lane = lane_class(row["lane"])
        status = row["status"] if row["status"] in STATUSES else "open"
        by_lane.setdefault(lane, {})
        by_lane[lane][status] = by_lane[lane].get(status, 0) + count(row["n"])
    most = max((sum(v.values()) for v in by_lane.values()), default=0)
    out = []
    for lane in (*LANES, "other"):
        counts = by_lane.get(lane)
        if not counts:
            continue
        total = sum(counts.values())
        x = 0.0
        segments = []
        for status in STATUSES:
            n = counts.get(status, 0)
            if not n:
                continue
            w = n / most * 100
            segments.append({"status": status, "n": n, "x": f1(x), "w": f1(w)})
            x += w
        out.append({"lane": lane, "total": total, "counts": counts, "segments": segments})
    return out


def response(data: dict[str, Any]) -> list[dict[str, Any]]:
    tiles = []
    for days in ("7", "30"):
        window = data["response"].get(days, {})
        for key, label, note in (
            ("mtta", "Mean time to acknowledge", "first page sent to first acknowledgement"),
            ("mttr", "Mean time to close", "case opened to closed"),
        ):
            part = window.get(key, {})
            n = count(part.get("n"))
            tiles.append(
                {
                    "label": f"{label} · {days} d",
                    "value": dur(part.get("avg_s")) if n else "none yet",
                    "note": f"{note} · {n} case{'s' if n != 1 else ''}",
                }
            )
    return tiles


def status_tiles(data: dict[str, Any]) -> list[dict[str, Any]]:
    h, f = data["health"], data["flow"]
    open_sev = data["open_by_severity"]
    open_total = sum(count(v) for v in open_sev.values())
    parts = [
        f"{count(open_sev[s])} {s}"
        for s in ("critical", "high", "medium", "low", "info")
        if count(open_sev.get(s))
    ]
    sensors_total = count(h["sensors_total"])
    online = count(h["sensors_online"])
    return [
        {
            "label": "Open cases",
            "value": str(open_total),
            "cls": "accent",
            "note": ", ".join(parts) or "none open",
        },
        {
            "label": "Pages waiting for an ack",
            "value": str(count(f["unacked_pages"])),
            "cls": "warn" if count(f["unacked_pages"]) else "up",
            "note": f"last acknowledgement {ago(f['last_ack_age_s'])} ago"
            if f["last_ack_age_s"] is not None
            else "no acknowledgement yet",
        },
        {
            "label": "Sensors online",
            "value": f"{online}/{sensors_total}" if sensors_total else "none",
            "cls": ("up" if online == sensors_total else "warn") if sensors_total else "setup",
            "note": "from the posture collector"
            if sensors_total
            else "the posture collector has not reported",
        },
        {
            "label": "Model spend",
            "value": "Sprint 5",
            "cls": "setup",
            "note": "not measured yet; no estimate is shown",
        },
    ]


def health(data: dict[str, Any]) -> list[dict[str, str]]:
    """The pipeline health list. The thresholds are the pager's own (worker.Limits), so a red
    dot here is a SOC STALE push there."""
    h, f = data["health"], data["flow"]
    firing = stale_reasons(
        {
            "oldest_pending_page_s": h["oldest_pending_page_s"],
            "failed_last_24h": h["failed_last_24h"],
            "oldest_unassigned_alert_s": h["oldest_unassigned_alert_s"],
        },
        count(h["reconcile_sources"]),
        number(h["reconcile_quiet_s"]),
        float(number(h["backup_age_s"]) or 0.0),
        LIMITS,
        count(h["posture_runs"]),
        number(h["posture_quiet_s"]),
    )
    rows: list[dict[str, str]] = []

    total, online = count(h["sensors_total"]), count(h["sensors_online"])
    if not total:
        sensors = ("idle", "no sensor data: the posture collector has not reported", "")
    elif firing["posture_quiet"]:
        sensors = ("down", f"{online} of {total} reporting; the sensor list is out of date", "")
    elif online < total:
        sensors = ("warn", f"{total - online} of {total} sensors offline", "")
    else:
        sensors = ("up", f"{total} enrolled, all reporting", "")
    rows.append(
        {
            "name": "Endpoint sensors",
            "state": sensors[0],
            "detail": sensors[1],
            "seen": ago(h["sensors_updated_age_s"]) if total else "",
        }
    )

    enabled, sources_total = count(f["sources_enabled"]), count(f["sources_total"])
    rows.append(
        {
            "name": "Alert sources",
            "state": "up" if enabled else "idle",
            "detail": f"{enabled} of {sources_total} enabled · webhook and catch-up"
            if sources_total
            else "no source configured",
            "seen": ago(f["last_alert_age_s"]) if f["last_alert_age_s"] is not None else "",
        }
    )

    sources = count(h["reconcile_sources"])
    quiet = number(h["reconcile_quiet_s"]) or 0.0
    if not sources:
        catchup = ("idle", "not set up")
    elif firing["reconcile_quiet"]:
        catchup = ("down", f"no completed run for {dur(quiet)}")
    elif count(h["reconcile_errors"]):
        catchup = (
            "warn",
            f"{count(h['reconcile_errors'])} sources with an error on their last run",
        )
    elif quiet > LIMITS.reconcile_stale_s / 2:
        catchup = ("warn", f"last completed run {dur(quiet)} ago")
    else:
        catchup = ("up", f"{sources} sources, every few minutes")
    rows.append(
        {
            "name": "Catch-up worker",
            "state": catchup[0],
            "detail": catchup[1],
            "seen": ago(quiet) if sources else "",
        }
    )

    pager_down = [
        text
        for key, text in (
            ("pages_pending", "a page is waiting to go out"),
            ("page_failed", "a page failed in the last 24 hours"),
            ("caser_behind", "alerts are not becoming cases"),
        )
        if firing[key]
    ]
    rows.append(
        {
            "name": "Pager and case builder",
            "state": "down" if pager_down else "up",
            "detail": "; ".join(pager_down) or "no page waiting, none failed, no alert unassigned",
            "seen": ago(h["last_page_sent_age_s"]) if h["last_page_sent_age_s"] is not None else "",
        }
    )

    runs = count(h["posture_runs"])
    org = h["org_errors"]
    if not runs:
        posture = ("idle", "not set up")
    elif firing["posture_quiet"]:
        posture = ("down", f"no good run for {dur(h['posture_quiet_s'])}")
    elif org is None:
        posture = ("up", "sensors and rules every 5 minutes; org errors not readable with this key")
    elif count(org):
        posture = ("warn", f"{count(org)} errors reported on the organization")
    else:
        posture = ("up", "sensors, rules and org errors every 5 minutes")
    rows.append(
        {
            "name": "Posture collector",
            "state": posture[0],
            "detail": posture[1],
            "seen": ago(h["posture_quiet_s"]) if runs else "",
        }
    )

    backup = float(number(h["backup_age_s"]) or 0.0)
    state = (
        "down" if firing["backup_old"] else ("warn" if backup > LIMITS.backup_stale_s / 2 else "up")
    )
    rows.append(
        {
            "name": "Database backups",
            "state": state,
            "detail": "last good dump",
            "seen": ago(backup),
        }
    )
    rows.append(
        {
            "name": "Email backup path",
            "state": "idle",
            "detail": "independent of the SOC service; not monitored here",
            "seen": "",
        }
    )
    rows.append(
        {"name": "LLM analyst", "state": "idle", "detail": "not built yet", "seen": "Sprint 5"}
    )
    return rows


# ---- the timeline ----

PLOT_L, PLOT_R, PLOT_T, PLOT_B = 44.0, 992.0, 24.0, 236.0
WIDTH, HEIGHT = 1000, 268
MAX_TYPES = 5  # the rest are drawn together as "other"


def nice_ceiling(value: int) -> int:
    """The next 'round' number at or above value, for the top of the y axis."""
    if value <= 4:
        return 4
    magnitude = 10 ** (len(str(value)) - 1)
    for step in (1, 2, 2.5, 5, 10):
        if value <= step * magnitude:
            return int(step * magnitude)
    return int(10 * magnitude)


def timeline(data: dict[str, Any]) -> dict[str, Any]:
    """The detection-volume chart: stacked columns per hour (day for 30 days), one color per
    SOURCE TYPE, with the deploys as dashed lines. Returned as drawing instructions."""
    tl = data["timeline"]
    unit_s = 86400 if tl["unit"] == "day" else 3600
    rows = [(int(r["t"]), r["c"]) for r in tl["rows"]]
    totals_by_type: dict[str, int] = {}
    for _, c in rows:
        for type_, n in c.items():
            totals_by_type[type_] = totals_by_type.get(type_, 0) + count(n)
    ranked = [t for t, _ in sorted(totals_by_type.items(), key=lambda kv: (-kv[1], kv[0]))]
    shown = ranked[:MAX_TYPES]
    has_other = len(ranked) > MAX_TYPES
    legend = [{"type": t, "cls": f"t{i}", "total": totals_by_type[t]} for i, t in enumerate(shown)]
    if has_other:
        legend.append(
            {
                "type": "other types",
                "cls": f"t{MAX_TYPES}",
                "total": sum(totals_by_type[t] for t in ranked[MAX_TYPES:]),
            }
        )

    def stack(c: dict[str, Any]) -> list[tuple[str, str, int]]:
        parts = [(t, f"t{i}", count(c.get(t))) for i, t in enumerate(shown)]
        if has_other:
            parts.append(
                ("other types", f"t{MAX_TYPES}", sum(count(c.get(t)) for t in ranked[MAX_TYPES:]))
            )
        return [p for p in parts if p[2] > 0]

    peak = max((sum(p[2] for p in stack(c)) for _, c in rows), default=0)
    top = nice_ceiling(peak)
    plot_w, plot_h = PLOT_R - PLOT_L, PLOT_B - PLOT_T
    n = max(len(rows), 1)
    slot = plot_w / n
    bar_w = max(slot * 0.78, 0.6)
    scale = plot_h / top

    bars: list[dict[str, str]] = []
    labels: list[dict[str, str]] = []
    for i, (t, c) in enumerate(rows):
        x = PLOT_L + i * slot + (slot - bar_w) / 2
        when = datetime.fromtimestamp(t, UTC)
        stamp = when.strftime("%b %d" if unit_s == 86400 else "%b %d %H:00 UTC")
        y = PLOT_B
        for type_, cls, n_alerts in stack(c):
            h = n_alerts * scale
            y -= h
            bars.append(
                {
                    "x": f1(x),
                    "y": f1(y),
                    "w": f1(bar_w),
                    "h": f1(h),
                    "cls": cls,
                    "tip": f"{stamp} · {type_}: {n_alerts}",
                }
            )
        every = 5 if unit_s == 86400 else (6 if len(rows) <= 30 else 24)
        if unit_s == 86400:
            show = i % every == 0
            text = when.strftime("%b %d")
        elif len(rows) <= 30:
            show = when.hour % every == 0
            text = when.strftime("%H:00")
        else:
            show = when.hour == 0
            text = when.strftime("%a %d")
        if show:
            labels.append({"x": f1(PLOT_L + i * slot + slot / 2), "text": text})

    ticks = [
        {"y": f1(PLOT_B - v * scale), "text": str(v)}
        for v in sorted({0, top // 4, top // 2, top * 3 // 4, top})
    ]
    first = rows[0][0] if rows else 0
    span = max(n * unit_s, 1)
    deploys = []
    for d in data["deploys"]:
        x = PLOT_L + (int(d["at"]) - first) / span * plot_w
        if PLOT_L <= x <= PLOT_R:
            deploys.append(
                {
                    "x": f1(x),
                    "sha": str(d["sha"])[:7],
                    "tip": f"deploy {str(d['sha'])[:7]} · {utc_label(int(d['at']))}",
                }
            )
    return {
        "width": WIDTH,
        "height": HEIGHT,
        "left": f1(PLOT_L),
        "right": f1(PLOT_R),
        "top": f1(PLOT_T),
        "bottom": f1(PLOT_B),
        "bars": bars,
        "labels": labels,
        "ticks": ticks,
        "deploys": deploys,
        "legend": legend,
        "unit": tl["unit"],
        "empty": peak == 0,
        "total": sum(totals_by_type.values()),
    }


# ---- the other pages ----


def fleet(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for s in data["fleet"]:
        online = bool(s["online"])
        state = "up" if online and not s["isolated"] else ("warn" if online else "down")
        rows.append(
            {
                "hostname": s["hostname"],
                "platform": s["platform"],
                "version": s.get("version") or "",
                "state": state,
                "label": ("isolated" if s["isolated"] else "online") if online else "offline",
                "last_seen": ago(s.get("last_seen_age_s")),
                "updated": ago(s.get("updated_age_s")),
            }
        )
    return rows


def sources(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for i, s in enumerate(data["sources"], start=1):
        catchup = s.get("catchup_age_s")
        if not s["has_cursor"]:
            catch_state, catch_text = "idle", "no catch-up"
        elif s.get("catchup_error"):
            catch_state, catch_text = "down", f"error {s['catchup_error']}"
        elif number(catchup) is not None and (number(catchup) or 0) > LIMITS.reconcile_stale_s:
            catch_state, catch_text = "down", f"last ran {ago(catchup)} ago"
        elif (number(catchup) or 0) > LIMITS.reconcile_stale_s / 2:
            catch_state, catch_text = "warn", f"last ran {ago(catchup)} ago"
        else:
            catch_state, catch_text = "up", f"last ran {ago(catchup)} ago"
        if not s["enabled"]:
            state = "idle"
        elif catch_state == "down":
            state = "down"
        elif catch_state == "warn" or s["last_alert_age_s"] is None:
            state = "warn"
        else:
            state = "up"
        rows.append(
            {
                "label": f"{s['type']} #{i}",
                "client": s["client"],
                "enabled": bool(s["enabled"]),
                "alerts": count(s["alerts"]),
                "last_alert": ago(s["last_alert_age_s"]),
                "catch_state": catch_state,
                "catch_text": catch_text,
                "state": state,
            }
        )
    return rows


def rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    top = max((count(r["alerts"]) for r in data["rules"]), default=0)
    return [
        {
            "rule": r["rule"] or "(no rule name)",
            "alerts": count(r["alerts"]),
            "cases": count(r["cases"]),
            "last": ago(r["last_age_s"]),
            "worst": r["worst"],
            "inventory": r.get("inventory") or "not listed",
            "pct": f1(count(r["alerts"]) / top * 100) if top else "0.0",
        }
        for r in data["rules"]
    ]


def clock(epoch: float | None = None) -> dict[str, str]:
    now = datetime.fromtimestamp(epoch, UTC) if epoch else datetime.now(UTC)
    return {
        "epoch": str(int(now.timestamp())),
        "time": now.strftime("%H:%M:%S"),
        "date": now.strftime("%a, %b %d · UTC"),
    }
