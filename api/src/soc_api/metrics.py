"""Prometheus text for the console's /metrics page.

The numbers come from the database (pipeline_metrics(), migration 0009), because the API,
the pager worker and the catch-up worker are separate containers and in-process counters
would not add up. This module only turns those rows into text. A label value is accepted
only if it is a page kind from a fixed list or a histogram bound; anything else is dropped, so
nothing a sender wrote can reach the output. Source slugs are never labels: a slug is the secret
part of the public webhook path.
"""

import re
from collections.abc import Iterable

# metric key in the function's rows -> (exposed name, type, help)
COUNTERS = {
    "alerts_ingested": (
        "soc_alerts_ingested_total",
        "Alerts stored (all sources; a source's name is never a label).",
        None,
    ),
    "alerts_grouped": (
        "soc_alerts_grouped_total",
        "Alerts that joined a case that already existed.",
        None,
    ),
    "alerts_late": (
        "soc_alerts_late_total",
        "Alerts stored over 5 minutes after they were detected (the catch-up worker's finds).",
        None,
    ),
    "pages_sent": ("soc_pages_sent_total", "Pushes sent, per kind.", "kind"),
    "pages_failed": ("soc_pages_failed_total", "Pushes that failed.", None),
    "cases_acked": ("soc_cases_acknowledged_total", "Cases acknowledged by a person.", None),
}
KINDS = {"page", "repage1", "repage2"}
BOUND = re.compile(r"^[0-9]{1,6}$")
HISTOGRAM = "soc_ack_latency_seconds"
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def render(rows: Iterable[tuple[str, str, float]]) -> str:
    """Prometheus text format from (metric, label, value) rows."""
    series: dict[str, list[tuple[str, float]]] = {}
    for metric, label, value in rows:
        series.setdefault(metric, []).append((label, float(value)))
    out: list[str] = []
    for key, (name, text, label_name) in COUNTERS.items():
        out += [f"# HELP {name} {text}", f"# TYPE {name} counter"]
        for label, value in sorted(series.get(key, [])):
            if label_name is None:
                if label == "":
                    out.append(f"{name} {number(value)}")
            elif label_name == "kind" and label in KINDS:
                out.append(f'{name}{{{label_name}="{label}"}} {number(value)}')
    out += [
        f"# HELP {HISTOGRAM} Seconds from the first push for a case to its acknowledgement.",
        f"# TYPE {HISTOGRAM} histogram",
    ]
    buckets = sorted(
        (int(label), value)
        for label, value in series.get("ack_latency_bucket", [])
        if BOUND.match(label)
    )
    count = next((v for _, v in series.get("ack_latency_count", [])), 0.0)
    total = next((v for _, v in series.get("ack_latency_sum", [])), 0.0)
    for bound, value in buckets:
        out.append(f'{HISTOGRAM}_bucket{{le="{bound}"}} {number(value)}')
    out.append(f'{HISTOGRAM}_bucket{{le="+Inf"}} {number(count)}')
    out.append(f"{HISTOGRAM}_sum {number(total)}")
    out.append(f"{HISTOGRAM}_count {number(count)}")
    return "\n".join(out) + "\n"
