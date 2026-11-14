"""The console's degraded banner: the pipeline conditions the pager already treats as STALE.

The numbers come from console_health() (migration 0010); the decision is the worker's own
stale_reasons() with its default limits, so the banner and the "SOC STALE" push can never
disagree about a threshold. The text names the condition and how old it is, in fixed
sentences with numbers only: nothing from a client, an alert or the database's own error
messages.
"""

from typing import Any

from soc_api.worker import Limits, stale_reasons

LIMITS = Limits()

UNREADABLE = "Pipeline health cannot be read: the console cannot reach the database."


def age(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 1:
        return "under a minute"
    if minutes < 120:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} hours"
    return f"{hours // 24} days"


def notices(health: dict[str, Any]) -> list[str]:
    """One sentence per condition that holds; an empty list when the pipeline is healthy."""
    quiet = health["reconcile_quiet_s"]
    firing = stale_reasons(
        {
            "oldest_pending_page_s": health["oldest_pending_page_s"],
            "failed_last_24h": health["failed_last_24h"],
            "oldest_unassigned_alert_s": health["oldest_unassigned_alert_s"],
        },
        int(health["reconcile_sources"]),
        None if quiet is None else float(quiet),
        float(health["backup_age_s"]),
        LIMITS,
    )
    out: list[str] = []
    if firing["pages_pending"]:
        out.append(f"A page has been waiting to go out for {age(health['oldest_pending_page_s'])}.")
    if firing["page_failed"]:
        out.append("A page failed to send in the last 24 hours.")
    if firing["caser_behind"]:
        out.append(
            "New alerts are not becoming cases: the oldest has waited "
            f"{age(health['oldest_unassigned_alert_s'])}."
        )
    if firing["reconcile_quiet"]:
        out.append(f"The catch-up worker has not completed a run for {age(float(quiet or 0))}.")
    if firing["backup_old"]:
        out.append(f"The last good database backup is {age(float(health['backup_age_s']))} old.")
    return out
