"""The one-line record every rotate command leaves for the operator's log."""

from datetime import datetime

from soc_api.rotate import state as st
from soc_api.rotate.keys import printable


def record_line(now: datetime, run_id: str, action: str, result: str, **fields: str | int) -> str:
    """Ids (last four characters only), dates and counts: never a key, never a value."""
    parts = [f"rotate {st.stamp(now)} {action}"]
    parts += [f"{k}={printable(str(v), 64).replace(' ', '_')}" for k, v in fields.items()]
    parts += [f"result={result}", f"run={run_id}"]
    return " ".join(parts)
