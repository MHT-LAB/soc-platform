"""Work out what is due: dates, status per key, the plan and its short hash.

A key is due `period_days` after it was last rotated (or on the date a person set when they
recorded it). The monthly session is the first Monday of the month; a key that would go
overdue before the session after next is done at the next session, so nothing trickles in
between. The plan hash covers the register commit and exactly the automatic keys the plan
would rotate: an approval is good for that plan and no other.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from soc_api.rotate.keys import KeyFile, Register, printable
from soc_api.rotate.state import KeyState, State

DUE_SOON_DAYS = 7
ACTIONABLE = ("overdue", "no_record", "due_soon", "this_session")
RANK = {"overdue": 0, "no_record": 1, "due_soon": 2, "this_session": 3, "ok": 4, "not_ready": 5}


def local_today(moment: datetime) -> date:
    """The calendar day in New York, where the sessions and the calendar hold are kept."""
    return moment.astimezone(ZoneInfo("America/New_York")).date()


def first_monday(year: int, month: int) -> date:
    first = date(year, month, 1)
    return first + timedelta(days=(7 - first.weekday()) % 7)


def session_on_or_after(day: date) -> date:
    this_month = first_monday(day.year, day.month)
    if this_month >= day:
        return this_month
    year, month = (day.year + 1, 1) if day.month == 12 else (day.year, day.month + 1)
    return first_monday(year, month)


def following_session(session: date) -> date:
    return session_on_or_after(session + timedelta(days=1))


@dataclass(frozen=True)
class Row:
    key: KeyFile
    last: date | None
    due: date | None
    status: str  # overdue | no_record | due_soon | this_session | ok | not_ready
    revoke_pending: bool

    def days_text(self, today: date) -> str:
        if self.due is None:
            return "no record of a last rotation"
        days = (self.due - today).days
        return f"{-days} days overdue" if days < 0 else f"in {days} days"


def classify(key: KeyFile, ks: KeyState | None, today: date, after: date) -> Row:
    pending = bool(ks and ks.revoke_pending)
    last = ks.last_rotated if ks else None
    due = None
    if ks is not None and key.period_days is not None:
        due = ks.due_override or ks.last_rotated + timedelta(days=key.period_days)
    if not key.ready:
        status = "not_ready"
    elif due is None:
        status = "no_record"
    elif due < today:
        status = "overdue"
    elif due <= today + timedelta(days=DUE_SOON_DAYS):
        status = "due_soon"
    elif due < after:
        status = "this_session"
    else:
        status = "ok"
    return Row(key, last, due, status, pending and key.ready)


@dataclass(frozen=True)
class Plan:
    today: date
    commit: str
    session: date
    after: date
    rows: tuple[Row, ...]
    untracked: int  # keys replaced on exposure only (method none)
    unknown_state: int  # state entries whose key file no longer exists

    @property
    def automatic_actions(self) -> tuple[Row, ...]:
        """What an apply would rotate: ready automatic keys that are due, plus any whose old
        key is still live (the apply finishes the revoke)."""
        return tuple(
            r
            for r in self.rows
            if r.key.method == "automatic" and (r.status in ACTIONABLE or r.revoke_pending)
        )

    @property
    def manual_session(self) -> tuple[Row, ...]:
        return tuple(r for r in self.rows if r.key.method == "manual" and r.status in ACTIONABLE)

    @property
    def counts(self) -> dict[str, int]:
        by = {s: sum(1 for r in self.rows if r.status == s) for s in RANK}
        return {
            **by,
            "revoke_pending": sum(1 for r in self.rows if r.revoke_pending),
            "sensitive_overdue": sum(
                1 for r in self.rows if r.status == "overdue" and r.key.sensitive
            ),
            "automatic": len(self.automatic_actions),
            "manual_session": len(self.manual_session),
        }

    @property
    def needs_attention(self) -> bool:
        c = self.counts
        return bool(c["overdue"] or c["no_record"] or c["revoke_pending"])

    @property
    def plan_hash(self) -> str:
        actions = sorted(
            [
                r.key.id,
                r.last.isoformat() if r.last else "",
                r.due.isoformat() if r.due else "",
                r.status,
                r.revoke_pending,
            ]
            for r in self.automatic_actions
        )
        payload = json.dumps({"commit": self.commit, "actions": actions}, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def summary(self) -> str:
        c = self.counts
        return (
            f"overdue={c['overdue']} no_record={c['no_record']} due_soon={c['due_soon']} "
            f"this_session={c['this_session']} ok={c['ok']} not_ready={c['not_ready']} "
            f"revoke_pending={c['revoke_pending']} automatic={c['automatic']} "
            f"manual_session={c['manual_session']}"
        )


def build_plan(register: Register, state: State, today: date, commit: str) -> Plan:
    session = session_on_or_after(today)
    after = following_session(session)
    tracked = [k for k in register.keys.values() if k.method != "none"]
    rows = [classify(k, state.keys.get(k.id), today, after) for k in tracked]
    rows.sort(
        key=lambda r: (RANK[r.status], r.due or date.max, not r.key.sensitive, r.key.id),
    )
    return Plan(
        today=today,
        commit=commit,
        session=session,
        after=after,
        rows=tuple(rows),
        untracked=len(register.keys) - len(tracked),
        unknown_state=len(set(state.keys) - set(register.keys)),
    )


def _line(r: Row, today: date) -> str:
    kind = "sensitive" if r.key.sensitive else "standard"
    last = r.last.isoformat() if r.last else "unknown"
    due = r.due.isoformat() if r.due else "unknown"
    flag = "  REVOKE-PENDING (the old key is still live)" if r.revoke_pending else ""
    return (
        f"  {r.key.id:<28} {kind:<9} {r.key.period_days or '-':>3}d  last {last}  "
        f"due {due} ({r.days_text(today)}){flag}"
    )


def render(plan: Plan) -> list[str]:
    """The plan as fixed-format text: names, dates and counts the code computed. Text that
    came from a key file is cut to printable ASCII first."""
    lines = [
        f"Key rotation plan: register commit {plan.commit[:12]}, today {plan.today}",
        f"Next session {plan.session}; the one after is {plan.after}. "
        "Keys that would go overdue before then are done at the next session.",
        f"Counts: {plan.summary()}",
    ]
    if plan.untracked or plan.unknown_state:
        lines.append(
            f"({plan.untracked} key(s) replaced on exposure only; "
            f"{plan.unknown_state} state entr(ies) with no key file)"
        )
    auto = plan.automatic_actions
    lines += ["", f"Automatic keys to rotate ({len(auto)}):"]
    lines += [_line(r, plan.today) for r in auto] or ["  none"]
    manual = plan.manual_session
    lines += ["", f"Manual keys for the {plan.session} session ({len(manual)}):"]
    for r in manual:
        lines.append(_line(r, plan.today))
        if r.key.check:
            lines.append(f"      proof: {printable(r.key.check, 100)}")
    if not manual:
        lines.append("  none")
    skipped = [r for r in plan.rows if r.status == "not_ready"]
    if skipped:
        lines += [
            "",
            f"Not ready, skipped ({len(skipped)}): " + ", ".join(r.key.id for r in skipped),
        ]
    return lines
