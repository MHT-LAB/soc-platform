"""Key rotation, step one: plan, approve and record. This build changes no key anywhere.

    python -m soc_api.rotate                     plan, then a typed `yes` to approve it
    python -m soc_api.rotate --plan [--quiet]    the plan only; asks nothing (the daily timer)
    python -m soc_api.rotate --record ID [--date YYYY-MM-DD] [--due YYYY-MM-DD]
                                                 a person did this key by hand: write it down

Started by deploy/rotate.sh as the one-shot compose `rotate` service, which has no network, no
secret and no way to reach a vendor. It reads the key register (read-only) and writes three
small files to its state folder: state.json (dates and outcomes), status.json (counts only,
for the console) and record.txt (one line for the operator's log).

Exit codes: 0 done or nothing to do, 1 could not write its files, 2 refused before changing
anything, 3 not confirmed, 4 (plan only) something is overdue, has no record, or has an old
key still live.
"""

import os
import re
import sys
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from soc_api.rotate import state as st
from soc_api.rotate.keys import ID_RE, load_register, printable
from soc_api.rotate.plan import Plan, build_plan, render

OK, FAILED, REFUSED, DECLINED, ATTENTION = 0, 1, 2, 3, 4
DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
MAX_PROBLEMS_SHOWN = 20
USAGE = "usage: rotate [--plan [--quiet] | --record ID [--date YYYY-MM-DD] [--due YYYY-MM-DD]]"


class ConfigError(Exception):
    """A missing or malformed setting. Names the setting, never its value."""


class UsageError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    keys_dir: Path
    state_dir: Path
    commit: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Config":
        commit = env.get("SOC_ROTATE_COMMIT", "")
        if not st.COMMIT_RE.fullmatch(commit):
            raise ConfigError("SOC_ROTATE_COMMIT is missing or is not a full commit id")
        return cls(
            keys_dir=Path(env.get("SOC_ROTATE_KEYS_DIR", "/keys")),
            state_dir=Path(env.get("SOC_ROTATE_STATE", "/state")),
            commit=commit,
        )


@dataclass(frozen=True)
class Args:
    mode: str  # approve | plan | record
    quiet: bool = False
    key_id: str = ""
    on: date | None = None
    due: date | None = None


def _day(text: str) -> date:
    if not DAY_RE.fullmatch(text):
        raise UsageError("a date must look like YYYY-MM-DD")
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise UsageError("not a real date") from None


def parse_args(argv: list[str]) -> Args:
    if not argv:
        return Args("approve")
    if argv[0] == "--plan":
        if argv[1:] not in ([], ["--quiet"]):
            raise UsageError(USAGE)
        return Args("plan", quiet=argv[1:] == ["--quiet"])
    if argv[0] == "--record":
        if len(argv) < 2 or not ID_RE.fullmatch(argv[1]):
            raise UsageError(USAGE)
        on = due = None
        rest = argv[2:]
        while rest:
            if len(rest) < 2 or rest[0] not in ("--date", "--due"):
                raise UsageError(USAGE)
            if rest[0] == "--date" and on is None:
                on = _day(rest[1])
            elif rest[0] == "--due" and due is None:
                due = _day(rest[1])
            else:
                raise UsageError(USAGE)
            rest = rest[2:]
        return Args("record", key_id=argv[1], on=on, due=due)
    raise UsageError(USAGE)


def record_line(now: datetime, run_id: str, action: str, result: str, **fields: str | int) -> str:
    """One line for the operator's log and the vault Build Log: ids, dates and counts only."""
    parts = [f"rotate {st.stamp(now)} {action}"]
    parts += [f"{k}={printable(str(v), 64).replace(' ', '_')}" for k, v in fields.items()]
    parts += [f"result={result}", f"run={run_id}"]
    return " ".join(parts)


def tty_confirm(prompt: str) -> bool:
    """A typed `yes` read from the terminal. No terminal means no."""
    if not sys.stdin.isatty():
        print("no terminal to ask on: nothing was changed")
        return False
    try:
        return input(prompt).strip() == "yes"
    except EOFError:
        return False


def _write_status(cfg: Config, plan: Plan, now: datetime) -> None:
    """Counts only, for the console and the pager: never a key name or a value."""
    st.write_json_atomic(
        cfg.state_dir / "status.json",
        {
            "version": 1,
            "generated_at": st.stamp(now),
            "commit": plan.commit[:12],
            "session": plan.session.isoformat(),
            "counts": plan.counts,
        },
    )


def _finish(cfg: Config, say: Callable[[str], None], line: str) -> None:
    try:
        (cfg.state_dir / "record.txt").write_text(line + "\n", encoding="utf-8")
    except OSError:
        say("warning: could not write the record file; the line below is the record")
    say(line)


def run(
    cfg: Config,
    args: Args,
    confirm: Callable[[str], bool],
    say: Callable[[str], None] = print,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    moment = now()
    run_id = uuid.uuid4().hex[:12]
    today = moment.astimezone(ZoneInfo("America/New_York")).date()
    commit12 = cfg.commit[:12]

    register = load_register(cfg.keys_dir)
    if register.problems:
        for p in register.problems[:MAX_PROBLEMS_SHOWN]:
            say(p)
        if len(register.problems) > MAX_PROBLEMS_SHOWN:
            say(f"... and {len(register.problems) - MAX_PROBLEMS_SHOWN} more")
        say(
            f"refused: {len(register.problems)} problem(s) in the key register; nothing was changed"
        )
        _finish(
            cfg, say, record_line(moment, run_id, args.mode, "refused-register", commit=commit12)
        )
        return REFUSED
    state_path = cfg.state_dir / "state.json"
    try:
        state = st.load(state_path)
    except st.StateError as exc:
        say(f"refused: {exc}. Move state.json aside after looking at it; nothing was changed")
        _finish(cfg, say, record_line(moment, run_id, args.mode, "refused-state", commit=commit12))
        return REFUSED

    plan = build_plan(register, state, today, cfg.commit)

    if args.mode == "plan":
        for line in [f"plan: {plan.summary()}"] if args.quiet else render(plan):
            say(line)
        try:
            _write_status(cfg, plan, moment)
        except OSError:
            say("FAILED: could not write status.json")
            return FAILED
        code = ATTENTION if plan.needs_attention else OK
        _finish(
            cfg,
            say,
            record_line(
                moment,
                run_id,
                "plan",
                "attention" if code == ATTENTION else "ok",
                commit=commit12,
                plan=plan.plan_hash,
                **plan.counts,
            ),
        )
        return code

    if args.mode == "approve":
        return _approve(cfg, plan, state, confirm, say, moment, run_id)
    return _record(cfg, args, register.keys, state, plan, confirm, say, moment, run_id, today)


def _approve(
    cfg: Config,
    plan: Plan,
    state: st.State,
    confirm: Callable[[str], bool],
    say: Callable[[str], None],
    moment: datetime,
    run_id: str,
) -> int:
    commit12 = cfg.commit[:12]
    for line in render(plan):
        say(line)
    if not plan.automatic_actions:
        say("")
        say("Nothing automatic is due: there is nothing to approve.")
        _finish(
            cfg, say, record_line(moment, run_id, "approve", "nothing-to-approve", commit=commit12)
        )
        return OK
    say("")
    say(
        f"Plan {plan.plan_hash}. This build makes no change to any key; "
        "it only records the approval."
    )
    if not confirm(f"Approve plan {plan.plan_hash} for 30 minutes? Type yes: "):
        say("Not confirmed: nothing was changed.")
        _finish(
            cfg,
            say,
            record_line(
                moment, run_id, "approve", "declined", commit=commit12, plan=plan.plan_hash
            ),
        )
        return DECLINED
    state.approval = st.Approval(plan.plan_hash, cfg.commit, moment)
    try:
        st.save(cfg.state_dir / "state.json", state)
    except OSError:
        say("FAILED: could not write state.json")
        return FAILED
    say(f"Approved plan {plan.plan_hash} until {st.stamp(moment + st.APPROVAL_MAX_AGE)}.")
    _finish(
        cfg,
        say,
        record_line(moment, run_id, "approve", "approved", commit=commit12, plan=plan.plan_hash),
    )
    return OK


def _record(
    cfg: Config,
    args: Args,
    keys: Mapping[str, object],
    state: st.State,
    plan: Plan,
    confirm: Callable[[str], bool],
    say: Callable[[str], None],
    moment: datetime,
    run_id: str,
    today: date,
) -> int:
    commit12 = cfg.commit[:12]
    row = next((r for r in plan.rows if r.key.id == args.key_id), None)
    if row is None:
        say("refused: that id is not a tracked key in the register; nothing was changed")
        _finish(cfg, say, record_line(moment, run_id, "record", "refused-id", commit=commit12))
        return REFUSED
    on = args.on or today
    if on > today or (args.due is not None and args.due < on):
        say("refused: the date is in the future, or the due date is before it; nothing was changed")
        _finish(cfg, say, record_line(moment, run_id, "record", "refused-date", id=row.key.id))
        return REFUSED
    due_text = args.due.isoformat() if args.due else f"last + {row.key.period_days} days"
    say(f"{row.key.id}: rotated by hand on {on}, next due {due_text}. This makes no vendor call.")
    if not confirm(f"Write down that {row.key.id} was rotated on {on}? Type yes: "):
        say("Not confirmed: nothing was changed.")
        _finish(cfg, say, record_line(moment, run_id, "record", "declined", id=row.key.id))
        return DECLINED
    state.keys[row.key.id] = st.KeyState(
        last_rotated=on,
        outcome="recorded",
        revoke_pending=False,
        due_override=args.due,
        updated=st.stamp(moment),
    )
    try:
        st.save(cfg.state_dir / "state.json", state)
    except OSError:
        say("FAILED: could not write state.json")
        return FAILED
    fresh = build_plan(load_register(cfg.keys_dir), state, today, cfg.commit)
    next_due = next((r.due for r in fresh.rows if r.key.id == row.key.id), None)
    try:
        _write_status(cfg, fresh, moment)
    except OSError:
        say("warning: could not refresh status.json")
    _finish(
        cfg,
        say,
        record_line(
            moment,
            run_id,
            "record",
            "recorded",
            id=row.key.id,
            date=on.isoformat(),
            next_due=next_due.isoformat() if next_due else "unknown",
        ),
    )
    return OK


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
    except UsageError as exc:
        print(f"refused: {exc}")
        return REFUSED
    try:
        cfg = Config.from_env(os.environ)
    except ConfigError as exc:
        print(f"refused: {exc}")
        return REFUSED
    return run(cfg, args, tty_confirm)
