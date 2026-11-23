"""Key rotation, step one: plan, approve and record. This build changes no key anywhere.

    python -m soc_api.rotate                     plan, then a typed `yes` to approve it
    python -m soc_api.rotate --plan [--quiet]    the plan only; asks nothing (the daily timer)
    python -m soc_api.rotate --record ID [ID ...] [--date YYYY-MM-DD] [--due YYYY-MM-DD]
                                                 a person did these keys by hand: write them down
    python -m soc_api.rotate --apply HASH        rotate the automatic keys of the approved plan
    python -m soc_api.rotate --preflight         the read calls of an apply, nothing changed
    python -m soc_api.rotate --provision HASH    create the keys the plan lists "to create"

The last three run on the host (deploy/rotate.sh starts them), not in the container: they need
the rights on standard input, the vendor and the secrets manager over the network, and the
consumer's env file and service. See soc_api.rotate.apply.

The first three are started by deploy/rotate.sh as the one-shot compose `rotate` service, which
has no network, no secret and no way to reach a vendor. They read the key register (read-only)
and write three small files to its state folder: state.json (dates and outcomes), status.json
(counts only, for the console) and record.txt (one line for the operator's log).

Exit codes: 0 done or nothing to do, 1 could not write its files, 2 refused before changing
anything, 3 not confirmed, 4 (plan only) something is overdue, has no record, or has an old
key still live.
"""

import io
import os
import re
import sys
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from soc_api.rotate import state as st
from soc_api.rotate.codes import ATTENTION, DECLINED, FAILED, OK, REFUSED
from soc_api.rotate.keys import ID_RE, load_register
from soc_api.rotate.plan import Plan, Row, build_plan, local_today, render
from soc_api.rotate.records import record_line

DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
MAX_PROBLEMS_SHOWN = 20
MAX_RECORD_IDS = 20  # one record line each, and rotate.sh keeps 20 lines
USAGE = (
    "usage: rotate [--plan [--quiet] | --record ID [ID ...] [--date YYYY-MM-DD] [--due YYYY-MM-DD]"
    " | --preflight | --apply HASH | --provision HASH]"
)


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
    mode: str  # approve | plan | record | apply | preflight | provision
    quiet: bool = False
    plan_hash: str = ""
    key_ids: tuple[str, ...] = ()
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
    if argv[0] == "--apply":
        if len(argv) != 2 or not st.HASH_RE.fullmatch(argv[1]):
            raise UsageError(USAGE)
        return Args("apply", plan_hash=argv[1])
    if argv[0] == "--provision":
        if len(argv) != 2 or not st.HASH_RE.fullmatch(argv[1]):
            raise UsageError(USAGE)
        return Args("provision", plan_hash=argv[1])
    if argv == ["--preflight"]:
        return Args("preflight")
    if argv[0] == "--record":
        ids: list[str] = []
        rest = argv[1:]
        while rest and ID_RE.fullmatch(rest[0]):
            ids.append(rest[0])
            rest = rest[1:]
        if not ids or len(ids) > MAX_RECORD_IDS:
            raise UsageError(USAGE)
        on = due = None
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
        return Args("record", key_ids=tuple(ids), on=on, due=due)
    raise UsageError(USAGE)


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


class _Gone(io.TextIOBase):
    """Standard output after the operator's connection went away: accepts and drops text."""

    def write(self, text: str, /) -> int:
        return len(text)


def say_now(line: str) -> None:
    """Print one line and push it out at once. Over `ssh ... pct exec` there is no terminal, so
    Python would hold its output in a block buffer and the operator would see nothing for the
    whole grace wait of a rotation.

    If the operator's side has gone (Ctrl-C on their machine closes the pipe), a write fails.
    That must never change what the run does: a failed print inside a rotation would otherwise
    roll back a healthy key. So printing stops quietly and the run finishes, or undoes itself,
    as it would have; every line still reaches record.txt, and rotate.sh appends it to the log."""
    try:
        print(line, flush=True)
    except (OSError, ValueError):  # BrokenPipeError is an OSError; ValueError: stdout closed
        sys.stdout = _Gone()


def _finish_lines(cfg: Config, say: Callable[[str], None], lines: list[str]) -> None:
    try:
        (cfg.state_dir / "record.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        say("warning: could not write the record file; the lines below are the record")
    for line in lines:
        say(line)


def _finish(cfg: Config, say: Callable[[str], None], line: str) -> None:
    _finish_lines(cfg, say, [line])


def run(
    cfg: Config,
    args: Args,
    confirm: Callable[[str], bool],
    say: Callable[[str], None] = print,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    if args.mode not in ("plan", "approve", "record"):
        say("refused: that mode runs on the host through deploy/rotate.sh, not here")
        return REFUSED
    moment = now()
    run_id = uuid.uuid4().hex[:12]
    today = local_today(moment)
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
    return _record(cfg, args, state, plan, confirm, say, moment, run_id, today)


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
    if not plan.automatic_actions and not plan.provisions:
        say("")
        say("Nothing automatic is due and no key is waiting to be created: nothing to approve.")
        _finish(
            cfg, say, record_line(moment, run_id, "approve", "nothing-to-approve", commit=commit12)
        )
        return OK
    say("")
    say(
        f"Plan {plan.plan_hash}. Approving makes no change to any key; "
        "it only records the approval. "
        "Then `rotate.sh --apply` rotates the automatic keys and `rotate.sh --provision` "
        "creates the keys listed to create (an approval is good for one of them)."
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
    state: st.State,
    plan: Plan,
    confirm: Callable[[str], bool],
    say: Callable[[str], None],
    moment: datetime,
    run_id: str,
    today: date,
) -> int:
    commit12 = cfg.commit[:12]
    if len(set(args.key_ids)) != len(args.key_ids):
        say("refused: an id is listed twice; nothing was changed")
        _finish(
            cfg, say, record_line(moment, run_id, "record", "refused-duplicate", commit=commit12)
        )
        return REFUSED
    by_id = {r.key.id: r for r in plan.rows}
    rows: list[Row] = [by_id[i] for i in args.key_ids if i in by_id]
    if len(rows) != len(args.key_ids):
        say("refused: an id is not a tracked key in the register; nothing was changed")
        _finish(cfg, say, record_line(moment, run_id, "record", "refused-id", commit=commit12))
        return REFUSED
    on = args.on or today
    if on > today or (args.due is not None and args.due < on):
        say("refused: the date is in the future, or the due date is before it; nothing was changed")
        _finish_lines(
            cfg,
            say,
            [record_line(moment, run_id, "record", "refused-date", id=r.key.id) for r in rows],
        )
        return REFUSED
    for row in rows:
        due_text = args.due.isoformat() if args.due else f"last + {row.key.period_days} days"
        say(
            f"{row.key.id}: rotated by hand on {on}, next due {due_text}. "
            "This makes no vendor call."
        )
    if len(rows) == 1:
        question = f"Write down that {rows[0].key.id} was rotated on {on}? Type yes: "
    else:
        question = f"Write down that these {len(rows)} keys were rotated on {on}? Type yes: "
    if not confirm(question):
        say("Not confirmed: nothing was changed.")
        _finish_lines(
            cfg,
            say,
            [record_line(moment, run_id, "record", "declined", id=r.key.id) for r in rows],
        )
        return DECLINED
    for row in rows:
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
    next_due = {r.key.id: r.due for r in fresh.rows}
    try:
        _write_status(cfg, fresh, moment)
    except OSError:
        say("warning: could not refresh status.json")
    _finish_lines(
        cfg,
        say,
        [
            record_line(
                moment,
                run_id,
                "record",
                "recorded",
                id=r.key.id,
                date=on.isoformat(),
                next_due=d.isoformat() if (d := next_due.get(r.key.id)) else "unknown",
            )
            for r in rows
        ],
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
    if args.mode in ("apply", "preflight", "provision"):
        return _host_run(cfg, args)
    return run(cfg, args, tty_confirm)


def _host_run(cfg: Config, args: Args) -> int:
    """The modes that touch the network, the consumer and the secrets manager."""
    import time

    from soc_api.rotate import apply as ap
    from soc_api.rotate import provision as pv
    from soc_api.rotate.consumer import HostConsumer
    from soc_api.rotate.lc import LimaCharlieKeys
    from soc_api.rotate.rights import Rights, read_rights
    from soc_api.rotate.store import SecretsManager

    compose = Path(os.environ.get("SOC_ROTATE_COMPOSE", ""))
    if not (compose.is_file() and os.access(compose, os.X_OK)):
        print("refused: SOC_ROTATE_COMPOSE is not the compose wrapper (deploy/rotate.sh sets it)")
        return REFUSED
    state_root = Path(os.environ.get("SOC_STATE_DIR", "/srv/soc"))

    def build(rights: Rights) -> ap.Deps:
        return ap.Deps(
            vendor_for=lambda oid: LimaCharlieKeys(oid, rights.lc_key),
            store=SecretsManager(rights),
            consumer=HostConsumer(state_root, compose),
            sleep=time.sleep,
        )

    common = {
        "keys_dir": cfg.keys_dir,
        "state_dir": cfg.state_dir,
        "commit": cfg.commit,
        "read": lambda: read_rights(sys.stdin),
        "build": build,
        "say": say_now,
        "now": lambda: datetime.now(UTC),
    }
    ap.stop_on_hangup()
    try:
        if args.mode == "preflight":
            return ap.run_preflight(**common)  # type: ignore[arg-type]
        if args.mode == "provision":
            return pv.run_provision(plan_hash=args.plan_hash, **common)  # type: ignore[arg-type]
        return ap.run_apply(plan_hash=args.plan_hash, **common)  # type: ignore[arg-type]
    except KeyboardInterrupt:
        print("INTERRUPTED: anything done for the key in progress was undone (see above)")
        return FAILED
