"""Apply an approved rotation plan, attended, one key at a time. Also: a read-only preflight.

Runs on the host as root, in standard-library Python, because it must rewrite a consumer's env
file, recreate that service and run its health check; a hardened container cannot do that
without the Docker socket, which would be root-equivalent. The rights (the vendor key that can
make keys and the login to the secrets manager) arrive on standard input for this one run, are
held in memory in `Secret` wrappers that cannot be printed, and are never written anywhere.

Per key, in this order, stopping at the first thing that is wrong:

  1. the live old key is found (by the id recorded last time, else by its exact name) and its
     permissions must equal the key file's list exactly, or nothing is touched;
  2. a new key is created with the same permissions;
  3. its value is written to the secrets manager (the old value is held in memory for rollback);
  4. the consumer's env file is rewritten (the old file is kept as .prev) and the service is
     recreated;
  5. its named health check must pass, then pass again after the grace period;
  6. only then is the OLD key revoked, by the exact id found in step 1.

Any failure before step 6 undoes what was done (restore the file and recreate the service,
put the old secret back, delete the new key): the old key is never revoked unless both checks
passed. If the revoke itself fails the new key is already working, so the run records
`revoke_pending` and a later run finishes the revoke. The first failure stops the whole run.

Nothing printed or recorded here is a value: ids appear as their last four characters.
"""

import fcntl
import os
import re
import signal
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Protocol

from soc_api.rotate import state as st
from soc_api.rotate.codes import ATTENTION, FAILED, OK, REFUSED
from soc_api.rotate.keys import ApplySpec, load_register
from soc_api.rotate.lc import OID_RE, NewKey, VendorKey
from soc_api.rotate.net import RotateError
from soc_api.rotate.plan import ACTIONABLE, Plan, Row, build_plan, local_today
from soc_api.rotate.records import record_line
from soc_api.rotate.rights import Rights, RightsError, Secret

MAX_PROBLEMS_SHOWN = 20
APPROVAL_MESSAGES = {
    "no_approval": "there is no approval; run rotate.sh and approve the plan first",
    "commit_changed": "the key register changed since the approval; plan and approve again",
    "plan_changed": "the plan is not the one that was approved; plan and approve again",
    "from_the_future": "the approval's time is in the future",
    "expired": "the approval is older than 30 minutes; plan and approve again",
}


class Vendor(Protocol):
    def list_keys(self) -> dict[str, VendorKey]: ...
    def create_key(self, name: str, perms: tuple[str, ...]) -> NewKey: ...
    def delete_key(self, key_id: str) -> None: ...


class Store(Protocol):
    def get(self, path: str, name: str) -> Secret: ...
    def set(self, path: str, name: str, value: Secret) -> None: ...


class Consumer(Protocol):
    def install(self, env_file: str, var: str, value: Secret) -> None: ...
    def restore(self, env_file: str) -> None: ...
    def discard_prev(self, env_file: str) -> None: ...
    def restart(self, services: tuple[str, ...] | list[str]) -> None: ...
    def check(self, name: str) -> bool: ...


@dataclass
class Deps:
    vendor_for: Callable[[str], Vendor]  # given the organization id
    store: Store
    consumer: Consumer
    sleep: Callable[[float], None]


class ApplyLock:
    """One apply at a time on this host. Held for the life of the process."""

    def __init__(self, path: Path) -> None:
        self._fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._fd)
            raise RotateError("locked") from None

    def release(self) -> None:
        os.close(self._fd)  # closing the descriptor drops the lock


def stop_on_hangup() -> None:
    """A dropped connection (hangup) or a terminate must undo the work like a Ctrl-C does,
    not kill the process half way with the new key installed and the old one still live."""

    def stop(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    for sig in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(sig, stop)


def last4(identifier: str) -> str:
    return identifier[-4:]


@dataclass
class Session:
    deps: Deps
    state: st.State
    moment: datetime
    today: date
    run_id: str
    say: Callable[[str], None]
    lines: list[str] = field(default_factory=list)

    def note(self, action: str, result: str, **fields: str | int) -> None:
        line = record_line(self.moment, self.run_id, action, result, **fields)
        self.lines.append(line)
        self.say(line)


def is_ours(name: str, console_name: str) -> bool:
    """A key this rotator made or replaces: exactly the console name, or the console name, a
    hyphen and the eight-digit date it was made. Nothing looser, so a stranger is never taken."""
    return name == console_name or bool(re.fullmatch(re.escape(console_name) + r"-\d{8}", name))


def _locate(
    keys: dict[str, VendorKey], ks: st.KeyState | None, spec: ApplySpec
) -> tuple[VendorKey | None, str]:
    """The one live key this rotation replaces: the recorded id, else the exact name."""
    if ks is not None and ks.vendor_key_id:
        found = keys.get(ks.vendor_key_id)
        if found is None:
            return None, "recorded_key_missing"
        if not is_ours(found.name, spec.console_name):
            return None, "recorded_key_renamed"
        return found, ""
    # No id on record (first rotation, or the state was rebuilt): exactly one live key with our
    # name, with or without a date. Two (an unfinished rotation) is refused for a person.
    named = [k for k in keys.values() if is_ours(k.name, spec.console_name)]
    if len(named) == 1:
        return named[0], ""
    return None, "old_key_missing" if not named else "old_key_ambiguous"


def _check_old(
    vendor: Vendor,
    ks: st.KeyState | None,
    spec: ApplySpec,
    today: date,
    say: Callable[[str], None],
) -> tuple[VendorKey | None, str]:
    """The old key, if it is safe to go on: found, exactly the permissions the file lists, and
    the new key's name free."""
    keys = vendor.list_keys()
    old, why = _locate(keys, ks, spec)
    if old is None:
        return None, why
    want = frozenset(spec.perms)
    if old.perms != want:
        extra, missing = sorted(old.perms - want)[:10], sorted(want - old.perms)[:10]
        say(f"  the live key's permissions differ from the file: extra={extra} missing={missing}")
        return None, "perms_differ"
    if any(k.name == f"{spec.console_name}-{today:%Y%m%d}" for k in keys.values()):
        return None, "new_name_taken"
    return old, ""


def _oid(session: Session, spec: ApplySpec) -> str:
    try:
        value = session.deps.store.get(spec.path, spec.org_name).reveal()
    except RotateError as exc:
        raise RotateError(f"org_id_{exc.code}", exc.detail) from None
    if not OID_RE.fullmatch(value):
        raise RotateError("org_id_bad_oid")
    return value


def _rollback(
    session: Session,
    vendor: Vendor,
    spec: ApplySpec,
    *,
    created: NewKey | None,
    old_value: Secret | None,
    stored: bool,
    installed: bool,
) -> list[str]:
    """Undo what this key's run did, newest first. Returns the steps that could not be undone."""
    d, undone = session.deps, []
    if installed:
        try:
            d.consumer.restore(spec.env_file)
            d.consumer.restart(spec.restart)
            if not d.consumer.check(spec.check):
                undone.append("old_key_check_failed")
        except RotateError as exc:
            undone.append(f"consumer_{exc.code}")
        except Exception:  # noqa: BLE001 - an undo step must never stop the steps after it
            undone.append("consumer_unexpected_error")
    if stored and old_value is not None:
        try:
            d.store.set(spec.path, spec.secret_name, old_value)
        except RotateError as exc:
            undone.append(f"secret_{exc.code}")
        except Exception:  # noqa: BLE001
            undone.append("secret_unexpected_error")
    if created is not None:
        try:
            vendor.delete_key(created.id)
        except RotateError as exc:
            undone.append(f"new_key_{exc.code}")
        except Exception:  # noqa: BLE001
            undone.append("new_key_unexpected_error")
    return undone


def _fail(session: Session, row: Row, result: str, **fields: str | int) -> bool:
    ks = session.state.keys.get(row.key.id)
    if ks is not None:
        ks.outcome = "failed"
        ks.updated = st.stamp(session.moment)
    session.note("apply", result, id=row.key.id, **fields)
    return False


def _finish_revoke(session: Session, row: Row, spec: ApplySpec, oid: str) -> bool:
    """The new key is already in use; take the old one out of service."""
    ks = session.state.keys[row.key.id]
    vendor = session.deps.vendor_for(oid)
    try:
        live = vendor.list_keys().get(ks.old_key_id)
        if live is None:
            session.say(f"  {row.key.id}: the old key is already gone")
        elif not is_ours(live.name, spec.console_name):
            session.note("revoke", "refused-old_key_renamed", id=row.key.id)
            return False
        else:
            vendor.delete_key(ks.old_key_id)
    except RotateError as exc:
        session.note("revoke", f"failed-{exc.code}", id=row.key.id, old=last4(ks.old_key_id))
        return False
    session.note("revoke", "revoked", id=row.key.id, old=last4(ks.old_key_id))
    ks.revoke_pending, ks.old_key_id, ks.updated = False, "", st.stamp(session.moment)
    return True


def _rotate(session: Session, row: Row, spec: ApplySpec, oid: str) -> bool:
    d = session.deps
    vendor = d.vendor_for(oid)
    ks = session.state.keys.get(row.key.id)
    old, why = _check_old(vendor, ks, spec, session.today, session.say)
    if old is None:
        session.note("apply", f"refused-{why}", id=row.key.id)
        return False
    created: NewKey | None = None
    old_value: Secret | None = None
    stored = installed = False
    try:
        created = vendor.create_key(f"{spec.console_name}-{session.today:%Y%m%d}", spec.perms)
        if created.id == old.id:
            raise RotateError("new_key_is_old_key")
        session.say(f"  {row.key.id}: new key created (ends {last4(created.id)})")
        old_value = d.store.get(spec.path, spec.secret_name)
        d.store.set(spec.path, spec.secret_name, created.value)
        stored = True
        d.consumer.install(spec.env_file, spec.env_var, created.value)
        installed = True
        d.consumer.restart(spec.restart)
        if not d.consumer.check(spec.check):
            raise RotateError("check_failed")
        session.say(f"  {row.key.id}: health check passed; waiting {spec.grace_minutes} min")
        d.sleep(spec.grace_minutes * 60)
        if not d.consumer.check(spec.check):
            raise RotateError("check_failed_after_grace")
    except BaseException as exc:
        code = exc.code if isinstance(exc, RotateError) else "interrupted"
        if isinstance(exc, RotateError) and exc.detail:
            session.say(f"  {row.key.id}: the reply looked like {exc.detail}")
        undone = _rollback(
            session,
            vendor,
            spec,
            created=created,
            old_value=old_value,
            stored=stored,
            installed=installed,
        )
        fields: dict[str, str | int] = {"old": last4(old.id)}
        if created is not None:
            fields["new"] = last4(created.id)
        if undone:
            _fail(session, row, f"failed-{code}-ROLLBACK-INCOMPLETE", **fields)
            session.say(f"  NEEDS A PERSON: could not undo: {', '.join(undone)}")
        else:
            _fail(session, row, f"failed-{code}-rolled-back", **fields)
            session.say(f"  {row.key.id}: undone; the old key is still the one in use")
        if not isinstance(exc, RotateError):
            raise
        return False
    revoked = True
    try:
        vendor.delete_key(old.id)
    except RotateError as exc:
        revoked = False
        session.say(
            f"  {row.key.id}: the new key works but the old one was not revoked ({exc.code})"
        )
    d.consumer.discard_prev(spec.env_file)
    entry = st.KeyState(
        last_rotated=session.today,
        outcome="rotated",
        revoke_pending=not revoked,
        updated=st.stamp(session.moment),
        vendor_key_id=created.id,
        old_key_id="" if revoked else old.id,
    )
    session.state.keys[row.key.id] = entry
    due = session.today + timedelta(days=row.key.period_days or 0)
    session.note(
        "apply",
        "rotated" if revoked else "rotated-REVOKE-PENDING",
        id=row.key.id,
        old=last4(old.id),
        new=last4(created.id),
        check="ok",
        revoked="yes" if revoked else "no",
        next_due=due.isoformat(),
    )
    return True


def _write_record(state_dir: Path, lines: list[str], say: Callable[[str], None]) -> None:
    try:
        (state_dir / "record.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        say("warning: could not write the record file; the lines above are the record")


def _save(state_dir: Path, state: st.State, say: Callable[[str], None]) -> bool:
    try:
        st.save(state_dir / "state.json", state)
    except OSError:
        say("FAILED: could not write state.json; record what happened by hand with --record")
        return False
    return True


def run_apply(
    *,
    keys_dir: Path,
    state_dir: Path,
    commit: str,
    plan_hash: str,
    read: Callable[[], Rights],
    build: Callable[[Rights], Deps],
    say: Callable[[str], None],
    now: Callable[[], datetime],
) -> int:
    moment, run_id = now(), uuid.uuid4().hex[:12]
    today = local_today(moment)
    refused = _refuser(state_dir, say, moment, run_id)
    try:
        lock = ApplyLock(state_dir / "apply.lock")
    except (RotateError, OSError):
        return refused("locked", "could not take the apply lock (another apply may be running)")
    try:
        register = load_register(keys_dir)
        if register.problems:
            for p in register.problems[:MAX_PROBLEMS_SHOWN]:
                say(p)
            return refused("register", f"{len(register.problems)} problem(s) in the key register")
        try:
            state = st.load(state_dir / "state.json")
        except st.StateError as exc:
            return refused("state", str(exc))
        plan = build_plan(register, state, today, commit)
        problem = None if plan.plan_hash == plan_hash else "plan_changed"
        problem = problem or st.approval_problem(state, plan_hash, commit, moment)
        if problem:
            return refused(problem, APPROVAL_MESSAGES[problem])
        if not plan.automatic_actions:
            say("Nothing automatic is due: nothing to apply.")
            line = record_line(moment, run_id, "apply", "nothing-to-apply", commit=commit[:12])
            say(line)
            _write_record(state_dir, [line], say)
            return OK
        try:
            rights = read()
        except RightsError as exc:
            return refused("rights", str(exc))
        session = Session(build(rights), state, moment, today, run_id, say)
        state.approval = None  # an approval is good for one apply, however it ends
        if not _save(state_dir, state, say):
            return FAILED
        try:
            code = _apply_rows(session, plan, state_dir)
        finally:
            # Also when interrupted: what was undone, and the lines for the log, are kept.
            _save(state_dir, state, say)
            _write_record(state_dir, session.lines, say)
        return code
    finally:
        lock.release()


def _refuser(
    state_dir: Path, say: Callable[[str], None], moment: datetime, run_id: str
) -> Callable[[str, str], int]:
    def refused(code: str, message: str) -> int:
        say(f"refused: {message}; nothing was changed")
        line = record_line(moment, run_id, "apply", f"refused-{code}")
        say(line)
        _write_record(state_dir, [line], say)
        return REFUSED

    return refused


def _apply_rows(session: Session, plan: Plan, state_dir: Path) -> int:
    skipped = 0
    for row in plan.automatic_actions:
        spec = row.key.apply
        if spec is None:
            skipped += 1
            session.say(f"  skipped {row.key.id}: {row.key.apply_note or 'not supported yet'}")
            session.note("apply", "skipped", id=row.key.id)
            continue
        ok = True
        try:
            oid = _oid(session, spec)
            if row.revoke_pending:
                ok = _finish_revoke(session, row, spec, oid)
            if ok and row.status in ACTIONABLE:
                ok = _rotate(session, row, spec, oid)
        except RotateError as exc:
            if exc.detail:
                session.say(f"  {row.key.id}: the reply looked like {exc.detail}")
            ok = _fail(session, row, f"failed-{exc.code}")
        if not _save(state_dir, session.state, session.say):
            return FAILED
        if not ok:
            session.say("Stopped at the first failure; keys after this one were not touched.")
            return FAILED
    return ATTENTION if skipped else OK


# ---- preflight: the read calls only ----


def run_preflight(
    *,
    keys_dir: Path,
    state_dir: Path,
    commit: str,
    read: Callable[[], Rights],
    build: Callable[[Rights], Deps],
    say: Callable[[str], None],
    now: Callable[[], datetime],
) -> int:
    """Log in to both services, list the vendor's keys and read each value's name, and say
    whether a real apply could start. Creates, writes and deletes nothing, and needs no
    approval: it is how the unconfirmed API shapes are checked before the first rotation."""
    moment, run_id = now(), uuid.uuid4().hex[:12]
    today = local_today(moment)
    refused = _refuser(state_dir, say, moment, run_id)
    register = load_register(keys_dir)
    if register.problems:
        for p in register.problems[:MAX_PROBLEMS_SHOWN]:
            say(p)
        return refused("register", f"{len(register.problems)} problem(s) in the key register")
    try:
        state = st.load(state_dir / "state.json")
        rights = read()
    except st.StateError as exc:
        return refused("state", str(exc))
    except RightsError as exc:
        return refused("rights", str(exc))
    deps = build(rights)
    plan = build_plan(register, state, today, commit)
    session = Session(deps, state, moment, today, run_id, say)
    bad = 0
    for row in plan.rows:
        spec = row.key.apply
        if spec is None:
            continue
        try:
            oid = _oid(session, spec)
            old, why = _check_old(
                deps.vendor_for(oid), state.keys.get(row.key.id), spec, today, say
            )
            deps.store.get(
                spec.path, spec.secret_name
            )  # present and readable; the value is dropped
        except RotateError as exc:
            old, why = None, exc.code
            if exc.detail:
                say(f"  {row.key.id}: the reply looked like {exc.detail} (names and types only)")
        if old is None:
            bad += 1
            session.note("preflight", f"problem-{why}", id=row.key.id)
        else:
            session.note("preflight", "ok", id=row.key.id, current=last4(old.id))
    if not session.lines:
        say("No automatic key in the register can be rotated by this build.")
    _write_record(
        state_dir, session.lines or [record_line(moment, run_id, "preflight", "none")], say
    )
    return FAILED if bad else OK
