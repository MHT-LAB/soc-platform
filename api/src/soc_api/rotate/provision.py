"""Create a key for the first time, attended, from an approved plan. The partner of apply.py.

Apply replaces a key that exists. This makes the first one, so a person never sees or pastes its
value: it goes from the vendor (or from the random generator) straight into the secrets manager
and the env files. The plan lists the keys to create, the approval is the same typed yes bound
to that plan (30 minutes, one run), and the rights arrive on standard input like an apply's.

Per key, in this order, stopping at the first thing that is wrong:

  1. nothing is in the way: no live vendor key has the console name, the secret does not exist,
     and no env file already has the variable (a first creation never overwrites anything);
  2. a vendor key is created with exactly the file's permissions, then the vendor's list is read
     again and the new key's permissions must equal the file's, or it is deleted again (a key
     that came out wider than asked for is never left in service);
  3. the value is stored in the secrets manager (a random key's value is generated here);
  4. each env file gets its line (a file that does not exist is created, mode 600);
  5. each consumer's services are recreated and its named health check must pass.

Any failure undoes what was done, newest first: restore or delete the env files and recreate the
services, delete the secret, delete the new vendor key. On success the state records
`provisioned` with the vendor key's id (an identifier, not a value); a register change then
marks the key ready and the normal rotation takes over. Nothing printed or recorded is a value.
"""

import secrets
import string
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from soc_api.rotate import state as st
from soc_api.rotate.apply import (
    APPROVAL_MESSAGES,
    MAX_PROBLEMS_SHOWN,
    ApplyLock,
    Deps,
    Session,
    Vendor,
    _refuser,
    _save,
    _write_record,
    is_ours,
    last4,
)
from soc_api.rotate.codes import FAILED, OK
from soc_api.rotate.keys import GENERATED_CHARSET, ProvisionSpec, load_register
from soc_api.rotate.lc import OID_RE, NewKey
from soc_api.rotate.net import RotateError
from soc_api.rotate.plan import Row, build_plan, local_today
from soc_api.rotate.records import record_line
from soc_api.rotate.rights import Rights, RightsError, Secret

ALPHABET = string.ascii_letters + string.digits + "._-"
FIRST = string.ascii_letters + string.digits  # a value never starts with a dot or a dash


def generate(length: int, charset: str = GENERATED_CHARSET) -> Secret:
    """A random value from the system's secure source. Only the one charset is allowed, so
    the value always passes the form every env file and init script checks."""
    if charset != GENERATED_CHARSET or not 16 <= length <= 255:
        raise RotateError("bad_generate")
    chars = [secrets.choice(FIRST)] + [secrets.choice(ALPHABET) for _ in range(length - 1)]
    return Secret("".join(chars))


def _oid(session: Session, spec: ProvisionSpec) -> str:
    try:
        value = session.deps.store.get(spec.path, spec.org_name).reveal()
    except RotateError as exc:
        raise RotateError(f"org_id_{exc.code}", exc.detail) from None
    if not OID_RE.fullmatch(value):
        raise RotateError("org_id_bad_oid")
    return value


def _refuse(session: Session, row: Row, why: str) -> bool:
    session.note("provision", f"refused-{why}", id=row.key.id)
    return False


def _undo(
    session: Session,
    vendor: Vendor | None,
    spec: ProvisionSpec,
    *,
    created: NewKey | None,
    attempted: bool,
    stored: bool,
    added: list[tuple[str, bool]],
    restarted: list[tuple[str, ...]],
) -> list[str]:
    """Take back what this key's run did, newest first. Returns what could not be undone."""
    d, undone = session.deps, []
    for env_file, was_created in reversed(added):
        try:
            d.consumer.remove(env_file, was_created)
        except RotateError as exc:
            undone.append(f"file_{exc.code}")
        except Exception:  # noqa: BLE001 - an undo step must never stop the steps after it
            undone.append("file_unexpected_error")
    for services in reversed(restarted):
        try:
            d.consumer.restart(services)  # the service comes back without the new line
        except RotateError as exc:
            undone.append(f"consumer_{exc.code}")
        except Exception:  # noqa: BLE001
            undone.append("consumer_unexpected_error")
    if stored:
        try:
            d.store.delete(spec.path, spec.secret_name)
        except RotateError as exc:
            if exc.code != "secrets_delete_http_404":  # never stored: nothing to take back
                undone.append(f"secret_{exc.code}")
        except Exception:  # noqa: BLE001
            undone.append("secret_unexpected_error")
    if vendor is not None and (created is not None or attempted):
        try:
            if created is not None:
                vendor.delete_key(created.id)
            else:
                # The create's reply was lost: the key may exist anyway. No key had this name a
                # moment ago (checked above), so any key with it now is the one just made.
                for key in vendor.list_keys().values():
                    if key.name == spec.console_name:
                        vendor.delete_key(key.id)
        except RotateError as exc:
            undone.append(f"new_key_{exc.code}")
        except Exception:  # noqa: BLE001
            undone.append("new_key_unexpected_error")
    return undone


def _clear(session: Session, row: Row, spec: ProvisionSpec) -> tuple[Vendor | None, str]:
    """Everything that must be true before anything is made. (vendor client, why-not)."""
    d = session.deps
    vendor: Vendor | None = None
    if spec.vendor != "self":
        vendor = d.vendor_for(_oid(session, spec))
        if any(is_ours(k.name, spec.console_name) for k in vendor.list_keys().values()):
            return vendor, "name_taken"
    if d.store.exists(spec.path, spec.secret_name):
        return vendor, "secret_exists"
    for c in spec.consumers:
        if d.consumer.has_var(c.env_file, c.env_var):
            return vendor, "env_var_present"
    return vendor, ""


def _provision(session: Session, row: Row, spec: ProvisionSpec) -> bool:
    d = session.deps
    vendor, why = _clear(session, row, spec)
    if why:
        return _refuse(session, row, why)
    created: NewKey | None = None
    attempted = stored = False
    added: list[tuple[str, bool]] = []
    restarted: list[tuple[str, ...]] = []
    try:
        if vendor is not None:
            attempted = True
            created = vendor.create_key(spec.console_name, spec.perms)
            session.say(f"  {row.key.id}: key created (ends {last4(created.id)})")
            live = vendor.list_keys().get(created.id)
            if (
                live is None
                or live.perms != frozenset(spec.perms)
                or live.name != spec.console_name
            ):
                raise RotateError("perms_differ_after_create")
            value = created.value
        else:
            value = generate(spec.length)
        # Set before the call: a create whose reply is lost may still have stored the value,
        # and the secret did not exist a moment ago (checked above), so deleting it is safe.
        stored = True
        d.store.create(spec.path, spec.secret_name, value)
        for c in spec.consumers:
            added.append((c.env_file, d.consumer.add(c.env_file, c.env_var, value)))
        for c in spec.consumers:
            if c.restart:
                d.consumer.restart(c.restart)
                restarted.append(c.restart)
            if c.check != "none" and not d.consumer.check(c.check):
                raise RotateError("check_failed")
        session.say(f"  {row.key.id}: written and checked")
    except BaseException as exc:
        code = exc.code if isinstance(exc, RotateError) else "interrupted"
        if isinstance(exc, RotateError) and exc.detail:
            session.say(f"  {row.key.id}: the reply looked like {exc.detail}")
        undone = _undo(
            session,
            vendor,
            spec,
            created=created,
            attempted=attempted,
            stored=stored,
            added=added,
            restarted=restarted,
        )
        fields: dict[str, str | int] = {"new": last4(created.id)} if created else {}
        ks = session.state.keys.get(row.key.id)
        if undone:
            # something may still exist: keep a failed entry so nobody retries over it blindly
            session.state.keys[row.key.id] = ks or st.KeyState(
                last_rotated=session.today,
                outcome="failed",
                updated=st.stamp(session.moment),
                vendor_key_id=created.id if created else "",
            )
            session.note("provision", f"failed-{code}-ROLLBACK-INCOMPLETE", id=row.key.id, **fields)
            session.say(f"  NEEDS A PERSON: could not undo: {', '.join(undone)}")
        else:
            session.note("provision", f"failed-{code}-rolled-back", id=row.key.id, **fields)
            session.say(f"  {row.key.id}: undone; nothing was left behind")
        if not isinstance(exc, RotateError):
            raise
        return False
    for env_file, was_created in added:
        if not was_created:
            d.consumer.discard_prev(env_file)
    session.state.keys[row.key.id] = st.KeyState(
        last_rotated=session.today,
        outcome="provisioned",
        updated=st.stamp(session.moment),
        vendor_key_id=created.id if created else "",
    )
    session.note(
        "provision",
        "provisioned",
        id=row.key.id,
        **({"new": last4(created.id)} if created else {}),
        files=len(added),
        check="ok",
    )
    return True


def _provision_rows(session: Session, rows: tuple[Row, ...], state_dir: Path) -> int:
    for row in rows:
        spec = row.key.provision
        assert spec is not None  # noqa: S101 - only provisionable rows are passed in
        try:
            ok = _provision(session, row, spec)
        except RotateError as exc:
            if exc.detail:
                session.say(f"  {row.key.id}: the reply looked like {exc.detail}")
            ok = _refuse(session, row, exc.code)
        if not _save(state_dir, session.state, session.say):
            return FAILED
        if not ok:
            session.say("Stopped at the first failure; keys after this one were not touched.")
            return FAILED
    return OK


def run_provision(
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
        return refused("locked", "could not take the apply lock (another run may be going)")
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
        if not plan.provisions:
            say("No key is waiting to be created: nothing to do.")
            line = record_line(moment, run_id, "provision", "nothing-to-create", commit=commit[:12])
            say(line)
            _write_record(state_dir, [line], say)
            return OK
        try:
            rights = read()
        except RightsError as exc:
            return refused("rights", str(exc))
        session = Session(build(rights), state, moment, today, run_id, say)
        state.approval = None  # an approval is good for one run, however it ends
        if not _save(state_dir, state, say):
            return FAILED
        try:
            return _provision_rows(session, plan.provisions, state_dir)
        finally:
            _save(state_dir, state, say)
            _write_record(state_dir, session.lines, say)
    finally:
        lock.release()
