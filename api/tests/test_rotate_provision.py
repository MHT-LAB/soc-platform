"""Creating a first key from an approved plan, against in-memory stand-ins: no network, no
subprocess, no real key. Every secret below is a sentinel the tests search the output for."""

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from rotate_fakes import (
    CLIENT_ID,
    CLIENT_SECRET,
    LC_KEY,
    NEW_ID,
    NEW_VALUE,
    NOW,
    OID,
    rights,
    unreadable,
)
from rotate_support import COMMIT, make_register
from test_rotate_provision_parts import self_toml, vendor_toml

from soc_api.rotate import apply as ap
from soc_api.rotate import provision as pv
from soc_api.rotate import state as st
from soc_api.rotate.keys import load_register
from soc_api.rotate.lc import NewKey, VendorKey
from soc_api.rotate.net import RotateError
from soc_api.rotate.plan import build_plan, local_today
from soc_api.rotate.rights import Rights, Secret

PERMS = ("dr.list", "dr.set")
RULES_FILE, POSTURE_FILE = "env/rules-lc.env", "env/posture-rules.env"


@dataclass
class World:
    """The vendor, the secrets manager and the host's files, with a log of every call."""

    log: list[str] = field(default_factory=list)
    fail: set[str] = field(default_factory=set)
    keys: dict[str, VendorKey] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=lambda: {"SOC_LC_OID": OID})
    files: dict[str, str] = field(default_factory=dict)  # a missing file is simply absent
    prev: dict[str, str] = field(default_factory=dict)
    checks: list[bool] = field(default_factory=list)
    interrupt_on_check: bool = False
    widen: bool = False
    made: int = 0

    def boom(self, op: str) -> None:
        self.log.append(op)
        if op.split(" ")[0] in self.fail:
            raise RotateError(f"fake_{op.split(' ')[0]}")

    def ops(self) -> list[str]:
        return [x.split(" ")[0] for x in self.log]

    # vendor
    def list_keys(self) -> dict[str, VendorKey]:
        self.boom("vendor.list")
        return dict(self.keys)

    def create_key(self, name: str, perms: tuple[str, ...]) -> NewKey:
        self.boom(f"create {name}")
        assert perms == PERMS  # noqa: S101 - exactly the file's list
        self.made += 1
        got = frozenset(perms) | ({"sensor.del"} if self.widen else set())
        self.keys[NEW_ID] = VendorKey(NEW_ID, name, got)
        return NewKey(NEW_ID, Secret(NEW_VALUE))

    def delete_key(self, key_id: str) -> None:
        self.boom("delete_key")
        self.keys.pop(key_id, None)

    # secrets manager
    def get(self, path: str, name: str) -> Secret:
        self.boom(f"get {name}")
        return Secret(self.secrets[name])

    def exists(self, path: str, name: str) -> bool:
        self.boom(f"exists {name}")
        return name in self.secrets

    def create(self, path: str, name: str, value: Secret) -> None:
        self.boom(f"store_create {name}")
        assert name not in self.secrets  # noqa: S101 - a create never overwrites
        self.secrets[name] = value.reveal()

    def delete(self, path: str, name: str) -> None:
        self.boom(f"store_delete {name}")
        self.secrets.pop(name, None)

    # consumer
    def has_var(self, env_file: str, var: str) -> bool:
        self.boom(f"has_var {env_file}")
        return any(x.startswith(f"{var}=") for x in self.files.get(env_file, "").split("\n"))

    def add(self, env_file: str, var: str, value: Secret) -> bool:
        self.boom(f"add {env_file}")
        existed = env_file in self.files
        if existed:
            self.prev[env_file] = self.files[env_file]
        self.files[env_file] = self.files.get(env_file, "") + f"{var}={value.reveal()}\n"
        return not existed

    def remove(self, env_file: str, created: bool) -> None:
        self.boom(f"remove {env_file}")
        if created:
            self.files.pop(env_file, None)
        else:
            self.files[env_file] = self.prev.pop(env_file)

    def discard_prev(self, env_file: str) -> None:
        self.log.append(f"discard_prev {env_file}")
        self.prev.pop(env_file, None)

    def restart(self, services: tuple[str, ...] | list[str]) -> None:
        self.boom(f"restart {','.join(services)}")

    def check(self, name: str) -> bool:
        self.log.append(f"check {name}")
        if self.interrupt_on_check:
            self.interrupt_on_check = False
            raise KeyboardInterrupt
        if "check_error" in self.fail:
            raise RotateError("fake_check_error")
        return self.checks.pop(0) if self.checks else True

    def deps(self) -> ap.Deps:
        return ap.Deps(lambda _oid: self, self, self, lambda _s: None)  # type: ignore[arg-type]


class Run:
    """A register, a state folder, and a way to approve and run a provision."""

    def __init__(
        self, root: Path, files: dict[str, str], world: World | None = None, **kw: Any
    ) -> None:
        self.world = world or World(**kw)
        self.keys_dir = make_register(root, files)
        self.state_dir = root / "state"
        self.state_dir.mkdir()
        self.said: list[str] = []
        self.moment = NOW
        self.rights_read = 0

    def state(self) -> st.State:
        path = self.state_dir / "state.json"
        return st.load(path) if path.exists() else st.State()

    def plan_hash(self) -> str:
        plan = build_plan(
            load_register(self.keys_dir), self.state(), local_today(self.moment), COMMIT
        )
        return plan.plan_hash

    def approve(self, *, age: timedelta = timedelta(0), commit: str = COMMIT) -> str:
        state = self.state()
        plan_hash = self.plan_hash()
        state.approval = st.Approval(plan_hash, commit, self.moment - age)
        st.save(self.state_dir / "state.json", state)
        return plan_hash

    def read(self) -> Rights:
        self.rights_read += 1
        return rights()

    def provision(self, plan_hash: str | None = None, *, read: Any = None) -> int:
        return pv.run_provision(
            keys_dir=self.keys_dir,
            state_dir=self.state_dir,
            commit=COMMIT,
            plan_hash=plan_hash or self.plan_hash(),
            read=read or self.read,
            build=lambda _r: self.world.deps(),
            say=self.said.append,
            now=lambda: self.moment,
        )

    def go(self) -> int:
        return self.provision(self.approve())

    def text(self) -> str:
        return "\n".join(self.said)

    def everything_written(self) -> str:
        parts = [self.text(), *(p.read_text() for p in self.state_dir.iterdir() if p.is_file())]
        return "\n".join(parts)


def vendor_run(root: Path, **kw: Any) -> Run:
    return Run(root, {"rules-key": vendor_toml()}, **kw)


def both_run(root: Path, **kw: Any) -> Run:
    return Run(root, {"rules-key": vendor_toml(), "stamp-key": self_toml()}, **kw)


# ---- the good run ----


def test_a_vendor_key_is_made_stored_written_checked_and_recorded(tmp_path: Path) -> None:
    run = vendor_run(tmp_path, checks=[True])
    run.world.files[RULES_FILE] = "SOC_RULES_LC_OID=01234567-89ab-cdef-0123-456789abcdef\n"
    assert run.go() == 0
    w = run.world
    assert w.ops() == [
        "get",  # the organization id
        "vendor.list",
        "exists",
        "has_var",
        "create",
        "vendor.list",  # read back: the permissions must be exactly the file's
        "store_create",
        "add",
        "check",
        "discard_prev",
    ]
    assert w.secrets["RULES_KEY"] == NEW_VALUE
    assert w.files[RULES_FILE].endswith(f"SOC_RULES_LC_KEY={NEW_VALUE}\n")
    assert w.files[RULES_FILE].startswith("SOC_RULES_LC_OID=")  # the other line is kept
    assert w.keys[NEW_ID].name == "rules-key" and w.keys[NEW_ID].perms == frozenset(PERMS)
    entry = run.state().keys["rules-key"]
    assert (entry.outcome, entry.vendor_key_id, entry.last_rotated) == (
        "provisioned",
        NEW_ID,
        local_today(NOW),
    )
    assert run.state().approval is None  # good for one run, however it ends


def test_a_random_key_needs_no_vendor_and_goes_to_both_files(tmp_path: Path) -> None:
    run = Run(tmp_path, {"stamp-key": self_toml()}, checks=[True])
    run.world.files[RULES_FILE] = "SOC_RULES_ORG=acme\n"
    assert run.go() == 0
    w = run.world
    assert "vendor.list" not in w.log and not any(x.startswith("create ") for x in w.log)
    value = w.secrets["STAMP_KEY"]
    assert len(value) == 48
    assert w.files[RULES_FILE] == f"SOC_RULES_ORG=acme\nSOC_RULES_STAMP_KEY={value}\n"
    assert w.files[POSTURE_FILE] == f"SOC_POSTURE_STAMP_KEY={value}\n"
    # only the file that feeds a running service is restarted and checked
    assert "restart posture" in w.log and w.log.count("check posture_check") == 1
    assert run.state().keys["stamp-key"].vendor_key_id == ""
    assert value not in run.everything_written()


def test_the_stamp_key_is_made_before_the_vendor_key_and_both_are_recorded(tmp_path: Path) -> None:
    run = both_run(tmp_path, checks=[True, True])
    assert run.go() == 0
    ops = run.world.log
    assert ops.index("exists STAMP_KEY") < ops.index("exists RULES_KEY")
    assert set(run.state().keys) == {"stamp-key", "rules-key"}
    assert run.world.files[RULES_FILE].count("=") == 2  # the stamp line, then the key line


def test_no_value_or_credential_is_ever_printed_or_saved(tmp_path: Path) -> None:
    run = both_run(tmp_path, checks=[True, True])
    assert run.go() == 0
    written = run.everything_written()
    for sentinel in (NEW_VALUE, LC_KEY, CLIENT_ID, CLIENT_SECRET, run.world.secrets["STAMP_KEY"]):
        assert sentinel not in written
    assert "provision" in written and "provisioned" in written


def test_an_existing_file_that_was_extended_keeps_nothing_behind(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    run.world.files[RULES_FILE] = "A=1\n"
    assert run.go() == 0
    assert run.world.prev == {}


def test_a_second_run_with_nothing_left_to_create_does_nothing(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    assert run.go() == 0
    before = list(run.world.log)
    assert run.provision(run.approve()) == 0
    assert run.world.log == before and "nothing-to-create" in run.text()


# ---- what must be true before anything is made ----


@pytest.mark.parametrize("name", ["rules-key", "rules-key-20261118"])
def test_a_live_key_with_the_name_stops_it_before_anything_is_made(
    tmp_path: Path, name: str
) -> None:
    run = vendor_run(tmp_path)
    run.world.keys["theirs0001"] = VendorKey("theirs0001", name, frozenset(PERMS))
    assert run.go() == 1
    assert not any(x.startswith(("create ", "store_create", "add")) for x in run.world.log)
    assert "refused-name_taken" in run.text() and "rules-key" not in run.state().keys


def test_a_secret_that_is_already_there_stops_it(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    run.world.secrets["RULES_KEY"] = "something-already-here"
    assert run.go() == 1
    assert "refused-secret_exists" in run.text()
    assert run.world.secrets["RULES_KEY"] == "something-already-here"
    assert not any(x.startswith("create ") for x in run.world.log)


def test_a_variable_that_is_already_in_a_file_stops_it(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    run.world.files[RULES_FILE] = "SOC_RULES_LC_KEY=hand-made\n"
    assert run.go() == 1
    assert "refused-env_var_present" in run.text()
    assert run.world.files[RULES_FILE] == "SOC_RULES_LC_KEY=hand-made\n"
    assert not any(x.startswith("create ") for x in run.world.log)


def test_a_bad_organization_id_in_the_store_stops_it(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    run.world.secrets["SOC_LC_OID"] = "not-an-org-id"
    assert run.go() == 1 and "refused-org_id_bad_oid" in run.text()


def test_a_refusal_is_not_remembered_so_it_can_be_tried_again(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    run.world.secrets["RULES_KEY"] = "x"
    assert run.go() == 1
    assert "rules-key" not in run.state().keys  # nothing was made: nothing to protect from a retry
    del run.world.secrets["RULES_KEY"]
    assert run.go() == 0


# ---- the permissions the vendor really gave ----


def test_a_key_that_came_out_wider_than_asked_is_deleted_again_and_nothing_is_stored(
    tmp_path: Path,
) -> None:
    run = vendor_run(tmp_path, widen=True)
    assert run.go() == 1
    assert "perms_differ_after_create" in run.text() and "rolled-back" in run.text()
    assert NEW_ID not in run.world.keys and "RULES_KEY" not in run.world.secrets
    assert run.world.files == {} and "rules-key" not in run.state().keys


def test_a_key_that_came_back_under_another_name_is_taken_back_too(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    original = run.world.create_key

    def renamed(name: str, perms: tuple[str, ...]) -> NewKey:
        made = original(name, perms)
        run.world.keys[NEW_ID] = VendorKey(NEW_ID, "somebody-elses-name", frozenset(perms))
        return made

    run.world.create_key = renamed  # type: ignore[method-assign]
    assert run.go() == 1 and "perms_differ_after_create" in run.text()
    assert NEW_ID not in run.world.keys and "RULES_KEY" not in run.world.secrets


def test_a_key_the_vendor_cannot_find_again_is_treated_the_same_way(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)

    def lose(*_a: Any) -> None:
        run.world.keys.pop(NEW_ID, None)

    original = run.world.create_key

    def create_then_lose(name: str, perms: tuple[str, ...]) -> NewKey:
        made = original(name, perms)
        lose()
        return made

    run.world.create_key = create_then_lose  # type: ignore[method-assign]
    assert run.go() == 1 and "perms_differ_after_create" in run.text()


# ---- any failure undoes everything, newest first ----


@pytest.mark.parametrize(
    "fail",
    ["store_create", "add", "restart", "check_false", "check_error"],
)
def test_a_failure_at_any_step_leaves_nothing_behind(tmp_path: Path, fail: str) -> None:
    world = World(checks=[False] if fail == "check_false" else [])
    if fail != "check_false":
        world.fail = {fail}
    run = both_run(tmp_path, world=world)
    world.files[RULES_FILE] = "A=1\n"  # an existing file: it must come back exactly
    assert run.go() == 1
    # the first key is the stamp key: its steps are what failed, so it is the one undone
    assert world.files == {RULES_FILE: "A=1\n"} and world.prev == {}
    assert "STAMP_KEY" not in world.secrets and "RULES_KEY" not in world.secrets
    assert set(world.keys) == set() and run.state().keys == {}
    assert "rolled-back" in run.text() or "refused" in run.text()


def test_a_failed_key_creation_leaves_nothing_behind(tmp_path: Path) -> None:
    run = vendor_run(tmp_path, fail={"create"})
    assert run.go() == 1
    assert run.world.keys == {} and run.world.files == {} and "RULES_KEY" not in run.world.secrets
    assert "rules-key" not in run.state().keys


def test_a_secret_stored_but_whose_reply_was_lost_is_deleted_again(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    w = run.world

    def stored_then_timeout(path: str, name: str, value: Secret) -> None:
        w.secrets[name] = value.reveal()
        raise RotateError("timeout")

    w.create = stored_then_timeout  # type: ignore[method-assign]
    assert run.go() == 1
    assert "RULES_KEY" not in w.secrets and w.keys == {}
    assert "rolled-back" in run.text() and "ROLLBACK-INCOMPLETE" not in run.text()


def test_a_key_made_but_whose_reply_was_lost_is_found_by_name_and_deleted(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    w = run.world

    def made_then_timeout(name: str, perms: tuple[str, ...]) -> NewKey:
        w.keys["lostreply01"] = VendorKey("lostreply01", name, frozenset(perms))
        raise RotateError("timeout")

    w.create_key = made_then_timeout  # type: ignore[method-assign]
    w.keys["unrelated01"] = VendorKey("unrelated01", "someone-else", frozenset(PERMS))
    assert run.go() == 1
    assert set(w.keys) == {"unrelated01"}  # only the key with this exact name was taken back
    assert "rolled-back" in run.text()


def test_a_secret_that_was_never_stored_is_not_an_undo_failure(tmp_path: Path) -> None:
    run = vendor_run(tmp_path, fail={"store_create"})

    def not_found(path: str, name: str) -> None:
        raise RotateError("secrets_delete_http_404")

    run.world.delete = not_found  # type: ignore[method-assign,assignment]
    assert run.go() == 1
    assert "rolled-back" in run.text() and "ROLLBACK-INCOMPLETE" not in run.text()
    assert run.world.keys == {} and "rules-key" not in run.state().keys


def test_any_other_error_deleting_the_secret_is_an_incomplete_undo(tmp_path: Path) -> None:
    run = vendor_run(tmp_path, checks=[False])

    def forbidden(path: str, name: str) -> None:
        raise RotateError("secrets_delete_http_403")

    run.world.delete = forbidden  # type: ignore[method-assign,assignment]
    assert run.go() == 1 and "ROLLBACK-INCOMPLETE" in run.text()
    assert run.state().keys["rules-key"].outcome == "failed"


def test_a_vendor_failure_after_the_key_exists_deletes_the_key_and_the_secret(
    tmp_path: Path,
) -> None:
    run = vendor_run(tmp_path, checks=[False])
    assert run.go() == 1
    w = run.world
    undo = w.log[w.log.index("check rules_plan") + 1 :]
    # the files first, then the secret, then the key: newest first
    assert [x.split(" ")[0] for x in undo] == ["remove", "store_delete", "delete_key"]
    assert w.files == {} and w.secrets == {"SOC_LC_OID": OID} and w.keys == {}


def test_a_random_key_failing_its_check_restarts_the_service_without_the_new_line(
    tmp_path: Path,
) -> None:
    run = Run(tmp_path, {"stamp-key": self_toml()}, checks=[False])
    assert run.go() == 1
    w = run.world
    undo = w.log[w.log.index("check posture_check") + 1 :]
    assert [x.split(" ")[0] for x in undo] == ["remove", "remove", "restart", "store_delete"]
    assert w.files == {} and "STAMP_KEY" not in w.secrets


def test_a_second_file_failing_undoes_the_first(tmp_path: Path) -> None:
    run = Run(tmp_path, {"stamp-key": self_toml()})

    original = run.world.add

    def add(env_file: str, var: str, value: Secret) -> bool:
        if env_file == POSTURE_FILE:
            raise RotateError("env_write_failed")
        return original(env_file, var, value)

    run.world.add = add  # type: ignore[method-assign]
    assert run.go() == 1
    assert run.world.files == {} and "STAMP_KEY" not in run.world.secrets
    assert "env_write_failed" in run.text() and "rolled-back" in run.text()


def test_a_ctrl_c_during_the_check_undoes_everything_and_still_stops(tmp_path: Path) -> None:
    run = vendor_run(tmp_path, interrupt_on_check=True)
    with pytest.raises(KeyboardInterrupt):
        run.go()
    w = run.world
    assert w.files == {} and w.keys == {} and "RULES_KEY" not in w.secrets
    assert "interrupted-rolled-back" in "\n".join(
        (run.state_dir / "record.txt").read_text().split()
    )
    assert run.state().keys == {}


def test_the_first_failure_stops_the_run_and_the_next_key_is_not_touched(tmp_path: Path) -> None:
    run = both_run(tmp_path, checks=[False])
    assert run.go() == 1
    assert "Stopped at the first failure" in run.text()
    assert not any(x.startswith("exists RULES_KEY") for x in run.world.log)


def test_an_undo_that_cannot_finish_is_said_loudly_and_is_never_retried_blindly(
    tmp_path: Path,
) -> None:
    run = vendor_run(tmp_path, checks=[False])
    run.world.fail = {"delete_key"}  # the new key cannot be taken back
    assert run.go() == 1
    assert "ROLLBACK-INCOMPLETE" in run.text() and "NEEDS A PERSON" in run.text()
    entry = run.state().keys["rules-key"]
    assert (entry.outcome, entry.vendor_key_id) == ("failed", NEW_ID)
    # the key is still live: the plan must not offer to make another one over it
    plan = build_plan(load_register(run.keys_dir), run.state(), local_today(NOW), COMMIT)
    assert plan.provisions == ()


def test_an_unexpected_error_in_an_undo_step_does_not_stop_the_steps_after_it(
    tmp_path: Path,
) -> None:
    run = vendor_run(tmp_path, checks=[False])

    def boom(*_a: Any) -> None:
        raise ValueError("unexpected")

    run.world.remove = boom  # type: ignore[method-assign,assignment]
    assert run.go() == 1
    assert "file_unexpected_error" in run.text()
    assert "RULES_KEY" not in run.world.secrets and run.world.keys == {}  # the rest still ran


# ---- the approval ----


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"age": timedelta(minutes=31)}, "expired"),
        ({"commit": "cd" * 20}, "commit_changed"),
    ],
)
def test_a_stale_or_wrong_approval_changes_nothing_and_reads_no_rights(
    tmp_path: Path, kwargs: dict[str, Any], code: str
) -> None:
    run = vendor_run(tmp_path)
    assert run.provision(run.approve(**kwargs)) == 2
    assert f"refused-{code}" in run.text()
    assert run.rights_read == 0 and run.world.log == []


def test_no_approval_at_all_is_refused(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    assert run.provision() == 2 and "refused-no_approval" in run.text()
    assert run.rights_read == 0 and run.world.log == []


def test_an_approval_for_a_different_plan_is_refused(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    run.approve()
    assert run.provision("0123456789ab") == 2 and "refused-plan_changed" in run.text()
    assert run.world.log == []


def test_approving_one_list_is_not_approving_a_longer_one(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    hash_one = run.approve()
    make_register(tmp_path, {"stamp-key": self_toml()})  # another key appears after the approval
    assert run.provision(hash_one) == 2 and "refused-plan_changed" in run.text()
    assert run.world.log == []


def test_an_approval_is_used_up_by_one_run_even_when_it_fails(tmp_path: Path) -> None:
    run = vendor_run(tmp_path, checks=[False])
    hash_now = run.approve()
    assert run.provision(hash_now) == 1
    assert run.state().approval is None
    assert run.provision(hash_now) == 2 and "refused-no_approval" in run.text()


def test_rights_that_cannot_be_read_stop_it_before_any_call(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    assert run.provision(run.approve(), read=unreadable()) == 2
    assert "refused-rights" in run.text() and run.world.log == []


def test_a_second_run_at_the_same_time_is_refused(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    hash_now = run.approve()
    lock = ap.ApplyLock(run.state_dir / "apply.lock")
    try:
        assert run.provision(hash_now) == 2 and "refused-locked" in run.text()
    finally:
        lock.release()
    assert run.world.log == []


def test_a_register_with_a_problem_stops_it(tmp_path: Path) -> None:
    run = vendor_run(tmp_path)
    run.approve()
    (run.keys_dir / "junk.toml").write_text("not = [valid")
    assert run.provision("0123456789ab") == 2 and "refused-register" in run.text()
