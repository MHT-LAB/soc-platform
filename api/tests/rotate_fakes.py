"""In-memory stand-ins for the vendor, the secrets manager and the consumer, and a harness that
runs an apply against them. No network, no subprocess, no real key: every "secret" below is a
sentinel the tests search the outputs for."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from rotate_support import COMMIT, key_text, make_register

from soc_api.rotate import apply as ap
from soc_api.rotate import state as st
from soc_api.rotate.lc import NewKey, VendorKey
from soc_api.rotate.net import RotateError
from soc_api.rotate.plan import build_plan, local_today
from soc_api.rotate.rights import Rights, RightsError, Secret

NOW = datetime(2026, 11, 18, 15, 0, tzinfo=UTC)
OLD_VALUE = "OLDKEYVALUE-aaaaaaaaaaaa"
NEW_VALUE = "NEWKEYVALUE-bbbbbbbbbbbb"
LC_KEY = "LCROTATORKEY-cccccccccccc"
CLIENT_ID = "CLIENTID-dddd1111"
CLIENT_SECRET = "CLIENTSECRET-eeee2222ffff"
SENTINELS = (OLD_VALUE, NEW_VALUE, LC_KEY, CLIENT_ID, CLIENT_SECRET)
OID = "01234567-89ab-cdef-0123-456789abcdef"
PERMS = ("sensor.list", "dr.list")
OLD_ID, NEW_ID = "oldkeyid0001", "newkeyid0002"
SPEC_NAME = "x"  # console_name in rotate_support.key_text


def rights() -> Rights:
    return Rights(
        Secret(LC_KEY),
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        "https://secrets.example.test",
        "proj-12345678",
        "dev",
    )


@dataclass
class World:
    """Everything the apply can touch, and a log of every call (never a value)."""

    log: list[str] = field(default_factory=list)
    fail: set[str] = field(default_factory=set)
    keys: dict[str, VendorKey] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    env: str = OLD_VALUE
    checks: list[bool] = field(default_factory=lambda: [True, True])
    interrupt_on_check: bool = False
    made: int = 0

    def __post_init__(self) -> None:
        self.keys = self.keys or {OLD_ID: VendorKey(OLD_ID, SPEC_NAME, frozenset(PERMS))}
        self.secrets = self.secrets or {"AUTO_KEY_VALUE": OLD_VALUE, "SOC_LC_OID": OID}

    def boom(self, op: str) -> None:
        self.log.append(op)
        if op.split(" ")[0] in self.fail:
            raise RotateError(f"fake_{op.split(' ')[0]}")

    # vendor
    def list_keys(self) -> dict[str, VendorKey]:
        self.boom("vendor.list")
        return dict(self.keys)

    def create_key(self, name: str, perms: tuple[str, ...]) -> NewKey:
        self.boom(f"create {name}")
        assert perms == PERMS  # noqa: S101 - the new key must carry exactly the file's list
        new_id = NEW_ID if self.made == 0 else f"newkeyid{self.made + 2:04d}"
        self.made += 1
        self.keys[new_id] = VendorKey(new_id, name, frozenset(perms))
        return NewKey(new_id, Secret(NEW_VALUE))

    def delete_key(self, key_id: str) -> None:
        self.boom(f"delete {'old' if key_id == OLD_ID else 'new' if key_id == NEW_ID else 'other'}")
        self.keys.pop(key_id, None)

    # secrets manager
    def get(self, path: str, name: str) -> Secret:
        self.boom(f"get {name}")
        return Secret(self.secrets[name])

    def set(self, path: str, name: str, value: Secret) -> None:
        self.boom(f"set {name}")
        self.secrets[name] = value.reveal()

    # consumer
    def install(self, env_file: str, var: str, value: Secret) -> None:
        self.boom("install")
        self.env = value.reveal()

    def restore(self, env_file: str) -> None:
        self.boom("restore")
        self.env = OLD_VALUE

    def discard_prev(self, env_file: str) -> None:
        self.log.append("discard_prev")

    def restart(self, services: tuple[str, ...] | list[str]) -> None:
        self.boom("restart")

    def check(self, name: str) -> bool:
        self.log.append("check")
        if self.interrupt_on_check:
            self.interrupt_on_check = False  # one Ctrl-C, as a person would send
            raise KeyboardInterrupt
        if "check_error" in self.fail:
            raise RotateError("fake_check_error")
        return self.checks.pop(0) if self.checks else True

    def sleep(self, seconds: float) -> None:
        self.log.append(f"sleep {int(seconds)}")

    def deps(self) -> ap.Deps:
        return ap.Deps(lambda _oid: self, self, self, self.sleep)  # type: ignore[arg-type]


class Harness:
    """A register with one automatic key, a state folder, and a way to approve and apply."""

    def __init__(self, root: Path, world: World | None = None, files: dict[str, str] | None = None):
        self.world = world or World()
        self.keys_dir = make_register(
            root, files or {"auto-key": key_text("auto-key", method="automatic")}
        )
        self.state_dir = root / "state"
        self.state_dir.mkdir()
        self.said: list[str] = []
        self.moment = NOW
        self.rights_read = 0

    def state(self) -> st.State:
        return st.load(self.state_dir / "state.json")

    def put_state(self, state: st.State) -> None:
        st.save(self.state_dir / "state.json", state)

    def plan_hash(self) -> str:
        from soc_api.rotate.keys import load_register

        plan = build_plan(
            load_register(self.keys_dir), self.state_or_empty(), local_today(self.moment), COMMIT
        )
        return plan.plan_hash

    def state_or_empty(self) -> st.State:
        path = self.state_dir / "state.json"
        return st.load(path) if path.exists() else st.State()

    def approve(self, *, age: timedelta = timedelta(0), commit: str = COMMIT) -> str:
        state = self.state_or_empty()
        plan_hash = self.plan_hash()
        state.approval = st.Approval(plan_hash, commit, self.moment - age)
        self.put_state(state)
        return plan_hash

    def read(self) -> Rights:
        self.rights_read += 1
        return rights()

    def apply(self, plan_hash: str | None = None, *, read: object = None) -> int:
        return ap.run_apply(
            keys_dir=self.keys_dir,
            state_dir=self.state_dir,
            commit=COMMIT,
            plan_hash=plan_hash or self.plan_hash(),
            read=read or self.read,  # type: ignore[arg-type]
            build=lambda _r: self.world.deps(),
            say=self.said.append,
            now=lambda: self.moment,
        )

    def preflight(self) -> int:
        return ap.run_preflight(
            keys_dir=self.keys_dir,
            state_dir=self.state_dir,
            commit=COMMIT,
            read=self.read,
            build=lambda _r: self.world.deps(),
            say=self.said.append,
            now=lambda: self.moment,
        )

    def text(self) -> str:
        return "\n".join(self.said)

    def everything_written(self) -> str:
        return "\n".join(
            [self.text(), *(p.read_text() for p in self.state_dir.iterdir() if p.is_file())]
        )


def unreadable() -> object:
    def read() -> Rights:
        raise RightsError("missing LC_ROTATOR_KEY")

    return read
