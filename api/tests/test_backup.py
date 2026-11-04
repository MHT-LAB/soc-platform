"""deploy/backup.sh, deploy/init-backup.sh and the systemd units that run them.

The scripts run for real. The database container and the encryption tool are replaced by
small stubs (SOC_INIT_TEST is the only way to swap them in, and it is refused for root), so
what is checked is the script's own behaviour: what it refuses, what it leaves behind and
what it never writes. One test uses the real `age` where it is installed."""

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
BACKUP = DEPLOY / "backup.sh"
INIT = DEPLOY / "init-backup.sh"
BASH = shutil.which("bash") or "/bin/bash"

PUB = "age1" + "q" * 58
SECRET = "AGE-SECRET-KEY-1" + "Q" * 58
PLAIN = "PGDMP-fake-database-dump"  # what the stub database "dumps"; must never reach a file

not_root = pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user")

COMPOSE_STUB = r"""#!/bin/bash
# stands in for soc-compose.sh: only `exec -T db <command>` is understood
[[ "$1 $2 $3" == "exec -T db" ]] || exit 99
shift 3
cmd="$1"; shift
case "$cmd" in
  pg_isready) [[ -z "${STUB_DB_DOWN:-}" ]] ;;
  pg_dump)
    [[ -z "${STUB_DUMP_FAIL:-}" ]] || exit 1
    if [[ -n "${STUB_DUMP_EMPTY:-}" ]]; then exit 0; fi
    printf '%s\n' "${STUB_DUMP_BODY:-PGDMP-fake-database-dump}" ;;
  pg_dumpall)
    [[ -z "${STUB_ROLES_FAIL:-}" ]] || exit 1
    [[ -z "${STUB_ROLES_EMPTY:-}" ]] || exit 0
    echo "CREATE ROLE soc_app;"
    echo "ALTER ROLE soc_app WITH NOSUPERUSER LOGIN;"
    # like the real tool: passwords appear unless the flag says not to
    [[ " $* " == *" --no-role-passwords "* && -z "${STUB_ROLE_PASSWORD:-}" ]] \
      || echo "ALTER ROLE soc_app PASSWORD 'hunter2hunter2';" ;;
  pg_restore)
    body="$(cat)"
    [[ "$body" != *BAD* ]] || exit 1
    [[ -n "${STUB_NO_TABLES:-}" ]] || echo "; TABLE public alert soc_owner" ;;
  *) exit 98 ;;
esac
"""

# "encrypts" by rot13 behind a header, so the plain text never appears in the output
AGE_STUB = r"""#!/bin/bash
[[ -z "${STUB_AGE_FAIL:-}" ]] || exit 1
rec=""; out=""
while [[ $# -gt 1 ]]; do
  case "$1" in -R) rec="$2"; shift 2 ;; -o) out="$2"; shift 2 ;; *) break ;; esac
done
[[ -s "$rec" && -n "$out" && -f "$1" ]] || exit 2
{ echo "age-stub"; tr 'A-Za-z' 'N-ZA-Mn-za-m' < "$1"; } > "$out"
"""

KEYGEN_STUB = r"""#!/bin/bash
[[ -z "${STUB_KEYGEN_FAIL:-}" ]] || exit 1
if [[ "${1:-}" == "-y" ]]; then
  grep -q '^AGE-SECRET-KEY-1' || exit 1
  echo "@PUB@"
  exit 0
fi
echo "Public key: @PUB@" >&2
echo "# created: 2026-01-01T00:00:00Z"
echo "# public key: @PUB@"
echo "@SECRET@"
""".replace("@PUB@", PUB).replace("@SECRET@", SECRET)


def write_exe(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(0o755)
    return path


@pytest.fixture
def stubs(tmp_path: Path) -> Path:
    d = tmp_path / "stubs"
    d.mkdir()
    write_exe(d / "soc-compose.sh", COMPOSE_STUB)
    write_exe(d / "age", AGE_STUB)
    write_exe(d / "age-keygen", KEYGEN_STUB)
    return d


def host(state: Path, *, key: bool = True) -> Path:
    (state / "env").mkdir(parents=True, exist_ok=True)
    (state / "env" / "db-owner.env").write_text("SOC_MIGRATE_URL=x\n")
    if key:
        (state / "env" / "backup-age.pub").write_text(PUB + "\n")
    return state


def run_backup(
    state: Path, stubs: Path, *, test_mode: bool = True, **env: Any
) -> subprocess.CompletedProcess[str]:
    full = {"PATH": "/usr/bin:/bin", "SOC_STATE_DIR": str(state), "SOC_BACKUP_MIN_FREE_MB": "1"}
    if test_mode:
        full.update(
            SOC_INIT_TEST="1",
            SOC_COMPOSE=str(stubs / "soc-compose.sh"),
            SOC_BACKUP_AGE=str(stubs / "age"),
        )
    full.update(env)
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(BACKUP)],
        env=full,
        capture_output=True,
        text=True,
        timeout=60,
    )


def files(state: Path) -> set[str]:
    return {
        str(p.relative_to(state))
        for p in state.rglob("*")
        if p.relative_to(state).parts[0] != "stubs"
    }


def sets(state: Path) -> list[str]:
    return sorted(p.name[:-7] for p in (state / "backups").glob("soc-*.sha256"))


def stamp(n: int) -> str:
    return f"20261103T{n // 3600:02d}{n % 3600 // 60:02d}{n % 60:02d}Z"


def test_the_scripts_are_executable() -> None:
    assert os.access(BACKUP, os.X_OK) and os.access(INIT, os.X_OK)


# ---- backup.sh: the good run ----


@not_root
def test_a_run_writes_one_complete_encrypted_set_with_strict_modes(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1))
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("backup outcome=ok set=soc-20261103T000001Z ")
    folder = tmp_path / "backups"
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    names = sorted(p.name for p in folder.iterdir())
    assert names == [
        "soc-20261103T000001Z.dump.age",
        "soc-20261103T000001Z.globals.sql.age",
        "soc-20261103T000001Z.sha256",
    ]
    for p in folder.iterdir():
        assert stat.S_IMODE(p.stat().st_mode) == 0o600, p.name
    sums = (folder / "soc-20261103T000001Z.sha256").read_text().splitlines()
    assert len(sums) == 2
    for line in sums:
        digest, _, name = line.partition("  ")
        assert hashlib.sha256((folder / name).read_bytes()).hexdigest() == digest


@not_root
def test_nothing_in_plain_text_is_left_anywhere(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1), TMPDIR=str(tmp_path))
    assert r.returncode == 0, r.stderr
    for p in tmp_path.rglob("*"):
        if p.is_file() and p.parent.name != "stubs":
            data = p.read_bytes()
            assert PLAIN.encode() not in data, p
            assert b"CREATE ROLE" not in data, p
    leftovers = [p.name for p in (tmp_path / "backups").iterdir() if p.name.startswith(".")]
    assert leftovers == []  # no temporary folder, no lock


@not_root
def test_roles_are_dumped_without_passwords(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1))
    assert r.returncode == 0, r.stderr
    # the stub "encrypts" with rot13, so the roles file can be read back for the check
    enc = (tmp_path / "backups" / "soc-20261103T000001Z.globals.sql.age").read_text()
    plain = enc.split("\n", 1)[1].translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )
    assert "CREATE ROLE soc_app" in plain and "PASSWORD" not in plain


@not_root
def test_it_refuses_without_the_test_switch_unless_root(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    r = run_backup(tmp_path, stubs, test_mode=False)
    assert r.returncode == 1 and "reason=run_as_root" in r.stderr
    assert not (tmp_path / "backups").exists()


# ---- backup.sh: what it refuses, and what it leaves behind when it does ----


def refused(tmp_path: Path, stubs: Path, expect: str, **env: Any) -> None:
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1), **env)
    assert r.returncode == 1, r.stdout
    assert expect in r.stderr, r.stderr
    assert r.stdout == ""
    folder = tmp_path / "backups"
    assert not folder.exists() or sorted(p.name for p in folder.iterdir()) == []


@not_root
def test_no_key_file_means_no_backup_and_no_folder(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path, key=False)
    refused(tmp_path, stubs, "step=key reason=missing_env/backup-age.pub")
    assert not (tmp_path / "backups").exists()


@pytest.mark.parametrize(
    "content", ["not a key\n", PUB + "\n" + PUB + "\n", "AGE-SECRET-KEY-1" + "Q" * 58 + "\n"]
)
@not_root
def test_the_key_file_must_hold_exactly_one_public_key(
    tmp_path: Path, stubs: Path, content: str
) -> None:
    host(tmp_path)
    (tmp_path / "env" / "backup-age.pub").write_text(content)
    refused(tmp_path, stubs, "step=key")
    assert not (tmp_path / "backups").exists()


@not_root
def test_without_age_nothing_is_written(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    refused(tmp_path, stubs, "reason=age_is_not_installed", SOC_BACKUP_AGE="no-such-age")
    assert not (tmp_path / "backups").exists()


@not_root
def test_a_database_that_is_down_is_refused(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    refused(tmp_path, stubs, "step=database reason=database_not_healthy", STUB_DB_DOWN="1")


@pytest.mark.parametrize(
    ("env", "expect"),
    [
        ({"STUB_DUMP_FAIL": "1"}, "step=dump reason=pg_dump_failed"),
        ({"STUB_DUMP_EMPTY": "1"}, "step=verify reason=dump_is_empty"),
        ({"STUB_DUMP_BODY": "BAD dump"}, "step=verify reason=dump_is_not_readable"),
        ({"STUB_NO_TABLES": "1"}, "step=verify reason=dump_lists_no_tables"),
        ({"STUB_ROLES_FAIL": "1"}, "step=roles reason=pg_dumpall_failed"),
        ({"STUB_ROLES_EMPTY": "1"}, "step=verify reason=roles_dump_is_empty"),
        ({"STUB_ROLE_PASSWORD": "1"}, "step=verify reason=roles_dump_contains_a_password"),
        ({"STUB_AGE_FAIL": "1"}, "step=encrypt reason=age_failed"),
    ],
)
@not_root
def test_a_bad_dump_or_a_failed_encryption_leaves_no_file(
    tmp_path: Path, stubs: Path, env: dict[str, str], expect: str
) -> None:
    host(tmp_path)
    refused(tmp_path, stubs, expect, **env)


@not_root
def test_a_failed_run_keeps_the_sets_that_already_exist(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    assert run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1)).returncode == 0
    before = {p.name: p.read_bytes() for p in (tmp_path / "backups").iterdir()}
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(2), STUB_DUMP_FAIL="1")
    assert r.returncode == 1
    assert {p.name: p.read_bytes() for p in (tmp_path / "backups").iterdir()} == before


@not_root
def test_it_never_overwrites_a_set(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    assert run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1)).returncode == 0
    before = {p.name: p.read_bytes() for p in (tmp_path / "backups").iterdir()}
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1), STUB_DUMP_BODY="something else")
    assert r.returncode == 1 and "already_exists_never_overwrites" in r.stderr
    assert {p.name: p.read_bytes() for p in (tmp_path / "backups").iterdir()} == before


@not_root
def test_too_little_free_space_is_refused(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1), SOC_BACKUP_MIN_FREE_MB="999999999")
    assert r.returncode == 1 and "step=space reason=not_enough_free_space" in r.stderr
    assert sorted((tmp_path / "backups").iterdir()) == []


@pytest.mark.parametrize("keep", ["1", "101", "x", "8; rm"])
@not_root
def test_the_retention_setting_is_validated(tmp_path: Path, stubs: Path, keep: str) -> None:
    host(tmp_path)
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1), SOC_BACKUP_KEEP=keep)
    assert r.returncode == 1 and "SOC_BACKUP_KEEP_must_be_2_to_100" in r.stderr


# ---- backup.sh: retention, leftovers, overlap ----


@not_root
def test_the_newest_eight_sets_are_kept_by_default(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    for n in range(1, 11):
        assert run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(n)).returncode == 0
    assert sets(tmp_path) == [f"soc-{stamp(n)}" for n in range(3, 11)]
    assert len(list((tmp_path / "backups").iterdir())) == 8 * 3  # no strays of removed sets


@not_root
def test_the_retention_count_is_adjustable(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    for n in range(1, 5):
        r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(n), SOC_BACKUP_KEEP="2")
        assert r.returncode == 0, r.stderr
    assert sets(tmp_path) == [f"soc-{stamp(3)}", f"soc-{stamp(4)}"]
    assert r.stdout.strip().endswith("kept=2")


@not_root
def test_leftovers_of_a_dead_run_are_cleaned_but_complete_sets_are_not(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    assert run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1)).returncode == 0
    folder = tmp_path / "backups"
    (folder / "soc-20261103T000009Z.dump.age").write_text("half a set")
    (folder / "soc-20261103T000009Z.globals.sql.age").write_text("half a set")
    (folder / ".tmp.dead").mkdir()
    (folder / ".tmp.dead" / "soc.dump").write_text(PLAIN)
    assert run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(2)).returncode == 0
    assert sets(tmp_path) == [f"soc-{stamp(1)}", f"soc-{stamp(2)}"]
    assert sorted(p.name for p in folder.iterdir()) == sorted(
        f"soc-{stamp(n)}.{ext}" for n in (1, 2) for ext in ("dump.age", "globals.sql.age", "sha256")
    )


@not_root
def test_a_second_run_while_one_is_running_is_refused(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    lock = tmp_path / "backups" / ".lock"
    lock.mkdir(parents=True)
    (lock / "pid").write_text(str(os.getpid()))  # a live process
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1))
    assert r.returncode == 1 and "reason=another_backup_is_running" in r.stderr
    assert lock.is_dir()  # not the other run's to remove
    assert sets(tmp_path) == []


@not_root
def test_a_lock_left_by_a_dead_run_is_taken_over(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    dead = subprocess.Popen(["true"])  # noqa: S607
    dead.wait()
    lock = tmp_path / "backups" / ".lock"
    lock.mkdir(parents=True)
    (lock / "pid").write_text(str(dead.pid))
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1))
    assert r.returncode == 0, r.stderr
    assert not lock.exists()


# ---- backup.sh with the real age ----


@not_root
def test_the_real_age_round_trip(tmp_path: Path, stubs: Path) -> None:
    if not (Path("/usr/bin/age").exists() and Path("/usr/bin/age-keygen").exists()):
        # CI installs age and sets this, so the one test of the real tool can't skip there
        if os.environ.get("SOC_REQUIRE_AGE"):
            pytest.fail("SOC_REQUIRE_AGE is set but age is not installed")
        pytest.skip("age is not installed")
    pair = subprocess.run(  # noqa: S603
        ["/usr/bin/age-keygen"], capture_output=True, text=True, check=True
    )
    ident = tmp_path / "id.txt"
    ident.write_text(pair.stdout)
    pub = subprocess.run(  # noqa: S603
        ["/usr/bin/age-keygen", "-y", str(ident)], capture_output=True, text=True, check=True
    ).stdout.strip()
    host(tmp_path)
    (tmp_path / "env" / "backup-age.pub").write_text(pub + "\n")
    r = run_backup(tmp_path, stubs, SOC_BACKUP_NOW=stamp(1), SOC_BACKUP_AGE="/usr/bin/age")
    assert r.returncode == 0, r.stderr
    out = subprocess.run(  # noqa: S603
        [
            "/usr/bin/age",
            "-d",
            "-i",
            str(ident),
            str(tmp_path / "backups" / f"soc-{stamp(1)}.dump.age"),
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert out.strip() == PLAIN
    assert PLAIN not in (tmp_path / "backups" / f"soc-{stamp(1)}.dump.age").read_text("latin-1")


# ---- init-backup.sh ----


def run_init(
    state: Path, stubs: Path | None, *args: str, **env: str
) -> subprocess.CompletedProcess[str]:
    path = f"{stubs}:/usr/bin:/bin" if stubs else "/usr/bin:/bin"
    full = {"PATH": "/usr/bin:/bin", "SOC_STATE_DIR": str(state), "SOC_INIT_TEST": "1"}
    full["SOC_TEST_PATH"] = path
    full.update(env)
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(INIT), *args], env=full, capture_output=True, text=True, timeout=30
    )


@not_root
def test_init_writes_only_the_public_key_and_shows_the_private_one_once(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path, key=False)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    r = run_init(tmp_path, stubs, TMPDIR=str(scratch))
    assert r.returncode == 0, r.stderr
    f = tmp_path / "env" / "backup-age.pub"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert f.read_text() == PUB + "\n"
    assert r.stdout.count("AGE-SECRET-KEY-1") == 2  # the label line and the value
    assert f"SOC_BACKUP_AGE_KEY={SECRET}" in r.stdout
    assert f"SOC_BACKUP_AGE_PUB={PUB}" in r.stdout
    assert "AGE-SECRET-KEY-1" not in r.stderr
    for p in list(tmp_path.rglob("*")) + list(scratch.rglob("*")):
        if p.is_file() and p.parent.name != "stubs":
            assert b"AGE-SECRET-KEY" not in p.read_bytes(), p  # never on disk
    assert not [p for p in (tmp_path / "env").iterdir() if p.name.startswith(".init")]


@not_root
def test_init_never_overwrites_the_key(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    before = (tmp_path / "env" / "backup-age.pub").read_text()
    r = run_init(tmp_path, stubs)
    assert r.returncode == 1 and "never overwrites" in r.stderr
    assert (tmp_path / "env" / "backup-age.pub").read_text() == before
    assert "AGE-SECRET-KEY" not in r.stdout + r.stderr


@not_root
def test_init_needs_the_other_secrets_to_exist_first(tmp_path: Path, stubs: Path) -> None:
    (tmp_path / "env").mkdir()
    r = run_init(tmp_path, stubs)
    assert r.returncode == 1 and "init-secrets.sh first" in r.stderr
    assert files(tmp_path) == {"env"}


@not_root
def test_init_without_age_creates_nothing(tmp_path: Path) -> None:
    host(tmp_path, key=False)
    r = run_init(tmp_path, None)
    assert r.returncode == 1 and "apt install age" in r.stderr
    assert files(tmp_path) == {"env", "env/db-owner.env"}


@not_root
def test_init_with_a_failing_keygen_creates_nothing(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path, key=False)
    r = run_init(tmp_path, stubs, STUB_KEYGEN_FAIL="1")
    assert r.returncode == 1
    assert files(tmp_path) == {"env", "env/db-owner.env"}


@not_root
def test_init_restore_rebuilds_the_file_and_prints_nothing_secret(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path, key=False)
    r = run_init(tmp_path, stubs, "--restore", SOC_BACKUP_AGE_PUB=PUB)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "env" / "backup-age.pub").read_text() == PUB + "\n"
    assert PUB not in r.stdout and "SECRET" not in r.stdout


@pytest.mark.parametrize("value", ["", "nonsense", SECRET])
@not_root
def test_init_restore_rejects_anything_but_a_public_key(
    tmp_path: Path, stubs: Path, value: str
) -> None:
    host(tmp_path, key=False)
    r = run_init(tmp_path, stubs, "--restore", SOC_BACKUP_AGE_PUB=value)
    assert r.returncode == 1
    assert not (tmp_path / "env" / "backup-age.pub").exists()
    assert SECRET not in r.stdout + r.stderr


@not_root
def test_init_rejects_other_arguments(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path, key=False)
    assert run_init(tmp_path, stubs, "--force").returncode == 1


# ---- the timer ----


def test_the_service_runs_the_script_in_the_repo() -> None:
    text = (DEPLOY / "systemd" / "soc-backup.service").read_text()
    exec_line = next(x for x in text.splitlines() if x.startswith("ExecStart="))
    assert exec_line == "ExecStart=/opt/soc-platform/deploy/backup.sh"
    assert "Type=oneshot" in text and "NoNewPrivileges=yes" in text


def test_the_timer_runs_every_six_hours_and_never_in_the_hosts_backup_window() -> None:
    text = (DEPLOY / "systemd" / "soc-backup.timer").read_text()
    assert "Persistent=true" in text  # a missed run (host off) is made up at boot
    cal = next(x for x in text.splitlines() if x.startswith("OnCalendar="))
    parts = cal.split()
    hours = parts[1].split(":")[0].split(",")
    assert [int(h) for h in hours] == [0, 6, 12, 18]
    # the host's container backup starts at 02:00 and froze CT 110 until about 03:30, in the
    # PVE host's zone: without the same zone here, 06:17 UTC is 02:17 in summer time
    assert parts[-1] == "America/New_York"
    assert not any(2 <= int(h) <= 3 for h in hours)
