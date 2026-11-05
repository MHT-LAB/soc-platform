"""deploy/offsite.sh, deploy/init-offsite.sh and the compose service and unit they use.

The scripts run for real. The container runtime is replaced by a small stub (SOC_INIT_TEST is
the only way to swap it in, and it is refused for root), so what is checked is the script's
own behaviour: what it refuses, what it leaves behind, what it never prints and never puts in
a command. Two tests run the real `restic` against a local repository where it is installed
(CI installs it and sets SOC_REQUIRE_RESTIC=1, so they cannot skip there)."""

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
OFFSITE = DEPLOY / "offsite.sh"
INIT = DEPLOY / "init-offsite.sh"
BASH = shutil.which("bash") or "/bin/bash"

REPO = "s3:https://s3.us-east-005.backblazeb2.com/soc-offsite-test/ct110"
KEY_ID = "005abcdef0123456789abcdef"
APP_KEY = "K005AppKeyAppKeyAppKeyAppKey/+Q9"
PASSWORD = "ab12" * 16
SET = "soc-20261104T061700Z"
SECRETS = (APP_KEY, PASSWORD)

not_root = pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user")

COMPOSE_STUB = r"""#!/bin/bash
# stands in for soc-compose.sh. Every call, and the environment it was given, is recorded.
log() { [[ -z "${STUB_LOG:-}" ]] || echo "$*" >> "$STUB_LOG"; }
[[ -z "${STUB_ENV_LOG:-}" ]] || env >> "$STUB_ENV_LOG"
[[ -z "${STUB_LOCK_LOG:-}" ]] || {
  if [[ -d "$SOC_STATE_DIR/backups/.lock" ]]; then echo held >> "$STUB_LOCK_LOG"
  else echo free >> "$STUB_LOCK_LOG"; fi
}
log "compose $*"
[[ "$1 $2 $3 $4 $5" == "run --rm -T --no-deps offsite" ]] || exit 99
shift 5
cmd="$1"; shift
created="$SOC_STATE_DIR/stubs/repo-created"
case "$cmd" in
  cat)
    [[ -z "${STUB_REPO_MISSING:-}" || -e "$created" ]] || exit 10 ;;
  init)
    [[ -z "${STUB_INIT_FAIL:-}" ]] || exit 1
    touch "$created" ;;
  backup)
    [[ -z "${STUB_BACKUP_FAIL:-}" ]] || exit "${STUB_BACKUP_RC:-1}"
    echo '{"message_type":"status","percent_done":0.5}'
    [[ -n "${STUB_NO_SNAPSHOT_ID:-}" ]] || \
      echo '{"message_type":"summary","files_new":3,"data_added":4321,"snapshot_id":"5a7b9c1d"}' ;;
  snapshots)
    [[ -z "${STUB_VERIFY_FAIL:-}" ]] || exit 1
    if [[ -n "${STUB_VERIFY_EMPTY:-}" ]]; then echo '[]'; else
      echo '[{"id":"5a7b9c1de2f3a4b5c6d7e8f9","short_id":"5a7b9c1d"}]'
    fi ;;
  *) exit 98 ;;
esac
"""


def write_exe(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


@pytest.fixture
def stubs(tmp_path: Path) -> Path:
    d = tmp_path / "stubs"
    d.mkdir()
    write_exe(d / "soc-compose.sh", COMPOSE_STUB)
    return d


def host(
    state: Path,
    *,
    env_text: str | None = None,
    mode: int = 0o600,
    sets: bool = True,
) -> Path:
    env = state / "env"
    env.mkdir(parents=True, exist_ok=True)
    (env / "db-owner.env").write_text("SOC_MIGRATE_URL=x\n")
    if env_text is None:
        env_text = (
            f"RESTIC_REPOSITORY={REPO}\nRESTIC_PASSWORD={PASSWORD}\n"
            f"AWS_ACCESS_KEY_ID={KEY_ID}\nAWS_SECRET_ACCESS_KEY={APP_KEY}\n"
        )
    f = env / "offsite.env"
    f.write_text(env_text)
    f.chmod(mode)
    if sets:
        make_set(state / "backups")
    return state


def make_set(folder: Path, name: str = SET, *, sums: bool = True) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.dump.age").write_text("age-encryption.org/v1\nciphertext-dump\n")
    (folder / f"{name}.globals.sql.age").write_text("age-encryption.org/v1\nciphertext-roles\n")
    if sums:
        (folder / f"{name}.sha256").write_text(f"{'0' * 64}  {name}.dump.age\n")


def run_offsite(
    state: Path, stubs: Path, *args: str, test_mode: bool = True, **env: Any
) -> subprocess.CompletedProcess[str]:
    full = {"PATH": "/usr/bin:/bin", "SOC_STATE_DIR": str(state)}
    if test_mode:
        full.update(SOC_INIT_TEST="1", SOC_COMPOSE=str(stubs / "soc-compose.sh"))
    full.update(env)
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(OFFSITE), *args], env=full, capture_output=True, text=True, timeout=60
    )


def calls(log: Path) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


def restic_calls(log: Path) -> list[str]:
    return [c.removeprefix("compose run --rm -T --no-deps offsite ") for c in calls(log)]


def no_leftovers(state: Path) -> None:
    assert [p.name for p in state.iterdir() if p.name.startswith(".offsite.")] == []
    assert not (state / "backups" / ".lock").exists()


def refused(
    tmp_path: Path, stubs: Path, expect: str, *args: str, **env: Any
) -> subprocess.CompletedProcess[str]:
    log = tmp_path / "calls.log"
    r = run_offsite(tmp_path, stubs, *args, STUB_LOG=str(log), **env)
    assert r.returncode != 0, r.stdout
    assert expect in r.stderr, r.stderr
    assert r.stdout == ""
    no_leftovers(tmp_path)
    for secret in SECRETS:
        assert secret not in r.stderr
    return r


# ---- the good run ----


@not_root
def test_a_good_run_checks_sends_and_checks_again_in_one_line(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    log = tmp_path / "calls.log"
    r = run_offsite(tmp_path, stubs, STUB_LOG=str(log))
    assert r.returncode == 0, r.stderr
    assert r.stdout == "offsite outcome=ok snapshot=5a7b9c1d added_bytes=4321\n"
    assert r.stderr == ""
    steps = [c.split()[0] for c in restic_calls(log)]
    assert steps == ["cat", "backup", "snapshots"]
    no_leftovers(tmp_path)


@not_root
def test_restic_is_asked_for_exactly_what_the_design_says(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    log = tmp_path / "calls.log"
    assert run_offsite(tmp_path, stubs, STUB_LOG=str(log)).returncode == 0
    cat, backup, snap = restic_calls(log)
    # the folder is read through the read-only mount, never the host's path
    assert backup.split()[:2] == ["backup", "/backups"]
    # the read-only steps take no restic lock. `restic backup` always takes one (it ignores
    # --no-lock), so the flag is not passed there: it would only claim what does not happen
    for c in (cat, snap):
        assert "--no-lock" in c.split()
    assert "--no-lock" not in backup.split()
    # the lock file and half-written sets are not sent
    assert "--exclude .lock" in backup and "--exclude .tmp.*" in backup
    assert "--tag soc-backup" in backup
    # the snapshot it checks is the one it just made
    assert snap.endswith("5a7b9c1d")
    assert not any(w in " ".join(restic_calls(log)) for w in ("forget", "prune", "unlock", "rm "))


@not_root
def test_no_secret_reaches_a_command_the_environment_or_the_output(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    log, envlog = tmp_path / "calls.log", tmp_path / "env.log"
    r = run_offsite(tmp_path, stubs, STUB_LOG=str(log), STUB_ENV_LOG=str(envlog))
    assert r.returncode == 0
    for secret in (*SECRETS, KEY_ID, REPO):
        assert secret not in r.stdout + r.stderr
        assert secret not in log.read_text()  # not in any argument
        assert secret not in envlog.read_text()  # not in the environment the stub saw
    # the key file is read by the container through compose's env_file, not by the script
    assert "RESTIC_PASSWORD" not in envlog.read_text()


@not_root
def test_the_lock_is_held_while_restic_runs_and_released_after(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    held = tmp_path / "lock.log"
    r = run_offsite(tmp_path, stubs, STUB_LOCK_LOG=str(held))
    assert r.returncode == 0
    assert set(held.read_text().split()) == {"held"}
    no_leftovers(tmp_path)


@not_root
def test_the_local_sets_are_never_touched(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    before = {p.name: p.read_bytes() for p in (tmp_path / "backups").iterdir()}
    for env in ({}, {"STUB_BACKUP_FAIL": "1"}, {"STUB_VERIFY_FAIL": "1"}):
        run_offsite(tmp_path, stubs, **env)
        assert {p.name: p.read_bytes() for p in (tmp_path / "backups").iterdir()} == before


# ---- refusals before anything is sent ----


@not_root
def test_a_missing_key_file_is_refused(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    (tmp_path / "env" / "offsite.env").unlink()
    refused(tmp_path, stubs, "step=config reason=missing_env/offsite.env")


@not_root
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_a_key_file_others_can_read_is_refused(tmp_path: Path, stubs: Path, mode: int) -> None:
    host(tmp_path, mode=mode)
    r = refused(tmp_path, stubs, "reason=env/offsite.env_is_readable_by_others")
    assert not (tmp_path / "calls.log").exists()
    assert r.returncode == 1


@not_root
@pytest.mark.parametrize(
    ("text", "reason"),
    [
        # the repository must be a Backblaze address: a typo can't send backups elsewhere
        (
            f"RESTIC_REPOSITORY=s3:https://s3.example.com/soc-offsite-test\nRESTIC_PASSWORD={PASSWORD}\n"
            f"AWS_ACCESS_KEY_ID={KEY_ID}\nAWS_SECRET_ACCESS_KEY={APP_KEY}\n",
            "RESTIC_REPOSITORY_is_not_a_b2_s3_address",
        ),
        (
            f"RESTIC_REPOSITORY=s3:https://s3.us-east-005.backblazeb2.com.evil.net/soc-offsite-test\n"
            f"RESTIC_PASSWORD={PASSWORD}\nAWS_ACCESS_KEY_ID={KEY_ID}\n"
            f"AWS_SECRET_ACCESS_KEY={APP_KEY}\n",
            "RESTIC_REPOSITORY_is_not_a_b2_s3_address",
        ),
        (
            f"RESTIC_REPOSITORY=s3:http://s3.us-east-005.backblazeb2.com/soc-offsite-test\n"
            f"RESTIC_PASSWORD={PASSWORD}\nAWS_ACCESS_KEY_ID={KEY_ID}\n"
            f"AWS_SECRET_ACCESS_KEY={APP_KEY}\n",
            "RESTIC_REPOSITORY_is_not_a_b2_s3_address",
        ),
        (
            f"RESTIC_REPOSITORY={REPO}\nRESTIC_PASSWORD=short\n"
            f"AWS_ACCESS_KEY_ID={KEY_ID}\nAWS_SECRET_ACCESS_KEY={APP_KEY}\n",
            "RESTIC_PASSWORD_is_not_32-128_hex_characters",
        ),
        (
            f"RESTIC_REPOSITORY={REPO}\nRESTIC_PASSWORD={PASSWORD}\n"
            f"AWS_ACCESS_KEY_ID=bad id\nAWS_SECRET_ACCESS_KEY={APP_KEY}\n",
            "AWS_ACCESS_KEY_ID_has_the_wrong_shape",
        ),
        # a $ would be expanded by compose when it reads the file
        (
            f"RESTIC_REPOSITORY={REPO}\nRESTIC_PASSWORD={PASSWORD}\n"
            f"AWS_ACCESS_KEY_ID={KEY_ID}\nAWS_SECRET_ACCESS_KEY=abcdefghij$HOME" + "k" * 10 + "\n",
            "AWS_SECRET_ACCESS_KEY_has_the_wrong_shape",
        ),
        (
            f"RESTIC_REPOSITORY={REPO}\nRESTIC_PASSWORD={PASSWORD}\n"
            f"AWS_ACCESS_KEY_ID={KEY_ID}\nAWS_SECRET_ACCESS_KEY={APP_KEY}\nRESTIC_PACK_SIZE=1\n",
            "env/offsite.env_has_a_line_this_does_not_understand",
        ),
        (
            f"RESTIC_REPOSITORY={REPO}\nRESTIC_PASSWORD={PASSWORD}\nAWS_ACCESS_KEY_ID={KEY_ID}\n",
            "env/offsite.env_must_have_exactly_four_lines",
        ),
        (
            f"RESTIC_REPOSITORY={REPO}\nRESTIC_REPOSITORY={REPO}\nRESTIC_PASSWORD={PASSWORD}\n"
            f"AWS_ACCESS_KEY_ID={KEY_ID}\n",
            "env/offsite.env_repeats_a_line",
        ),
        ("just some words\n", "env/offsite.env_has_a_line_this_does_not_understand"),
    ],
)
def test_a_key_file_of_the_wrong_shape_is_refused_without_echoing_it(
    tmp_path: Path, stubs: Path, text: str, reason: str
) -> None:
    host(tmp_path, env_text=text)
    refused(tmp_path, stubs, f"step=config reason={reason}")
    assert not (tmp_path / "calls.log").exists()  # nothing was started


@not_root
def test_with_no_complete_set_nothing_is_sent(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path, sets=False)
    make_set(tmp_path / "backups", sums=False)  # a set whose checksum was never written
    refused(tmp_path, stubs, "step=set reason=no_complete_backup_set_to_send")
    assert not (tmp_path / "calls.log").exists()


@not_root
def test_a_set_missing_a_file_is_not_complete(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    (tmp_path / "backups" / f"{SET}.globals.sql.age").unlink()
    refused(tmp_path, stubs, "reason=no_complete_backup_set_to_send")


@not_root
def test_a_run_while_a_backup_holds_the_lock_is_refused_and_leaves_the_lock(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    lock = tmp_path / "backups" / ".lock"
    lock.mkdir()
    holder = subprocess.Popen(["/bin/sleep", "30"])  # noqa: S603 - a live process to be "the backup"
    try:
        (lock / "pid").write_text(str(holder.pid))
        r = run_offsite(tmp_path, stubs, STUB_LOG=str(tmp_path / "calls.log"))
        assert r.returncode != 0 and "reason=a_backup_or_restore_is_running" in r.stderr
        assert lock.is_dir()  # not the other run's lock to remove
        assert not (tmp_path / "calls.log").exists()
    finally:
        holder.kill()
        holder.wait()


@not_root
def test_a_lock_left_by_a_dead_run_is_taken_over(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    lock = tmp_path / "backups" / ".lock"
    lock.mkdir()
    (lock / "pid").write_text("999999")
    assert run_offsite(tmp_path, stubs).returncode == 0
    no_leftovers(tmp_path)


@not_root
@pytest.mark.parametrize("args", [("--force",), ("--init", "x"), ("send",)])
def test_unknown_arguments_are_refused(tmp_path: Path, stubs: Path, args: tuple[str, ...]) -> None:
    host(tmp_path)
    refused(tmp_path, stubs, "reason=usage_offsite.sh", *args)
    assert not (tmp_path / "calls.log").exists()


def test_it_refuses_to_run_as_a_normal_user_without_the_test_switch(
    tmp_path: Path, stubs: Path
) -> None:
    if os.geteuid() == 0:
        pytest.skip("root runs it for real")
    host(tmp_path)
    r = run_offsite(tmp_path, stubs, test_mode=False)
    assert r.returncode == 1 and "reason=run_as_root" in r.stderr


# ---- failures part-way ----


@not_root
def test_a_repository_that_cannot_be_opened_is_reported_and_nothing_is_sent(
    tmp_path: Path, stubs: Path
) -> None:
    host(tmp_path)
    log = tmp_path / "calls.log"
    r = refused(
        tmp_path, stubs, "step=repository reason=cannot_open_the_repository", STUB_REPO_MISSING="1"
    )
    assert r.returncode == 1
    assert [c.split()[0] for c in restic_calls(log)] == ["cat"]  # no backup, no init


@not_root
@pytest.mark.parametrize("rc", ["1", "3", "11"])
def test_a_failed_upload_fails_the_run_with_the_exit_code(
    tmp_path: Path, stubs: Path, rc: str
) -> None:
    host(tmp_path)
    refused(
        tmp_path,
        stubs,
        f"step=backup reason=restic_backup_failed_exit_{rc}",
        STUB_BACKUP_FAIL="1",
        STUB_BACKUP_RC=rc,
    )


@not_root
def test_a_backup_that_names_no_snapshot_is_not_a_success(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    log = tmp_path / "calls.log"
    refused(
        tmp_path, stubs, "step=backup reason=restic_reported_no_snapshot", STUB_NO_SNAPSHOT_ID="1"
    )
    assert "snapshots" not in [c.split()[0] for c in restic_calls(log)]


@not_root
@pytest.mark.parametrize("env", [{"STUB_VERIFY_FAIL": "1"}, {"STUB_VERIFY_EMPTY": "1"}])
def test_a_snapshot_the_repository_does_not_return_is_not_a_success(
    tmp_path: Path, stubs: Path, env: dict[str, str]
) -> None:
    host(tmp_path)
    refused(tmp_path, stubs, "step=verify reason=the_repository_did_not_return_the_snapshot", **env)


# ---- --init ----


@not_root
def test_init_creates_an_empty_repository_once(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    log = tmp_path / "calls.log"
    env = {"STUB_REPO_MISSING": "1", "STUB_LOG": str(log)}
    r = run_offsite(tmp_path, stubs, "--init", **env)
    assert r.returncode == 0, r.stderr
    assert r.stdout == "offsite outcome=ok init=created\n"
    assert [c.split()[0] for c in restic_calls(log)] == ["cat", "init"]  # nothing is sent
    again = run_offsite(tmp_path, stubs, "--init", **env)
    assert again.returncode == 1
    assert "reason=repository_already_exists_nothing_changed" in again.stderr
    assert [c.split()[0] for c in restic_calls(log)].count("init") == 1
    no_leftovers(tmp_path)


@not_root
def test_init_works_before_the_first_backup_exists(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path, sets=False)
    r = run_offsite(tmp_path, stubs, "--init", STUB_REPO_MISSING="1")
    assert r.returncode == 0, r.stderr


@not_root
def test_a_repository_that_cannot_be_created_is_reported(tmp_path: Path, stubs: Path) -> None:
    host(tmp_path)
    refused(
        tmp_path,
        stubs,
        "step=init reason=could_not_create_the_repository",
        "--init",
        STUB_REPO_MISSING="1",
        STUB_INIT_FAIL="1",
    )


# ---- init-offsite.sh ----


def run_init(
    state: Path, *args: str, key: str | None = APP_KEY, **env: str | None
) -> subprocess.CompletedProcess[str]:
    full = {"PATH": "/usr/bin:/bin", "SOC_STATE_DIR": str(state), "SOC_INIT_TEST": "1"}
    full.update(
        {"SOC_OFFSITE_REPOSITORY": REPO, "SOC_OFFSITE_KEY_ID": KEY_ID}
        | {k: v for k, v in env.items() if v is not None}
    )
    for k, v in env.items():
        if v is None:
            full.pop(k, None)
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(INIT), *args],
        env=full,
        input=(key + "\n") if key is not None else "",
        capture_output=True,
        text=True,
        timeout=60,
    )


def init_host(state: Path) -> Path:
    (state / "env").mkdir(parents=True, exist_ok=True)
    (state / "env" / "db-owner.env").write_text("SOC_MIGRATE_URL=x\n")
    return state / "env" / "offsite.env"


@not_root
def test_init_writes_the_key_file_and_prints_only_the_password(tmp_path: Path) -> None:
    f = init_host(tmp_path)
    r = run_init(tmp_path)
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    lines = dict(x.split("=", 1) for x in f.read_text().splitlines())
    assert list(lines) == [
        "RESTIC_REPOSITORY",
        "RESTIC_PASSWORD",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    ]
    assert lines["RESTIC_REPOSITORY"] == REPO and lines["AWS_ACCESS_KEY_ID"] == KEY_ID
    assert lines["AWS_SECRET_ACCESS_KEY"] == APP_KEY
    password = lines["RESTIC_PASSWORD"]
    assert len(password) == 64 and set(password) <= set("0123456789abcdef")
    # shown once; the typed key is not echoed back
    assert f"SOC_OFFSITE_PASSWORD={password}" in r.stdout
    assert APP_KEY not in r.stdout + r.stderr
    # and what it wrote is exactly what offsite.sh accepts
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".")] == []
    assert [p.name for p in (tmp_path / "env").iterdir() if p.name.startswith(".")] == []


@not_root
def test_two_runs_make_different_passwords(tmp_path: Path) -> None:
    f = init_host(tmp_path)
    run_init(tmp_path)
    first = f.read_text()
    f.unlink()
    run_init(tmp_path)
    assert f.read_text() != first


@not_root
def test_init_never_overwrites(tmp_path: Path) -> None:
    f = init_host(tmp_path)
    f.write_text("keep me\n")
    r = run_init(tmp_path)
    assert r.returncode == 1 and "already exists" in r.stderr
    assert f.read_text() == "keep me\n"


@not_root
@pytest.mark.parametrize(
    "env",
    [
        {"SOC_OFFSITE_REPOSITORY": None},
        {"SOC_OFFSITE_REPOSITORY": "s3:https://evil.example.com/bucket"},
        {"SOC_OFFSITE_KEY_ID": None},
        {"SOC_OFFSITE_KEY_ID": "has spaces"},
    ],
)
def test_init_refuses_a_bad_address_or_key_id_before_asking_for_the_key(
    tmp_path: Path, env: dict[str, str | None]
) -> None:
    f = init_host(tmp_path)
    r = run_init(tmp_path, **env)
    assert r.returncode == 1 and r.stdout == ""
    assert not f.exists()


@not_root
@pytest.mark.parametrize("key", ["", "short", "has spaces in it 0123456789", "a" * 30 + "$HOME"])
def test_init_refuses_a_bad_application_key(tmp_path: Path, key: str) -> None:
    f = init_host(tmp_path)
    r = run_init(tmp_path, key=key)
    assert r.returncode == 1 and not f.exists()
    assert "that is not an application key" in r.stderr
    assert key not in r.stderr or key == ""


@not_root
def test_init_needs_the_database_secrets_first(tmp_path: Path) -> None:
    r = run_init(tmp_path)
    assert r.returncode == 1 and "run init-secrets.sh first" in r.stderr


@not_root
def test_restore_rebuilds_the_same_file_from_the_environment_and_prints_nothing_secret(
    tmp_path: Path,
) -> None:
    f = init_host(tmp_path)
    r = run_init(
        tmp_path, "--restore", key=None, SOC_OFFSITE_APP_KEY=APP_KEY, SOC_OFFSITE_PASSWORD=PASSWORD
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == f"restored {f} from the environment\n"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert f.read_text() == (
        f"RESTIC_REPOSITORY={REPO}\nRESTIC_PASSWORD={PASSWORD}\n"
        f"AWS_ACCESS_KEY_ID={KEY_ID}\nAWS_SECRET_ACCESS_KEY={APP_KEY}\n"
    )


@not_root
@pytest.mark.parametrize(
    "env",
    [
        {"SOC_OFFSITE_APP_KEY": None, "SOC_OFFSITE_PASSWORD": PASSWORD},
        {"SOC_OFFSITE_APP_KEY": APP_KEY, "SOC_OFFSITE_PASSWORD": None},
        {"SOC_OFFSITE_APP_KEY": APP_KEY, "SOC_OFFSITE_PASSWORD": "nothex"},
    ],
)
def test_restore_needs_all_four_values(tmp_path: Path, env: dict[str, str | None]) -> None:
    f = init_host(tmp_path)
    r = run_init(tmp_path, "--restore", key=None, **env)
    assert r.returncode == 1 and not f.exists()


@not_root
def test_a_file_made_by_init_passes_the_script_s_own_checks(tmp_path: Path, stubs: Path) -> None:
    init_host(tmp_path)
    assert run_init(tmp_path).returncode == 0
    make_set(tmp_path / "backups")
    r = run_offsite(tmp_path, stubs)
    assert r.returncode == 0, r.stderr


# ---- the compose service and the units ----

COMPOSE: dict[str, Any] = yaml.safe_load((DEPLOY / "compose.yml").read_text())
SERVICE = COMPOSE["services"]["offsite"]


def test_the_service_is_on_egress_only_and_publishes_nothing() -> None:
    assert SERVICE["networks"] == ["egress"]  # no database network, not the tunnel's
    assert "ports" not in SERVICE and "expose" not in SERVICE
    assert SERVICE.get("network_mode") is None


def test_the_service_sees_the_backup_folder_read_only_and_nothing_else() -> None:
    assert SERVICE["volumes"] == ["${SOC_STATE_DIR:-/srv/soc}/backups:/backups:ro"]


def test_the_service_holds_only_the_repository_key_file() -> None:
    assert [e["path"] for e in SERVICE["env_file"]] == [
        "${SOC_STATE_DIR:-/srv/soc}/env/offsite.env"
    ]
    assert "environment" not in SERVICE


def test_the_service_is_started_only_by_name_and_is_hardened() -> None:
    assert SERVICE["profiles"] == ["offsite"] and SERVICE["restart"] == "no"
    assert SERVICE["read_only"] is True and SERVICE["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in SERVICE["security_opt"]
    assert "mem_limit" in SERVICE and "pids_limit" in SERVICE
    assert SERVICE["entrypoint"] == ["/usr/bin/restic"]
    assert "@sha256:" in SERVICE["image"]


def test_soc_compose_does_not_turn_the_service_on() -> None:
    text = (DEPLOY / "soc-compose.sh").read_text()
    assert "offsite" not in text  # `up -d` must never start it


def test_the_offsite_unit_runs_the_script_and_skips_quietly_without_a_key_file() -> None:
    text = (DEPLOY / "systemd" / "soc-offsite.service").read_text()
    exec_line = next(x for x in text.splitlines() if x.startswith("ExecStart="))
    assert exec_line == "ExecStart=/opt/soc-platform/deploy/offsite.sh"
    assert "Type=oneshot" in text and "NoNewPrivileges=yes" in text
    assert "ConditionPathExists=/srv/soc/env/offsite.env" in text


def test_a_finished_backup_starts_the_offsite_unit_but_a_failed_one_does_not() -> None:
    text = (DEPLOY / "systemd" / "soc-backup.service").read_text()
    assert "OnSuccess=soc-offsite.service" in text
    assert "OnFailure" not in text


# ---- the real restic ----

RESTIC = shutil.which("restic") or (
    str(Path.home() / "bin" / "restic") if (Path.home() / "bin" / "restic").exists() else None
)

REAL_STUB = r"""#!/bin/bash
# stands in for soc-compose.sh, but runs the real restic against a local repository.
# run --rm -T --no-deps offsite <restic args>; the container's /backups is the real folder.
shift 5
args=()
for a in "$@"; do
  if [[ "$a" == "/backups" ]]; then args+=("$SOC_STATE_DIR/backups"); else args+=("$a"); fi
done
export RESTIC_REPOSITORY="$REAL_REPO" RESTIC_PASSWORD="$REAL_PASSWORD"
exec "$REAL_RESTIC" "${args[@]}"
"""


@pytest.fixture
def real_restic(tmp_path: Path, stubs: Path) -> dict[str, str]:
    if RESTIC is None:
        if os.environ.get("SOC_REQUIRE_RESTIC"):
            pytest.fail("SOC_REQUIRE_RESTIC is set but restic is not installed")
        pytest.skip("restic is not installed")
    write_exe(stubs / "soc-compose.sh", REAL_STUB)
    return {
        "REAL_RESTIC": RESTIC,
        "REAL_REPO": str(tmp_path / "repo"),
        "REAL_PASSWORD": PASSWORD,
        "HOME": str(tmp_path / "home"),
    }


def restic_out(env: dict[str, str], *args: str) -> str:
    full = {"PATH": "/usr/bin:/bin", "RESTIC_REPOSITORY": env["REAL_REPO"]}
    full |= {"RESTIC_PASSWORD": env["REAL_PASSWORD"], "HOME": env["HOME"]}
    r = subprocess.run(  # noqa: S603 - the real restic, fixed arguments
        [env["REAL_RESTIC"], *args, "--no-cache"], env=full, capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr
    return r.stdout


@not_root
def test_real_restic_creates_sends_checks_and_sends_only_what_is_new(
    tmp_path: Path, stubs: Path, real_restic: dict[str, str]
) -> None:
    host(tmp_path)
    (tmp_path / "backups" / ".tmp.abc").mkdir()
    (tmp_path / "backups" / ".tmp.abc" / "soc.dump").write_text("PLAIN-DUMP-MUST-NOT-LEAVE")
    r = run_offsite(tmp_path, stubs, "--init", **real_restic)
    assert r.returncode == 0, r.stderr
    first = run_offsite(tmp_path, stubs, **real_restic)
    assert first.returncode == 0, first.stderr
    assert first.stdout.startswith("offsite outcome=ok snapshot=")
    assert int(first.stdout.split("added_bytes=")[1]) > 0
    listing = restic_out(real_restic, "ls", "latest")
    for name in (f"{SET}.dump.age", f"{SET}.globals.sql.age", f"{SET}.sha256"):
        assert name in listing
    assert ".lock" not in listing and ".tmp." not in listing and "soc.dump\n" not in listing
    # a second run with nothing new adds (almost) nothing and makes another snapshot
    second = run_offsite(tmp_path, stubs, **real_restic)
    assert second.returncode == 0, second.stderr
    assert int(second.stdout.split("added_bytes=")[1]) < int(first.stdout.split("added_bytes=")[1])
    snaps = json.loads(restic_out(real_restic, "snapshots", "--json"))
    assert len(snaps) == 2 and all(s["tags"] == ["soc-backup"] for s in snaps)
    no_leftovers(tmp_path)


@not_root
def test_real_restic_gets_the_sets_back_byte_for_byte(
    tmp_path: Path, stubs: Path, real_restic: dict[str, str]
) -> None:
    host(tmp_path)
    assert run_offsite(tmp_path, stubs, "--init", **real_restic).returncode == 0
    assert run_offsite(tmp_path, stubs, **real_restic).returncode == 0
    out = tmp_path / "restored"
    restic_out(real_restic, "restore", "latest", "--target", str(out))
    found = {p.name: p.read_bytes() for p in out.rglob("soc-*") if p.is_file()}
    want = {
        p.name: p.read_bytes()
        for p in (tmp_path / "backups").iterdir()
        if p.name.startswith("soc-")
    }
    assert found == want and len(found) == 3


@not_root
def test_real_restic_with_the_wrong_password_sends_nothing(
    tmp_path: Path, stubs: Path, real_restic: dict[str, str]
) -> None:
    host(tmp_path)
    assert run_offsite(tmp_path, stubs, "--init", **real_restic).returncode == 0
    wrong = dict(real_restic, REAL_PASSWORD="f" * 64)
    r = run_offsite(tmp_path, stubs, **wrong)
    assert r.returncode == 1 and "step=repository reason=cannot_open_the_repository" in r.stderr
    again = run_offsite(tmp_path, stubs, "--init", **wrong)
    assert again.returncode == 1
    assert "repository_already_exists" in again.stderr or "could_not_create" in again.stderr
    assert len(json.loads(restic_out(real_restic, "snapshots", "--json"))) == 0
