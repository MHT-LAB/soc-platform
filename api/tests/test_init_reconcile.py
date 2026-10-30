"""deploy/init-reconcile.sh: creates the catch-up worker's two database files, tells the
operator the value exactly once, never overwrites, and can rebuild the files from the secrets
manager's copy. These run the real script (SOC_INIT_TEST skips the root check, and is
refused for root)."""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

from soc_api.config import Settings
from soc_api.db import MIN_PASSWORD_LENGTH

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "init-reconcile.sh"
BASH = shutil.which("bash") or "/bin/bash"
FILES = ("env/reconcile-db.env", "env/reconcile-owner.env")
NAME = "SOC_DB_RECONCILE_PASSWORD"

not_root = pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user")


def host(tmp: Path) -> Path:
    """A host that already ran init-secrets.sh."""
    (tmp / "env").mkdir(parents=True, exist_ok=True)
    (tmp / "env" / "db-owner.env").write_text("SOC_MIGRATE_URL=x\n")
    return tmp


def run(
    state: Path, *args: str, test_mode: bool = True, **env: str
) -> subprocess.CompletedProcess[str]:
    full = {"PATH": "/usr/bin:/bin", "SOC_STATE_DIR": str(state), **env}
    if test_mode:
        full["SOC_INIT_TEST"] = "1"
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(SCRIPT), *args], env=full, capture_output=True, text=True, timeout=30
    )


def parse_env(path: Path) -> dict[str, str]:
    return {k: v for k, _, v in (line.partition("=") for line in path.read_text().splitlines())}


def printed(stdout: str) -> dict[str, str]:
    return {k: v for k, _, v in (line.partition("=") for line in stdout.splitlines()) if k == NAME}


def tree(state: Path) -> set[str]:
    return {str(p.relative_to(state)) for p in state.rglob("*")}


def test_the_script_is_executable() -> None:
    assert os.access(SCRIPT, os.X_OK)


@not_root
def test_a_run_creates_the_two_files_with_strict_modes_and_nothing_else(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(tmp_path)
    assert r.returncode == 0, r.stderr
    for f in FILES:
        assert stat.S_IMODE((tmp_path / f).stat().st_mode) == 0o600
    assert tree(tmp_path) == {"env", "env/db-owner.env", *FILES}


@not_root
def test_the_files_agree_and_the_app_accepts_them(tmp_path: Path) -> None:
    host(tmp_path)
    assert run(tmp_path).returncode == 0
    db_env = parse_env(tmp_path / "env/reconcile-db.env")
    owner = parse_env(tmp_path / "env/reconcile-owner.env")
    assert list(db_env) == ["SOC_RECONCILE_DATABASE_URL"]
    assert list(owner) == ["SOC_RECONCILE_DB_PASSWORD"]
    url = make_url(db_env["SOC_RECONCILE_DATABASE_URL"])
    assert url.username == "soc_reconcile"
    assert url.password == owner["SOC_RECONCILE_DB_PASSWORD"]
    # the catch-up worker runs on the database's own network
    assert (url.host, url.port, url.database) == ("db", 5432, "soc")
    assert len(owner["SOC_RECONCILE_DB_PASSWORD"]) >= MIN_PASSWORD_LENGTH
    assert re.fullmatch(r"[0-9a-f]{48}", owner["SOC_RECONCILE_DB_PASSWORD"])
    settings = Settings(reconcile_database_url=db_env["SOC_RECONCILE_DATABASE_URL"])
    assert (
        settings.reconcile_database_url.get_secret_value() == db_env["SOC_RECONCILE_DATABASE_URL"]
    )


@not_root
def test_the_printed_value_matches_the_files_and_warns(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(tmp_path)
    block = printed(r.stdout)
    assert set(block) == {NAME}
    assert (
        block[NAME] == parse_env(tmp_path / "env/reconcile-owner.env")["SOC_RECONCILE_DB_PASSWORD"]
    )
    assert "Do not paste" in r.stdout and "clear the terminal" in r.stdout
    assert r.stderr == ""


@not_root
def test_two_runs_never_produce_the_same_secret(tmp_path: Path) -> None:
    first = printed(run(host(tmp_path / "a")).stdout)[NAME]
    second = printed(run(host(tmp_path / "b")).stdout)[NAME]
    assert first != second


@not_root
def test_the_secret_is_written_nowhere_but_the_two_files(tmp_path: Path) -> None:
    host(tmp_path)
    value = printed(run(tmp_path).stdout)[NAME]
    allowed = {tmp_path / f for f in FILES}
    for path in tmp_path.rglob("*"):
        if path.is_file() and path not in allowed:
            assert value not in path.read_text(), path
    assert not (tmp_path / "deploy.log").exists()


@not_root
def test_it_needs_the_database_secrets_first(tmp_path: Path) -> None:
    (tmp_path / "env").mkdir()
    r = run(tmp_path)
    assert r.returncode == 1 and "run init-secrets.sh first" in r.stderr
    assert tree(tmp_path) == {"env"}


@not_root
@pytest.mark.parametrize("existing", FILES)
def test_it_never_overwrites_and_creates_nothing_else(tmp_path: Path, existing: str) -> None:
    host(tmp_path)
    target = tmp_path / existing
    target.write_text("KEEP=me\n")
    before = tree(tmp_path)
    r = run(tmp_path)
    assert r.returncode == 1 and "already exists" in r.stderr
    assert target.read_text() == "KEEP=me\n"
    assert tree(tmp_path) == before
    assert NAME not in r.stdout


@not_root
@pytest.mark.parametrize("args", [("extra",), ("--bogus",), ("--restore", "x")])
def test_wrong_arguments_print_usage(tmp_path: Path, args: tuple[str, ...]) -> None:
    host(tmp_path)
    before = tree(tmp_path)
    r = run(tmp_path, *args)
    assert r.returncode == 1 and "usage" in r.stderr
    assert tree(tmp_path) == before


@not_root
def test_without_root_and_without_the_test_switch_it_refuses(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(tmp_path, test_mode=False)
    assert r.returncode == 1 and "run as root" in r.stderr
    assert tree(tmp_path) == {"env", "env/db-owner.env"}


# ---- restore from the secrets manager's copy ----


@not_root
def test_restore_rebuilds_byte_identical_files_and_prints_no_secret(tmp_path: Path) -> None:
    host(tmp_path)
    block = printed(run(tmp_path).stdout)
    originals = {f: (tmp_path / f).read_bytes() for f in FILES}
    for f in FILES:
        (tmp_path / f).unlink()
    r = run(tmp_path, "--restore", **block)
    assert r.returncode == 0, r.stderr
    for f in FILES:
        assert (tmp_path / f).read_bytes() == originals[f]
        assert stat.S_IMODE((tmp_path / f).stat().st_mode) == 0o600
    assert block[NAME] not in r.stdout + r.stderr


@not_root
def test_restore_needs_the_value(tmp_path: Path) -> None:
    dst = host(tmp_path)
    r = run(dst, "--restore")
    assert r.returncode == 1 and tree(dst) == {"env", "env/db-owner.env"}


@not_root
@pytest.mark.parametrize("bad", ["short", "g" * 48, "A" * 48, "a" * 48 + "@evil", "a" * 47 + "\n"])
def test_restore_rejects_values_that_could_break_the_url_or_the_files(
    tmp_path: Path, bad: str
) -> None:
    dst = host(tmp_path)
    r = run(dst, "--restore", **{NAME: bad})
    assert r.returncode == 1 and tree(dst) == {"env", "env/db-owner.env"}


@not_root
def test_restore_also_refuses_to_overwrite(tmp_path: Path) -> None:
    host(tmp_path)
    block = printed(run(tmp_path).stdout)
    before = (tmp_path / "env/reconcile-db.env").read_bytes()
    r = run(tmp_path, "--restore", **block)
    assert r.returncode == 1
    assert (tmp_path / "env/reconcile-db.env").read_bytes() == before


def test_the_secret_only_ever_reaches_shell_builtins() -> None:
    """A here-document can go through a temporary file (bash before 5.1) and an external
    command's arguments are visible to every process: the variable holding the secret may
    only appear in printf (a builtin) and plain assignments."""
    text = SCRIPT.read_text()
    assert "<<" not in text.replace("<<<", "")
    for line in text.splitlines():
        code = line.split("#", 1)[0]
        if "$RECONCILE_PW" in code or "${RECONCILE_PW}" in code:
            assert code.lstrip().startswith(("printf", '"', "[[", "RECONCILE_PW=")), line
