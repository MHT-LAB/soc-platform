"""deploy/init-reconcile-lc.sh: takes the vendor API key from the keyboard (or, to restore,
from the environment), writes it to one mode-600 file, never prints it, never overwrites.
These run the real script (SOC_INIT_TEST skips the root check, and is refused for root)."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from soc_api.config import Settings

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "init-reconcile-lc.sh"
BASH = shutil.which("bash") or "/bin/bash"
FILE = "env/reconcile-lc.env"
KEY = "test-only-key-not-real"
OID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
SLUG = "lc-abcd1234"

not_root = pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user")


def host(tmp: Path, *, reconcile_db: bool = True) -> Path:
    """A host that already ran init-secrets.sh and init-reconcile.sh."""
    (tmp / "env").mkdir(parents=True, exist_ok=True)
    (tmp / "env" / "db-owner.env").write_text("SOC_MIGRATE_URL=x\n")
    if reconcile_db:
        (tmp / "env" / "reconcile-db.env").write_text("SOC_RECONCILE_DATABASE_URL=x\n")
    return tmp


def run(
    state: Path,
    *args: str,
    stdin: str = "",
    test_mode: bool = True,
    **env: str,
) -> subprocess.CompletedProcess[str]:
    full = {"PATH": "/usr/bin:/bin", "SOC_STATE_DIR": str(state), **env}
    if test_mode:
        full["SOC_INIT_TEST"] = "1"
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(SCRIPT), *args],
        env=full,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=30,
    )


def answers(key: str = KEY, oid: str = OID, slug: str = SLUG) -> str:
    return f"{key}\n{oid}\n{slug}\n"


def parse_env(path: Path) -> dict[str, str]:
    return {k: v for k, _, v in (line.partition("=") for line in path.read_text().splitlines())}


def tree(state: Path) -> set[str]:
    return {str(p.relative_to(state)) for p in state.rglob("*")}


BASE = {"env", "env/db-owner.env", "env/reconcile-db.env"}


def test_the_script_is_executable() -> None:
    assert os.access(SCRIPT, os.X_OK)


@not_root
def test_it_writes_one_file_with_the_three_values_and_a_strict_mode(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(tmp_path, stdin=answers())
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE((tmp_path / FILE).stat().st_mode) == 0o600
    assert parse_env(tmp_path / FILE) == {
        "SOC_RECONCILE_LC_KEY": KEY,
        "SOC_RECONCILE_LC_OID": OID,
        "SOC_RECONCILE_SOURCE": SLUG,
    }
    assert tree(tmp_path) == {*BASE, FILE}


@not_root
def test_the_app_accepts_the_file(tmp_path: Path) -> None:
    host(tmp_path)
    assert run(tmp_path, stdin=answers()).returncode == 0
    env = parse_env(tmp_path / FILE)
    settings = Settings(
        reconcile_lc_key=env["SOC_RECONCILE_LC_KEY"],
        reconcile_lc_oid=env["SOC_RECONCILE_LC_OID"],
        reconcile_source=env["SOC_RECONCILE_SOURCE"],
    )
    assert settings.reconcile_lc_key.get_secret_value() == KEY
    assert settings.reconcile_lc_oid == OID and settings.reconcile_source == SLUG


@not_root
def test_the_key_is_never_printed_anywhere(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(tmp_path, stdin=answers())
    assert KEY not in r.stdout + r.stderr
    assert "not shown" in r.stderr + r.stdout and "SOC_LC_RECONCILE_KEY" in r.stdout
    allowed = {tmp_path / FILE}
    for path in tmp_path.rglob("*"):
        if path.is_file() and path not in allowed:
            assert KEY not in path.read_text(), path


@not_root
def test_it_needs_the_database_files_first(tmp_path: Path) -> None:
    (tmp_path / "env").mkdir()
    r = run(tmp_path, stdin=answers())
    assert r.returncode == 1 and "run init-secrets.sh first" in r.stderr
    assert tree(tmp_path) == {"env"}
    host(tmp_path / "b", reconcile_db=False)
    r = run(tmp_path / "b", stdin=answers())
    assert r.returncode == 1 and "run init-reconcile.sh first" in r.stderr
    assert FILE not in tree(tmp_path / "b")


@not_root
def test_it_never_overwrites(tmp_path: Path) -> None:
    host(tmp_path)
    (tmp_path / FILE).write_text("KEEP=me\n")
    before = tree(tmp_path)
    r = run(tmp_path, stdin=answers())
    assert r.returncode == 1 and "already exists" in r.stderr
    assert (tmp_path / FILE).read_text() == "KEEP=me\n"
    assert tree(tmp_path) == before and KEY not in r.stdout + r.stderr


@not_root
@pytest.mark.parametrize(
    "stdin",
    [
        answers(key="short"),
        answers(key="a b" * 10),
        answers(key="x" * 129),
        answers(key=KEY + "$(touch pwned)"),
        answers(key=KEY + ";rm"),
        answers(oid="not-an-oid"),
        answers(oid=OID.upper()),
        answers(oid=OID + "x"),
        answers(slug="Bad_Slug"),
        answers(slug="x" * 33),
        answers(slug=""),
        answers(slug="a b"),
        "",
        KEY + "\n",
        KEY + "\n" + OID + "\n",
    ],
)
def test_bad_or_missing_answers_create_nothing(tmp_path: Path, stdin: str) -> None:
    host(tmp_path)
    r = run(tmp_path, stdin=stdin)
    assert r.returncode == 1
    assert tree(tmp_path) == BASE
    assert KEY not in r.stdout + r.stderr
    assert not (tmp_path / "pwned").exists()


@not_root
@pytest.mark.parametrize("args", [("extra",), ("--bogus",), ("--restore", "x")])
def test_wrong_arguments_print_usage(tmp_path: Path, args: tuple[str, ...]) -> None:
    host(tmp_path)
    r = run(tmp_path, *args, stdin=answers())
    assert r.returncode == 1 and "usage" in r.stderr
    assert tree(tmp_path) == BASE


@not_root
def test_without_root_and_without_the_test_switch_it_refuses(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(tmp_path, test_mode=False, stdin=answers())
    assert r.returncode == 1 and "run as root" in r.stderr
    assert tree(tmp_path) == BASE


@not_root
def test_restore_rebuilds_a_byte_identical_file_and_prints_no_secret(tmp_path: Path) -> None:
    host(tmp_path)
    assert run(tmp_path, stdin=answers()).returncode == 0
    original = (tmp_path / FILE).read_bytes()
    (tmp_path / FILE).unlink()
    r = run(
        tmp_path,
        "--restore",
        SOC_LC_RECONCILE_KEY=KEY,
        SOC_LC_OID=OID,
        SOC_INGEST_LC_SLUG=SLUG,
    )
    assert r.returncode == 0, r.stderr
    assert (tmp_path / FILE).read_bytes() == original
    assert stat.S_IMODE((tmp_path / FILE).stat().st_mode) == 0o600
    assert KEY not in r.stdout + r.stderr


@not_root
@pytest.mark.parametrize("missing", ["SOC_LC_RECONCILE_KEY", "SOC_LC_OID", "SOC_INGEST_LC_SLUG"])
def test_restore_needs_all_three_values(tmp_path: Path, missing: str) -> None:
    host(tmp_path)
    env = {"SOC_LC_RECONCILE_KEY": KEY, "SOC_LC_OID": OID, "SOC_INGEST_LC_SLUG": SLUG}
    del env[missing]
    r = run(tmp_path, "--restore", **env)
    assert r.returncode == 1 and tree(tmp_path) == BASE


@not_root
def test_restore_rejects_a_value_that_could_break_the_file(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(
        tmp_path,
        "--restore",
        SOC_LC_RECONCILE_KEY=KEY + "\nSOC_ENV=dev",
        SOC_LC_OID=OID,
        SOC_INGEST_LC_SLUG=SLUG,
    )
    assert r.returncode == 1 and tree(tmp_path) == BASE


def test_the_key_only_ever_reaches_shell_builtins() -> None:
    """The key variable may only be read into, tested with [[ ]] and written by printf (a
    builtin): never an external command's argument, which every process can see."""
    text = SCRIPT.read_text()
    assert "<<" not in text.replace("<<<", "")
    for line in text.splitlines():
        code = line.split("#", 1)[0]
        if "$LC_KEY" in code or "${LC_KEY}" in code:
            assert code.lstrip().startswith(("printf", '"', "[[", "LC_KEY=", "IFS=")), line
    assert "read -rs" in text  # echo off while it is typed
