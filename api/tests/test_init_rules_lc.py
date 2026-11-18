"""deploy/init-rules-lc.sh: takes the two keys from the keyboard (or, to restore, from the
environment), writes one mode-600 file, never prints a key, never overwrites.
These run the real script (SOC_INIT_TEST skips the root check, and is refused for root)."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "init-rules-lc.sh"
BASH = shutil.which("bash") or "/bin/bash"
FILE = "env/rules-lc.env"
KEY = "test-only-vendor-key-not-real"
STAMP = "test-only-stamp-key-0123456789abcdef-not-real"
OID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
ORG = "acme"
PREFIXES = "T - |BASE - "

not_root = pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user")


def host(tmp: Path) -> Path:
    (tmp / "env").mkdir(parents=True, exist_ok=True)
    return tmp


def run(
    state: Path, *args: str, stdin: str = "", test_mode: bool = True, **env: str
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


def answers(
    key: str = KEY, oid: str = OID, stamp: str = STAMP, org: str = ORG, prefixes: str = PREFIXES
) -> str:
    return f"{key}\n{oid}\n{stamp}\n{org}\n{prefixes}\n"


def tree(state: Path) -> set[str]:
    return {str(p.relative_to(state)) for p in state.rglob("*")}


def test_the_script_is_executable() -> None:
    assert os.access(SCRIPT, os.X_OK)


@not_root
def test_it_writes_one_file_with_the_five_values_and_a_strict_mode(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(tmp_path, stdin=answers())
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE((tmp_path / FILE).stat().st_mode) == 0o600
    assert (tmp_path / FILE).read_text().splitlines() == [
        f"SOC_RULES_LC_KEY={KEY}",
        f"SOC_RULES_LC_OID={OID}",
        f"SOC_RULES_STAMP_KEY={STAMP}",
        f"SOC_RULES_ORG={ORG}",
        f'SOC_RULES_PREFIXES="{PREFIXES}"',
    ]
    assert tree(tmp_path) == {"env", FILE}


@not_root
def test_the_service_accepts_what_the_script_wrote(tmp_path: Path) -> None:
    """The file goes through a compose env file, which strips the quotes; read it that way."""
    from soc_api.rules_deploy import Config

    host(tmp_path)
    assert run(tmp_path, stdin=answers()).returncode == 0
    env = {}
    for line in (tmp_path / FILE).read_text().splitlines():
        name, _, value = line.partition("=")
        env[name] = value.strip('"')
    env["SOC_RULES_COMMIT"] = "0" * 40
    cfg = Config.from_env(env)
    assert cfg.org == ORG and cfg.prefixes == ("T - ", "BASE - ")
    assert cfg.key == KEY and cfg.stamp_key == STAMP


@not_root
def test_a_trailing_space_in_a_prefix_survives(tmp_path: Path) -> None:
    host(tmp_path)
    assert run(tmp_path, stdin=answers(prefixes="ACME - ")).returncode == 0
    assert (tmp_path / FILE).read_text().splitlines()[-1] == 'SOC_RULES_PREFIXES="ACME - "'


@not_root
def test_the_keys_are_never_printed_anywhere(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(tmp_path, stdin=answers())
    out = r.stdout + r.stderr
    assert KEY not in out and STAMP not in out
    assert "not shown" in out and "SOC_LC_RULES_DEPLOY_KEY" in out and "SOC_RULES_STAMP_KEY" in out
    for path in tmp_path.rglob("*"):
        if path.is_file() and path != tmp_path / FILE:
            assert KEY not in path.read_text() and STAMP not in path.read_text(), path


@not_root
def test_it_needs_the_env_folder_first(tmp_path: Path) -> None:
    r = run(tmp_path, stdin=answers())
    assert r.returncode == 1 and "run init-secrets.sh first" in r.stderr
    assert tree(tmp_path) == set()


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
        answers(oid="not-a-uuid"),
        answers(oid=OID.upper()),
        answers(stamp="x" * 31),
        answers(stamp=STAMP + "$HOME"),
        answers(stamp=STAMP + "#c"),
        answers(stamp=STAMP + '"'),
        answers(stamp=KEY, key=KEY),
        answers(org="Not Valid"),
        answers(org=""),
        answers(org="x" * 33),
        answers(prefixes=""),
        answers(prefixes="ab"),
        answers(prefixes="T - |"),
        answers(prefixes='T - "x'),
        answers(prefixes="T - $HOME"),
        "",
        f"{KEY}\n",
    ],
)
def test_bad_or_missing_answers_write_nothing(tmp_path: Path, stdin: str) -> None:
    host(tmp_path)
    r = run(tmp_path, stdin=stdin)
    assert r.returncode == 1 and "FAILED" in r.stderr
    assert tree(tmp_path) == {"env"}
    assert not (tmp_path / "pwned").exists()
    assert KEY not in r.stdout + r.stderr


@not_root
def test_restore_rebuilds_the_file_from_the_environment(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(
        tmp_path,
        "--restore",
        SOC_LC_RULES_DEPLOY_KEY=KEY,
        SOC_LC_OID=OID,
        SOC_RULES_STAMP_KEY=STAMP,
        SOC_RULES_ORG=ORG,
        SOC_RULES_PREFIXES=PREFIXES,
    )
    assert r.returncode == 0, r.stderr
    assert "restored" in r.stdout and KEY not in r.stdout + r.stderr
    assert stat.S_IMODE((tmp_path / FILE).stat().st_mode) == 0o600
    assert f"SOC_RULES_STAMP_KEY={STAMP}" in (tmp_path / FILE).read_text()


@not_root
def test_restore_refuses_missing_values(tmp_path: Path) -> None:
    host(tmp_path)
    r = run(tmp_path, "--restore", SOC_LC_RULES_DEPLOY_KEY=KEY, SOC_LC_OID=OID)
    assert r.returncode == 1 and tree(tmp_path) == {"env"}


@not_root
def test_it_refuses_unknown_arguments(tmp_path: Path) -> None:
    host(tmp_path)
    for args in (["--bogus"], ["--restore", "x"]):
        r = run(tmp_path, *args, stdin=answers())
        assert r.returncode == 1 and "usage" in r.stderr
    assert tree(tmp_path) == {"env"}


def test_the_test_switch_is_refused_for_root_and_needed_otherwise(tmp_path: Path) -> None:
    host(tmp_path)
    if os.geteuid() == 0:
        assert run(tmp_path, stdin=answers()).returncode == 1
    else:
        r = run(tmp_path, stdin=answers(), test_mode=False)
        assert r.returncode == 1 and "run as root" in r.stderr
        assert tree(tmp_path) == {"env"}
