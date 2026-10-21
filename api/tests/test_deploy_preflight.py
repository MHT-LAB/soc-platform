"""deploy.sh must refuse, before touching anything, when the console allowlist
is missing or blank. These run the real script; every refusal case exits at the
preflight, before any cosign or docker call."""

import shutil
import subprocess
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "deploy.sh"
BASH = shutil.which("bash") or "/bin/bash"

BLANK = [
    None,  # no console.env at all
    "",
    "SOC_CONSOLE_USERS=",
    'SOC_CONSOLE_USERS=""',
    "SOC_CONSOLE_USERS=''",
    "SOC_CONSOLE_USERS=   ",
    "SOC_CONSOLE_USERS=,,",
    "#SOC_CONSOLE_USERS=a@example.com",
    "SOC_CONSOLE_USERSX=a@example.com",
]
GOOD = [
    "SOC_CONSOLE_USERS=a@example.com",
    "SOC_CONSOLE_USERS=a@example.com, b@example.com",
    'SOC_CONSOLE_USERS="a@example.com"',
]


@pytest.mark.parametrize("content", BLANK)
def test_deploy_refuses_without_a_console_allowlist(tmp_path: Path, content: str | None) -> None:
    (tmp_path / "env").mkdir()
    if content is not None:
        (tmp_path / "env" / "console.env").write_text(content + "\n")
    r = subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(DEPLOY), "edge"],
        env={"SOC_STATE_DIR": str(tmp_path), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert r.returncode == 1
    assert "must set SOC_CONSOLE_USERS" in r.stdout


@pytest.mark.parametrize("content", GOOD)
def test_preflight_pattern_accepts_real_logins(tmp_path: Path, content: str) -> None:
    env_file = tmp_path / "console.env"
    env_file.write_text(content + "\n")
    # Use the script's own pattern line, so the test can't drift from it.
    script = (
        f'eval "$(grep -m1 ^CONSOLE_USERS_LINE= {DEPLOY})"; grep -qE "$CONSOLE_USERS_LINE" "$1"'
    )
    r = subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, "-c", script, "_", str(env_file)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert r.returncode == 0


def test_deploy_pins_prod_so_a_stray_dev_env_cannot_leak_in() -> None:
    assert "\nexport SOC_ENV=prod\n" in DEPLOY.read_text()
