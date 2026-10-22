"""deploy.sh must refuse, before touching anything, when the console allowlist
is missing or blank, or the locally managed tunnel's config is not installed.
These run the real script; every refusal case exits at the preflight, before
any cosign or docker call."""

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


TUNNEL_ID = "6f0c2a52-0000-4000-8000-000000000000"
GOOD_CONFIG = f"""tunnel: {TUNNEL_ID}
credentials-file: /etc/cloudflared/{TUNNEL_ID}.json
ingress:
  - hostname: soc.example.com
    path: ^/healthz$
    service: http://api:8080
  - service: http_status:404
"""


def run_deploy(state: Path, overlay: str | None = None) -> subprocess.CompletedProcess[str]:
    env = {"SOC_STATE_DIR": str(state), "PATH": "/usr/bin:/bin"}
    if overlay:
        env["SOC_OVERLAY"] = overlay
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(DEPLOY), "edge"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def tunnel_state(tmp: Path, config: str | None, creds: bool = True) -> Path:
    (tmp / "env").mkdir()
    (tmp / "env" / "console.env").write_text("SOC_CONSOLE_USERS=a@example.com\n")
    (tmp / "tunnel").mkdir()
    if config is not None:
        (tmp / "tunnel" / "config.yml").write_text(config)
    if creds:
        (tmp / "tunnel" / f"{TUNNEL_ID}.json").write_text('{"TunnelID": "x"}\n')
    return tmp


@pytest.mark.parametrize(
    ("config", "creds", "message"),
    [
        (None, True, "config.yml is missing"),
        ("", True, "config.yml is missing"),
        (GOOD_CONFIG, False, f"tunnel credentials {{}}/tunnel/{TUNNEL_ID}.json are missing"),
        (
            GOOD_CONFIG.replace("credentials-file", "#credentials-file"),
            True,
            "must set credentials-file",
        ),
        # A credentials path outside the mounted directory can't be checked or read.
        (
            GOOD_CONFIG.replace("/etc/cloudflared/", "/root/.cloudflared/"),
            True,
            "must set credentials-file",
        ),
        (
            GOOD_CONFIG.replace(f"{TUNNEL_ID}.json", "../env/console.env"),
            True,
            "must set credentials-file",
        ),
        (GOOD_CONFIG.replace("  - service: http_status:404\n", ""), True, "catch-all rule"),
        (GOOD_CONFIG.replace("http_status:404", "http://api:8080"), True, "catch-all rule"),
    ],
)
def test_deploy_refuses_without_a_complete_tunnel_config(
    tmp_path: Path, config: str | None, creds: bool, message: str
) -> None:
    r = run_deploy(tunnel_state(tmp_path, config, creds))
    assert r.returncode == 1
    assert message.format(tmp_path) in r.stdout
    assert not (tmp_path / "env" / "image.env").exists()


def test_complete_tunnel_config_passes_the_preflight(tmp_path: Path) -> None:
    # PATH has no cosign, so a deploy that gets past the preflight stops at step 1.
    r = run_deploy(tunnel_state(tmp_path, GOOD_CONFIG))
    assert r.returncode == 1
    assert "verifying" in r.stdout and "tunnel" not in r.stdout.split("verifying")[0]


def test_other_edges_do_not_need_the_tunnel_config(tmp_path: Path) -> None:
    r = run_deploy(tunnel_state(tmp_path, None, creds=False), overlay="compose.stage-b.yml")
    assert "verifying" in r.stdout
