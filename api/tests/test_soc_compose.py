"""deploy/soc-compose.sh: one-off compose commands on the host must use exactly the
stack deploy.sh runs (project, both compose files, pinned image, db profile), or a
seed or psql shell would target an image or project that does not exist there."""

import shutil
import stat
import subprocess
from pathlib import Path

import pytest

DEPLOY_DIR = Path(__file__).resolve().parents[2] / "deploy"
WRAPPER = DEPLOY_DIR / "soc-compose.sh"
BASH = shutil.which("bash") or "/bin/bash"

FAKE_DOCKER = """#!/usr/bin/env bash
printf '%s\\n' "profiles=${COMPOSE_PROFILES-unset}" "$@" > "$FAKE_LOG"
"""


def run(tmp: Path, *args: str, **env: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bin_dir = tmp / "bin"
    bin_dir.mkdir(exist_ok=True)
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    log = tmp / "docker.log"
    r = subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(WRAPPER), *args],
        env={
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "SOC_STATE_DIR": str(tmp),
            "FAKE_LOG": str(log),
            **env,
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return r, log.read_text().splitlines() if log.exists() else []


def state(tmp: Path, *, image: bool = True, db: bool = True) -> None:
    (tmp / "env").mkdir()
    if image:
        (tmp / "env" / "image.env").write_text("SOC_API_IMAGE=x@sha256:" + "a" * 64 + "\n")
    if db:
        (tmp / "env" / "db.env").write_text("POSTGRES_PASSWORD=x\n")
        (tmp / "env" / "db-owner.env").write_text("SOC_MIGRATE_URL=x\n")


def test_it_runs_compose_like_deploy_sh(tmp_path: Path) -> None:
    state(tmp_path)
    r, argv = run(tmp_path, "exec", "db", "psql", "-U", "postgres")
    assert r.returncode == 0, r.stderr
    assert argv == [
        "profiles=db",
        "compose",
        "-p",
        "soc",
        "-f",
        str(DEPLOY_DIR / "compose.yml"),
        "-f",
        str(DEPLOY_DIR / "compose.stage-a.yml"),
        "--env-file",
        str(tmp_path / "env" / "image.env"),
        "exec",
        "db",
        "psql",
        "-U",
        "postgres",
    ]


def test_the_compose_invocation_matches_deploy_sh() -> None:
    # If deploy.sh changes how it calls compose, this wrapper must change with it.
    deploy = (DEPLOY_DIR / "deploy.sh").read_text()
    wrapper = WRAPPER.read_text()
    assert (
        "docker compose -p soc \\\n"
        '    -f "$HERE/compose.yml" -f "$HERE/$OVERLAY" \\\n'
        '    --env-file "$IMAGE_ENV"' in deploy
    )
    assert (
        'docker compose -p soc -f "$HERE/compose.yml" -f "$HERE/$OVERLAY" --env-file "$IMAGE_ENV"'
        in wrapper
    )


def test_without_database_files_the_db_profile_stays_off_whatever_the_shell_says(
    tmp_path: Path,
) -> None:
    state(tmp_path, db=False)
    r, argv = run(tmp_path, "ps", COMPOSE_PROFILES="db")
    assert r.returncode == 0
    assert argv[0] == "profiles=unset"


@pytest.mark.parametrize("args", [(), ("ps",)])
def test_it_refuses_before_the_first_deploy_or_without_a_command(
    tmp_path: Path, args: tuple[str, ...]
) -> None:
    state(tmp_path, image=not args)
    r, argv = run(tmp_path, *args)
    assert r.returncode != 0
    assert argv == []


def test_a_worker_file_turns_the_worker_profile_on_here_too(tmp_path: Path) -> None:
    state(tmp_path)
    (tmp_path / "env" / "worker.env").write_text("SOC_NTFY_TOPIC=x\n")
    r, argv = run(tmp_path, "ps")
    assert r.returncode == 0, r.stderr
    assert argv[0] == "profiles=db,worker"


def test_the_worker_profile_needs_the_database_profile(tmp_path: Path) -> None:
    state(tmp_path, db=False)
    (tmp_path / "env" / "worker.env").write_text("SOC_NTFY_TOPIC=x\n")
    r, argv = run(tmp_path, "ps")
    assert r.returncode == 0, r.stderr
    assert argv[0] == "profiles=unset"
