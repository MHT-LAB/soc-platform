"""deploy.sh --prepare: for a host that has never been deployed (the restore drill, a lost
host). Same checks as a deploy, then image.env and a pull, and nothing started. Refuses
beside a running stack and on a host whose image.env names another image."""

import stat
import subprocess
from pathlib import Path

from test_deploy_db import OLD_IMAGE, DbHost
from test_deploy_source_check import BASH, DEPLOY, IMAGE, REPO_DIGEST, Host

FAKE_DOCKER = """#!/usr/bin/env bash
echo "docker $* [profiles=${COMPOSE_PROFILES-unset}]" >> "$FAKE_LOG"
case "$1" in
  ps) if [[ -n "${FAKE_RUNNING:-}" ]]; then echo "$FAKE_RUNNING"; fi; exit "${FAKE_PS_RC:-0}" ;;
  buildx) printf '%s\\n' "$FAKE_LABELS"; exit 0 ;;
  compose)
    if [[ "$*" == *" pull "* ]]; then exit "${FAKE_PULL_RC:-0}"; fi
    if [[ "$*" == *" ps -q "* ]]; then echo cid; fi
    exit 0 ;;
  inspect)
    if [[ "$*" == *Health* ]]; then echo healthy; else echo imgid; fi
    exit 0 ;;
  image) printf '%s\\n' "$FAKE_REPODIGEST"; exit 0 ;;
esac
exit 0
"""

NEW_IMAGE = f"{IMAGE}@{REPO_DIGEST}"


class PrepHost(DbHost):
    def __init__(self, tmp: Path, **kw: bool) -> None:
        super().__init__(tmp, **kw)
        path = self.bin / "docker"
        path.write_text(FAKE_DOCKER)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        (self.state / "pgdata").mkdir()

    def run(self, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.tmp),
            "SOC_STATE_DIR": str(self.state),
            "SOC_TEST_BIN": str(self.bin),
            "SOC_SOURCE_DIR": str(self.src),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "FAKE_LOG": str(self.log),
            "FAKE_DIGEST": REPO_DIGEST,
            "FAKE_REPODIGEST": NEW_IMAGE,
            "FAKE_LABELS": Host.labels(self.main),
            **extra,
        }
        return subprocess.run(  # noqa: S603 - fixed argv, our own script
            [BASH, str(DEPLOY), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def prepare(self, **extra: str) -> subprocess.CompletedProcess[str]:
        return self.run("--prepare", "edge", **extra)

    def all_calls(self) -> list[str]:
        return self.log.read_text().splitlines()


def test_prepare_writes_image_env_pulls_and_starts_nothing(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    r = host.prepare()
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.image_env.read_text() == f"SOC_API_IMAGE={NEW_IMAGE}\nSOC_STATE_DIR={host.state}\n"
    calls = host.calls()
    assert len(calls) == 1, calls
    assert " pull --quiet" in calls[0]
    assert "[profiles=db]" in calls[0]  # the database image is pulled for restore.sh
    assert not any(c.startswith("docker run") or " up " in c for c in host.all_calls())
    assert "nothing started" in r.stdout


def test_prepare_runs_the_same_signature_and_source_checks(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    r = host.prepare(FAKE_COSIGN_SHA_RC="1")
    assert r.returncode == 1
    assert "does not name commit" in r.stdout
    assert not host.image_env.exists()
    assert host.calls() == []


def test_prepare_needs_no_tunnel_files_but_a_deploy_still_does(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    for f in (host.state / "tunnel").iterdir():
        f.unlink()
    (host.state / "tunnel").rmdir()
    assert host.prepare().returncode == 0
    r = host.run("edge")
    assert r.returncode == 1
    assert "tunnel/config.yml is missing" in r.stdout


def test_prepare_still_requires_the_console_allowlist(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    (host.state / "env" / "console.env").write_text("SOC_CONSOLE_USERS=\n")
    r = host.prepare()
    assert r.returncode == 1
    assert "SOC_CONSOLE_USERS" in r.stdout
    assert not host.image_env.exists()


def test_prepare_is_refused_while_the_stack_is_running(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    r = host.prepare(FAKE_RUNNING="abc123")
    assert r.returncode == 1
    assert "stack is not running" in r.stdout
    assert not host.image_env.exists()
    assert host.calls() == []
    assert not any(c.startswith("cosign") for c in host.all_calls())  # refused before verifying


def test_prepare_is_refused_when_running_containers_cannot_be_listed(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    r = host.prepare(FAKE_PS_RC="1")
    assert r.returncode == 1
    assert "could not list the running containers" in r.stdout
    assert not host.image_env.exists()


def test_prepare_never_changes_the_image_of_a_deployed_host(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    host.with_previous_image()
    before = host.image_env.read_text()
    r = host.prepare()
    assert r.returncode == 1
    assert "already names another image" in r.stdout
    assert host.image_env.read_text() == before
    assert host.calls() == []
    assert OLD_IMAGE in before


def test_prepare_can_be_run_again_for_the_same_image(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    assert host.prepare().returncode == 0
    r = host.prepare()
    assert r.returncode == 0, r.stdout
    assert f"SOC_API_IMAGE={NEW_IMAGE}\n" in host.image_env.read_text()
    calls = host.calls()
    assert len(calls) == 2, calls
    assert all(" pull --quiet" in c for c in calls)


def test_an_image_env_without_an_image_line_is_refused(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    host.image_env.write_text("SOC_STATE_DIR=/srv/soc\n")
    r = host.prepare()
    assert r.returncode == 1
    assert "names no image" in r.stdout
    assert host.image_env.read_text() == "SOC_STATE_DIR=/srv/soc\n"


def test_a_failed_pull_leaves_no_image_env_behind(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    r = host.prepare(FAKE_PULL_RC="1")
    assert r.returncode == 1
    assert "pulling the images failed" in r.stdout
    assert not host.image_env.exists()


def test_an_unknown_option_is_refused(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    r = host.run("--prep", "edge")
    assert r.returncode == 1
    assert "unknown option --prep" in r.stderr
    assert host.all_calls() == []


def test_a_normal_deploy_does_not_check_for_running_containers(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    r = host.run("edge", FAKE_RUNNING="abc123")
    assert r.returncode == 0, r.stdout
    assert not any(c.startswith("docker ps") for c in host.all_calls())
