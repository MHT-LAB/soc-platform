"""deploy/rules-deploy.sh: the host side of the rules deploy (Sprint 4, E3).

These run the real script with a fake docker first on PATH (SOC_TEST_BIN, refused for root) and
a throwaway git repository with ssh-signed commits as the rules clone, so nothing touches the
network or the machine. Every refusal must happen before the service is run.
"""

# ruff: noqa: S603 - every subprocess here runs a fixed argv built by the test itself
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "rules-deploy.sh"
BASH = shutil.which("bash") or "/bin/bash"
GIT = shutil.which("git") or "git"
SSH_KEYGEN = shutil.which("ssh-keygen")

pytestmark = [
    pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user (tests mode)"),
    pytest.mark.skipif(SSH_KEYGEN is None, reason="needs ssh-keygen to sign test commits"),
]

FAKE_DOCKER = """#!/usr/bin/env bash
echo "docker $*" >> "$FAKE_LOG"
echo "commit=${SOC_RULES_COMMIT:-} src=${SOC_RULES_SRC:-}" >> "$FAKE_LOG"
echo "profiles=${COMPOSE_PROFILES:-}" >> "$FAKE_LOG"
if [[ "$*" == *" run "* && "$*" == *" rules"* ]]; then
  if [[ -n "${FAKE_RECORD:-}" ]]; then
    printf '%s\\n' "$FAKE_RECORD" > "$SOC_STATE_DIR/rules-out/record.txt"
  fi
  exit "${FAKE_RC:-0}"
fi
exit 0
"""

RECORD = (
    "rules-deploy 2026-11-18T09:30:00Z org=aaaaaaaa commit=0123456789ab "
    "added=1 changed=0 removed=0 unchanged=0 unmanaged=0 result=applied"
)


class Host:
    """A host's state folder, a rules clone with a remote, and a signing key."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.state = root / "state"
        self.repo = root / "clone"
        self.origin = root / "origin.git"
        self.bin = root / "bin"
        self.log = root / "fake.log"
        self.key = root / "id_signer"
        self.other_key = root / "id_other"
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(root),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        self.bin.mkdir()
        (self.bin / "docker").write_text(FAKE_DOCKER)
        (self.bin / "docker").chmod(0o755)
        for key in (self.key, self.other_key):
            self._run(SSH_KEYGEN or "", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
        pub = Path(f"{self.key}.pub").read_text().strip()
        (root / "signers").write_text(f"signer@example.com {pub}\n")
        self._run(GIT, "init", "-q", "--bare", "-b", "main", str(self.origin))
        self._run(GIT, "init", "-q", "-b", "main", str(self.repo))
        for k, v in {
            "user.name": "Signer",
            "user.email": "signer@example.com",
            "gpg.format": "ssh",
            "gpg.ssh.allowedSignersFile": str(root / "signers"),
            "user.signingkey": str(self.key),
        }.items():
            self.git("config", k, v)
        self.git("remote", "add", "origin", str(self.origin))
        (self.repo / "detections" / "orgs" / "acme").mkdir(parents=True)
        self.commit("detections/orgs/acme/a.json", "{}")
        self.git("push", "-q", "origin", "main")
        self.git("branch", "--set-upstream-to=origin/main", "main")
        (self.state / "env").mkdir(parents=True)
        (self.state / "env" / "image.env").write_text("SOC_API_IMAGE=x\n")
        lc = self.state / "env" / "rules-lc.env"
        lc.write_text("SOC_RULES_LC_KEY=x\n")
        lc.chmod(0o600)

    def _run(self, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed argv in a test
            argv, env=self.env, capture_output=True, text=True, check=True, timeout=30
        )

    def git(self, *args: str) -> str:
        return self._run(GIT, "-C", str(self.repo), *args).stdout.strip()

    def commit(self, rel: str, text: str, *, signed: bool = True, key: Path | None = None) -> str:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.git("add", rel)
        argv = [GIT, "-C", str(self.repo)]
        if key is not None:
            argv += ["-c", f"user.signingkey={key}"]
        argv += ["commit", "-q", "-S" if signed else "--no-gpg-sign", "-m", f"change {rel}"]
        self._run(*argv)
        return self.git("rev-parse", "HEAD")

    def push(self) -> None:
        self.git("push", "-q", "origin", "main")

    def run(self, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {
            **self.env,
            "SOC_STATE_DIR": str(self.state),
            "SOC_RULES_REPO": str(self.repo),
            "SOC_TEST_BIN": str(self.bin),
            "FAKE_LOG": str(self.log),
            **extra,
        }
        return subprocess.run(  # noqa: S603 - fixed argv, our own script
            [BASH, str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60, input=""
        )

    def docker_calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def deploy_log(self) -> str:
        path = self.state / "rules-deploy.log"
        return path.read_text() if path.exists() else ""


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def test_the_script_is_executable() -> None:
    assert os.access(SCRIPT, os.X_OK)


def test_a_clean_signed_clone_at_origin_main_runs_the_service_with_that_commit(host: Host) -> None:
    head = host.git("rev-parse", "HEAD")
    r = host.run(FAKE_RECORD=RECORD)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = host.docker_calls()
    assert "--profile rules run --rm rules" in calls
    assert f"commit={head} src={host.repo}" in calls
    assert "profiles=" in calls and "profiles=rules" not in calls.replace("--profile rules", "")
    assert RECORD in host.deploy_log()
    assert RECORD in r.stdout
    assert "signed by" in host.deploy_log()


def test_the_services_exit_code_is_the_scripts_and_its_record_is_still_kept(host: Host) -> None:
    for rc in (1, 2, 3):
        r = host.run(FAKE_RECORD=RECORD, FAKE_RC=str(rc))
        assert r.returncode == rc
    assert host.deploy_log().count(RECORD) == 3


def test_no_record_is_reported_not_invented(host: Host) -> None:
    r = host.run(FAKE_RC="1")
    assert r.returncode == 1
    assert "no record was written" in host.deploy_log()


def test_a_stale_record_from_an_earlier_run_is_never_reused(host: Host) -> None:
    host.run(FAKE_RECORD=RECORD)
    first = host.deploy_log().count(RECORD)
    host.run()  # this time the service writes nothing
    assert host.deploy_log().count(RECORD) == first


def test_a_clone_that_is_behind_is_fast_forwarded_and_that_commit_is_what_runs(host: Host) -> None:
    other = host.root / "second"
    subprocess.run([GIT, "clone", "-q", str(host.origin), str(other)], env=host.env, check=True)
    for k, v in {
        "user.name": "Signer",
        "user.email": "signer@example.com",
        "gpg.format": "ssh",
        "user.signingkey": str(host.key),
    }.items():
        subprocess.run([GIT, "-C", str(other), "config", k, v], env=host.env, check=True)
    (other / "detections" / "orgs" / "acme" / "b.json").write_text("{}")
    subprocess.run([GIT, "-C", str(other), "add", "-A"], env=host.env, check=True)
    subprocess.run(
        [GIT, "-C", str(other), "commit", "-q", "-S", "-m", "more"], env=host.env, check=True
    )
    subprocess.run(
        [GIT, "-C", str(other), "push", "-q", "origin", "main"], env=host.env, check=True
    )
    new_head = subprocess.run(
        [GIT, "-C", str(other), "rev-parse", "HEAD"],
        env=host.env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    r = host.run(FAKE_RECORD=RECORD)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"commit={new_head}" in host.docker_calls()


def refused(host: Host, r: subprocess.CompletedProcess[str], text: str) -> None:
    assert r.returncode == 1, r.stdout + r.stderr
    assert text in r.stdout + r.stderr
    assert host.docker_calls() == ""  # the service was never run
    assert not (host.state / "rules-out").exists()  # and nothing was prepared for it


def test_a_head_commit_that_is_not_signed_is_refused(host: Host) -> None:
    host.commit("detections/orgs/acme/c.json", "{}", signed=False)
    host.push()
    refused(host, host.run(), "signature does not verify")


def test_a_commit_signed_by_a_key_the_host_does_not_trust_is_refused(host: Host) -> None:
    host.commit("detections/orgs/acme/c.json", "{}", key=host.other_key)
    host.push()
    refused(host, host.run(), "signature does not verify")


def test_a_clone_with_an_untracked_file_is_refused(host: Host) -> None:
    (host.repo / "detections" / "orgs" / "acme" / "stray.json").write_text("{}")
    refused(host, host.run(), "uncommitted or untracked files")


def test_a_clone_with_an_edited_tracked_file_is_refused(host: Host) -> None:
    (host.repo / "detections" / "orgs" / "acme" / "a.json").write_text('{"edited": true}')
    refused(host, host.run(), "uncommitted or untracked files")


def test_a_clone_with_a_local_commit_that_origin_does_not_have_is_refused(host: Host) -> None:
    host.commit("detections/orgs/acme/local.json", "{}")  # signed, but never pushed
    r = host.run()
    assert r.returncode == 1
    assert "not at origin/main" in r.stdout + r.stderr
    assert host.docker_calls() == ""


def test_a_diverged_clone_is_refused_and_left_alone(host: Host) -> None:
    host.commit("detections/orgs/acme/local.json", "{}")
    local = host.git("rev-parse", "HEAD")
    other = host.root / "second"
    subprocess.run([GIT, "clone", "-q", str(host.origin), str(other)], env=host.env, check=True)
    (other / "x.json").write_text("{}")
    for args in (
        ["config", "user.name", "T"],
        ["config", "user.email", "t@example.com"],
        ["add", "-A"],
        ["commit", "-q", "--no-gpg-sign", "-m", "x"],
        ["push", "-q", "origin", "main"],
    ):
        subprocess.run([GIT, "-C", str(other), *args], env=host.env, check=True)
    r = host.run()
    assert r.returncode == 1 and "cannot be fast-forwarded" in r.stdout + r.stderr
    assert host.git("rev-parse", "HEAD") == local  # never reset or merged
    assert host.docker_calls() == ""


def test_a_path_that_is_not_a_clone_is_refused(host: Host, tmp_path: Path) -> None:
    r = host.run(SOC_RULES_REPO=str(tmp_path / "nowhere"))
    refused(host, r, "is not a git clone")


def test_a_host_that_was_never_deployed_is_refused(host: Host) -> None:
    (host.state / "env" / "image.env").unlink()
    refused(host, host.run(), "run deploy.sh first")


def test_a_missing_settings_file_is_refused(host: Host) -> None:
    (host.state / "env" / "rules-lc.env").unlink()
    refused(host, host.run(), "run init-rules-lc.sh first")


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o400, 0o660])
def test_a_settings_file_that_is_not_mode_600_is_refused(host: Host, mode: int) -> None:
    path = host.state / "env" / "rules-lc.env"
    path.chmod(mode)
    refused(host, host.run(), "must be mode 600")
    assert stat.S_IMODE(path.stat().st_mode) == mode  # left as found


def test_it_will_not_run_as_a_normal_user_without_the_test_switch(host: Host) -> None:
    env = {**host.env, "SOC_STATE_DIR": str(host.state), "SOC_RULES_REPO": str(host.repo)}
    r = subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30, input=""
    )
    assert r.returncode == 1 and "run as root" in r.stderr
    assert host.docker_calls() == ""


def test_a_shell_variable_cannot_pick_the_profiles_or_the_commit(host: Host) -> None:
    head = host.git("rev-parse", "HEAD")
    r = host.run(
        FAKE_RECORD=RECORD,
        COMPOSE_PROFILES="db,worker,rules",
        SOC_RULES_COMMIT="f" * 40,
        SOC_RULES_SRC="/elsewhere",
    )
    assert r.returncode == 0
    calls = host.docker_calls()
    assert f"commit={head} src={host.repo}" in calls
    assert "f" * 40 not in calls and "/elsewhere" not in calls


def test_control_characters_in_the_record_never_reach_roots_terminal_or_the_log(
    host: Host,
) -> None:
    """The record is written inside the container; a compromised one must not be able to
    send terminal escape sequences to the operator."""
    r = host.run(FAKE_RECORD="rules-deploy \x1b]0;owned\x07 result=applied\x1b[2J")
    assert r.returncode == 0
    assert "\x1b" not in r.stdout and "\x07" not in r.stdout
    assert "\x1b" not in host.deploy_log() and "\x07" not in host.deploy_log()
    assert "rules-deploy ]0;owned result=applied[2J" in host.deploy_log()
