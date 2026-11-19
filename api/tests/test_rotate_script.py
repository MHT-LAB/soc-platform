"""deploy/rotate.sh: the host side of key rotation planning.

These run the real script with a fake docker first on PATH (SOC_TEST_BIN, refused for root) and a
throwaway git repository with ssh-signed commits as the register clone, so nothing touches the
network or the machine. Every refusal must happen before the service is run.
"""

# ruff: noqa: S603 - every subprocess here runs a fixed argv built by the test itself
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "rotate.sh"
BASH = shutil.which("bash") or "/bin/bash"
GIT = shutil.which("git") or "git"
SSH_KEYGEN = shutil.which("ssh-keygen")

pytestmark = [
    pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root user (tests mode)"),
    pytest.mark.skipif(SSH_KEYGEN is None, reason="needs ssh-keygen to sign test commits"),
]

FAKE_DOCKER = """#!/usr/bin/env bash
echo "docker $*" >> "$FAKE_LOG"
echo "commit=${SOC_ROTATE_COMMIT:-} src=${SOC_KEYS_SRC:-}" >> "$FAKE_LOG"
echo "profiles=${COMPOSE_PROFILES:-}" >> "$FAKE_LOG"
if [[ "$*" == *" run "* && "$*" == *" rotate"* ]]; then
  if [[ -n "${FAKE_RECORD:-}" ]]; then
    printf '%s\\n' "$FAKE_RECORD" > "$SOC_STATE_DIR/rotate/record.txt"
  fi
  exit "${FAKE_RC:-0}"
fi
exit 0
"""

RECORD = (
    "rotate 2026-11-18T09:00:00Z plan commit=0123456789ab plan=0123456789ab "
    "overdue=0 no_record=2 result=attention run=0123456789ab"
)


class Host:
    """A host's state folder, a register clone with a remote, and a signing key."""

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
            # git and ssh-keygen need a temporary folder to sign; a clean environment has none.
            **({"TMPDIR": os.environ["TMPDIR"]} if "TMPDIR" in os.environ else {}),
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
        self.commit("keys/example-key.toml", 'id = "example-key"\n')
        self.git("push", "-q", "origin", "main")
        self.git("branch", "--set-upstream-to=origin/main", "main")
        (self.state / "env").mkdir(parents=True)
        (self.state / "env" / "image.env").write_text("SOC_API_IMAGE=x\n")

    def _run(self, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
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

    def run(self, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {
            **self.env,
            "SOC_STATE_DIR": str(self.state),
            "SOC_KEYS_REPO": str(self.repo),
            "SOC_TEST_BIN": str(self.bin),
            "FAKE_LOG": str(self.log),
            **extra,
        }
        return subprocess.run(
            [BASH, str(SCRIPT), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            input="",
        )

    def docker_calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def rotate_log(self) -> str:
        path = self.state / "rotate.log"
        return path.read_text() if path.exists() else ""


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def test_the_script_is_executable() -> None:
    assert os.access(SCRIPT, os.X_OK)


def test_a_clean_signed_clone_runs_the_service_with_that_commit(host: Host) -> None:
    head = host.git("rev-parse", "HEAD")
    r = host.run(FAKE_RECORD=RECORD)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = host.docker_calls()
    assert "--profile rotate run --rm rotate" in calls
    assert " -T " not in calls  # a person is at the terminal: no -T
    assert f"commit={head} src={host.repo}" in calls
    assert "profiles=" in calls and "profiles=rotate" not in calls.replace("--profile rotate", "")
    assert RECORD in host.rotate_log() and RECORD in r.stdout
    assert "signed by" in host.rotate_log()


def test_the_plan_for_the_timer_has_no_terminal_and_passes_its_arguments(host: Host) -> None:
    r = host.run("--plan", "--quiet", FAKE_RECORD=RECORD)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "--profile rotate run --rm -T rotate --plan --quiet" in host.docker_calls()


def test_a_record_passes_its_id_and_dates(host: Host) -> None:
    r = host.run("--record", "n8n-customer", "--date", "2026-10-24", "--due", "2026-12-15")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "rotate --record n8n-customer --date 2026-10-24 --due 2026-12-15" in host.docker_calls()


@pytest.mark.parametrize(
    "args",
    [
        ["--apply"],
        ["--plan", "--apply"],
        ["--plan", "extra"],
        ["--quiet"],
        ["--record"],
        ["--record", "Bad Id"],
        ["--record", "x; rm -rf /"],
        ["--record", "$(id)"],
        ["--record", "a-key", "--date", "yesterday"],
        ["--record", "a-key", "--date", "2026-11-14\n"],
        ["--record", "a-key", "--when", "2026-11-14"],
        ["--record", "a-key", "--date"],
        ["anything"],
    ],
)
def test_arguments_the_script_does_not_know_are_refused_before_anything_runs(
    host: Host, args: list[str]
) -> None:
    r = host.run(*args)
    assert r.returncode == 2 and "usage" in r.stderr
    assert host.docker_calls() == ""
    assert not (host.state / "rotate").exists()
    assert host.rotate_log() == ""


def test_the_services_exit_code_is_the_scripts_and_its_record_is_still_kept(host: Host) -> None:
    for rc in (1, 2, 3, 4):
        r = host.run("--plan", FAKE_RECORD=RECORD, FAKE_RC=str(rc))
        assert r.returncode == rc
    assert host.rotate_log().count(RECORD) == 4


def test_no_record_is_reported_not_invented(host: Host) -> None:
    r = host.run("--plan", FAKE_RC="1")
    assert r.returncode == 1
    assert "no record was written" in host.rotate_log()


def test_a_stale_record_from_an_earlier_run_is_never_reused(host: Host) -> None:
    host.run("--plan", FAKE_RECORD=RECORD)
    first = host.rotate_log().count(RECORD)
    host.run("--plan")  # this time the service writes nothing
    assert host.rotate_log().count(RECORD) == first


def test_the_state_folder_is_private(host: Host) -> None:
    host.run("--plan", FAKE_RECORD=RECORD)
    assert stat.S_IMODE((host.state / "rotate").stat().st_mode) == 0o700


def refused(host: Host, r: subprocess.CompletedProcess[str], text: str) -> None:
    assert r.returncode == 1, r.stdout + r.stderr
    assert text in r.stdout + r.stderr
    assert host.docker_calls() == ""  # the service was never run
    assert not (host.state / "rotate").exists()  # and nothing was prepared for it


def test_a_head_commit_that_is_not_signed_is_refused(host: Host) -> None:
    host.commit("keys/other-key.toml", 'id = "other-key"\n', signed=False)
    host.push()
    refused(host, host.run("--plan"), "signature does not verify")


def test_a_commit_signed_by_a_key_the_host_does_not_trust_is_refused(host: Host) -> None:
    host.commit("keys/other-key.toml", 'id = "other-key"\n', key=host.other_key)
    host.push()
    refused(host, host.run("--plan"), "signature does not verify")


def test_a_clone_with_an_untracked_file_is_refused(host: Host) -> None:
    (host.repo / "keys" / "stray.toml").write_text("x")
    refused(host, host.run("--plan"), "uncommitted or untracked files")


def test_a_clone_with_an_edited_tracked_file_is_refused(host: Host) -> None:
    (host.repo / "keys" / "example-key.toml").write_text('id = "edited"\n')
    refused(host, host.run("--plan"), "uncommitted or untracked files")


def test_a_clone_with_a_local_commit_that_origin_does_not_have_is_refused(host: Host) -> None:
    host.commit("keys/local-key.toml", 'id = "local-key"\n')  # signed, but never pushed
    r = host.run("--plan")
    assert r.returncode == 1 and "not at origin/main" in r.stdout + r.stderr
    assert host.docker_calls() == ""


def test_a_path_that_is_not_a_clone_is_refused(host: Host, tmp_path: Path) -> None:
    refused(host, host.run("--plan", SOC_KEYS_REPO=str(tmp_path / "nowhere")), "is not a git clone")


def test_a_clone_without_a_keys_folder_is_refused(host: Host) -> None:
    host.git("rm", "-q", "-r", "keys")
    host._run(GIT, "-C", str(host.repo), "commit", "-q", "-S", "-m", "remove keys")
    host.push()
    refused(host, host.run("--plan"), "keys is missing")


def test_a_host_that_was_never_deployed_is_refused(host: Host) -> None:
    (host.state / "env" / "image.env").unlink()
    refused(host, host.run("--plan"), "run deploy.sh first")


def test_it_will_not_run_as_a_normal_user_without_the_test_switch(host: Host) -> None:
    env = {**host.env, "SOC_STATE_DIR": str(host.state), "SOC_KEYS_REPO": str(host.repo)}
    r = subprocess.run(
        [BASH, str(SCRIPT), "--plan"], env=env, capture_output=True, text=True, timeout=30, input=""
    )
    assert r.returncode == 1 and "run as root" in r.stderr
    assert host.docker_calls() == ""


def test_a_shell_variable_cannot_pick_the_profiles_or_the_commit(host: Host) -> None:
    head = host.git("rev-parse", "HEAD")
    r = host.run(
        "--plan",
        FAKE_RECORD=RECORD,
        COMPOSE_PROFILES="db,worker,rotate",
        SOC_ROTATE_COMMIT="f" * 40,
        SOC_KEYS_SRC="/elsewhere",
    )
    assert r.returncode == 0
    calls = host.docker_calls()
    assert f"commit={head} src={host.repo}" in calls
    assert "f" * 40 not in calls and "/elsewhere" not in calls


def test_control_characters_in_the_record_never_reach_roots_terminal_or_the_log(host: Host) -> None:
    """The record is written inside the container; a compromised one must not be able to
    send terminal escape sequences to the operator."""
    r = host.run("--plan", FAKE_RECORD="rotate \x1b]0;owned\x07 result=ok\x1b[2J")
    assert r.returncode == 0
    assert "\x1b" not in r.stdout and "\x07" not in r.stdout
    assert "\x1b" not in host.rotate_log() and "\x07" not in host.rotate_log()
    assert "rotate ]0;owned result=ok[2J" in host.rotate_log()
