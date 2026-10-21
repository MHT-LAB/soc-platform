"""deploy.sh step 2b: the image must come from a commit that is on main.

These run the real script with fake cosign, docker and curl first on PATH
(SOC_TEST_BIN) and a throwaway git repo as the host's clone, so nothing touches
the network or the machine. Every refusal must happen before anything on the
host changes: no image.env, no compose call.
"""

import json
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "deploy.sh"
GIT = shutil.which("git") or "git"
BASH = shutil.which("bash") or "/bin/bash"

REPO_DIGEST = "sha256:" + "a" * 64
IMAGE = "ghcr.io/mht-lab/soc-api"

FAKE_COSIGN = """#!/usr/bin/env bash
echo "cosign $*" >> "$FAKE_LOG"
if [[ "$*" == *"--certificate-github-workflow-sha"* ]]; then exit "${FAKE_COSIGN_SHA_RC:-0}"; fi
if [[ "$1" == "verify-attestation" ]]; then exit 0; fi
if [[ "$1" == "verify" ]]; then
  printf '[{"critical":{"image":{"docker-manifest-digest":"%s"}}}]\\n' "$FAKE_DIGEST"
  exit 0
fi
exit 1
"""

FAKE_DOCKER = """#!/usr/bin/env bash
echo "docker $*" >> "$FAKE_LOG"
case "$1" in
  buildx) printf '%s\\n' "$FAKE_LABELS"; exit 0 ;;
  compose) if [[ "$*" == *" ps -q "* ]]; then echo cid; fi; exit 0 ;;
  inspect) echo imgid; exit 0 ;;
  image) printf '%s\\n' "$FAKE_REPODIGEST"; exit 0 ;;
esac
exit 0
"""

FAKE_CURL = """#!/usr/bin/env bash
if [[ "${*: -1}" == */version ]]; then echo '{"version":"test"}'; fi
exit 0
"""


def git(repo: Path, *args: str) -> str:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(repo.parent),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_COMMITTER_NAME": "t",
        "GIT_AUTHOR_EMAIL": "1+t@users.noreply.github.com",
        "GIT_COMMITTER_EMAIL": "1+t@users.noreply.github.com",
    }
    r = subprocess.run(  # noqa: S603 - fixed argv
        [GIT, "-C", str(repo), *args], env=env, capture_output=True, text=True, check=True
    )
    return r.stdout.strip()


def commit(repo: Path, name: str) -> str:
    (repo / name).write_text(name)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", name)
    return git(repo, "rev-parse", "HEAD")


class Host:
    """A fake deploy host: a clone of a repo whose main has two commits."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        origin = tmp / "origin.git"
        origin.mkdir()
        git(origin, "init", "-q", "--bare", "-b", "main")
        work = tmp / "work"
        work.mkdir()
        git(work, "init", "-q", "-b", "main")
        git(work, "remote", "add", "origin", str(origin))
        self.first = commit(work, "a")
        self.main = commit(work, "b")
        git(work, "push", "-q", "origin", "main")
        # A commit that exists but was never merged to main.
        git(work, "checkout", "-q", "-b", "feature")
        self.unmerged = commit(work, "unreviewed")
        git(work, "push", "-q", "origin", "feature")
        self.src = tmp / "src"
        git(tmp, "clone", "-q", str(origin), str(self.src))
        git(self.src, "fetch", "-q", "origin", "feature")  # object is present locally

        self.state = tmp / "state"
        (self.state / "env").mkdir(parents=True)
        (self.state / "env" / "console.env").write_text("SOC_CONSOLE_USERS=a@example.com\n")
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for name, body in (("cosign", FAKE_COSIGN), ("docker", FAKE_DOCKER), ("curl", FAKE_CURL)):
            path = self.bin / name
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.log = tmp / "fake.log"
        self.log.write_text("")

    @staticmethod
    def labels(revision: str | None) -> str:
        return json.dumps(
            {} if revision is None else {"org.opencontainers.image.revision": revision}
        )

    def run(
        self, labels: str, cosign_sha_rc: int = 0, source: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.tmp),
            "SOC_STATE_DIR": str(self.state),
            "SOC_TEST_BIN": str(self.bin),
            "SOC_SOURCE_DIR": str(source or self.src),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "FAKE_LOG": str(self.log),
            "FAKE_DIGEST": REPO_DIGEST,
            "FAKE_REPODIGEST": f"{IMAGE}@{REPO_DIGEST}",
            "FAKE_LABELS": labels,
            "FAKE_COSIGN_SHA_RC": str(cosign_sha_rc),
        }
        return subprocess.run(  # noqa: S603 - fixed argv, our own script
            [BASH, str(DEPLOY), "edge"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    @property
    def changed_the_host(self) -> bool:
        wrote = (self.state / "env" / "image.env").exists()
        started = "docker compose" in self.log.read_text()
        return wrote or started


def test_image_from_a_commit_on_main_is_deployed(tmp_path: Path) -> None:
    host = Host(tmp_path)
    r = host.run(Host.labels(host.main))
    assert r.returncode == 0, r.stdout
    assert f"source commit {host.main} is on main" in r.stdout
    assert "deployed" in r.stdout
    assert (host.state / "env" / "image.env").exists()
    # cosign was asked to bind the signature to exactly that commit.
    assert f"--certificate-github-workflow-sha {host.main}" in host.log.read_text()


def test_an_older_commit_that_is_still_on_main_is_deployed(tmp_path: Path) -> None:
    host = Host(tmp_path)
    assert host.run(Host.labels(host.first)).returncode == 0


REFUSALS = [
    ("unmerged", "not on main"),
    ("unknown-object", "not on main"),
    ("no-label", "no valid source commit label"),
    ("not-hex", "no valid source commit label"),
    ("short-sha", "no valid source commit label"),
    ("labels-null", "could not read"),
]


@pytest.mark.parametrize(("case", "message"), REFUSALS)
def test_refused_before_anything_changes(tmp_path: Path, case: str, message: str) -> None:
    host = Host(tmp_path)
    labels = {
        "unmerged": Host.labels(host.unmerged),
        "unknown-object": Host.labels("1" * 40),
        "no-label": Host.labels(None),
        "not-hex": Host.labels("main"),
        "short-sha": Host.labels(host.main[:12]),
        "labels-null": "null",
    }[case]
    r = host.run(labels)
    assert r.returncode == 1, r.stdout
    assert message in r.stdout
    assert not host.changed_the_host


def test_a_forged_label_is_refused_when_cosign_rejects_the_commit(tmp_path: Path) -> None:
    """The label names a commit that is on main, but the signature is for another."""
    host = Host(tmp_path)
    r = host.run(Host.labels(host.main), cosign_sha_rc=1)
    assert r.returncode == 1
    assert "does not name commit" in r.stdout
    assert not host.changed_the_host


def test_a_failed_fetch_is_a_refusal_not_a_pass(tmp_path: Path) -> None:
    host = Host(tmp_path)
    broken = tmp_path / "broken"
    broken.mkdir()
    git(broken, "init", "-q", "-b", "main")
    git(broken, "remote", "add", "origin", str(tmp_path / "does-not-exist.git"))
    r = host.run(Host.labels(host.main), source=broken)
    assert r.returncode == 1
    assert "could not fetch" in r.stdout
    assert not host.changed_the_host


def test_a_source_dir_that_is_not_a_repo_is_a_refusal(tmp_path: Path) -> None:
    host = Host(tmp_path)
    nope = tmp_path / "nope"
    nope.mkdir()
    r = host.run(Host.labels(host.main), source=nope)
    assert r.returncode == 1 and "could not fetch" in r.stdout
    assert not host.changed_the_host


def test_the_label_text_is_never_echoed(tmp_path: Path) -> None:
    host = Host(tmp_path)
    r = host.run(Host.labels("evil-injected-text"))
    assert r.returncode == 1
    assert "evil-injected-text" not in r.stdout + r.stderr


def test_the_test_hook_is_refused_for_root_before_path_changes() -> None:
    """The real deploy runs as root; the PATH hook must be dead there. (Tests never
    run as root, so this checks the guard is present and comes first.)"""
    text = DEPLOY.read_text()
    guard = text.index('if [[ -n "${SOC_TEST_BIN:-}" && "$EUID" -eq 0 ]]')
    path = text.index("export PATH=")
    assert guard < path
    assert "SOC_TEST_BIN=" not in text  # the script never sets it itself
