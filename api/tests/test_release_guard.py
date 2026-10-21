"""The release workflow must not publish a tag from a commit that is not on main,
and must scan the pushed image before signing it."""

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "scripts" / "check-tag-on-main.sh"
RELEASE = (ROOT / ".github" / "workflows" / "release.yml").read_text()
GIT = shutil.which("git") or "git"
BASH = shutil.which("bash") or "/bin/bash"


def git(repo: Path, *args: str) -> str:
    r = subprocess.run(  # noqa: S603 - fixed argv
        [GIT, "-C", str(repo), "-c", "commit.gpgsign=false", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return r.stdout.strip()


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "1+t@users.noreply.github.com")
    git(repo, "config", "user.name", "t")
    return repo


def commit(repo: Path, name: str) -> str:
    (repo / name).write_text(name)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", name)
    return git(repo, "rev-parse", "HEAD")


def guard(repo: Path, sha: str, ref: str = "main") -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, our own script
        [BASH, str(GUARD), sha, ref], cwd=repo, capture_output=True, text=True, check=False
    )


def test_commit_on_main_may_be_released(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    sha = commit(repo, "a")
    assert guard(repo, sha).returncode == 0


def test_older_commit_still_on_main_may_be_released(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    first = commit(repo, "a")
    commit(repo, "b")
    assert guard(repo, first).returncode == 0


def test_commit_on_an_unmerged_branch_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    commit(repo, "a")
    git(repo, "checkout", "-q", "-b", "feature")
    side = commit(repo, "unreviewed")
    git(repo, "checkout", "-q", "main")
    r = guard(repo, side)
    assert r.returncode == 1 and "not on main" in r.stdout


def test_missing_main_ref_is_a_failure_not_a_pass(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    sha = commit(repo, "a")
    r = guard(repo, sha, ref="origin/main")
    assert r.returncode == 1 and "fetch-depth" in r.stdout


def test_unknown_commit_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    commit(repo, "a")
    assert guard(repo, "0" * 40).returncode != 0


def test_release_workflow_order_guard_then_scan_before_signing() -> None:
    """Guard before any build; scan after the push and before sign/attest."""
    guard_at = RELEASE.index("check-tag-on-main.sh")
    login_at = RELEASE.index("docker/login-action")
    build_at = RELEASE.index("docker/build-push-action")
    scan_at = RELEASE.index("aquasecurity/trivy-action")
    sign_at = RELEASE.index("cosign sign")
    assert guard_at < login_at < build_at < scan_at < sign_at
    assert "if: startsWith(github.ref, 'refs/tags/')" in RELEASE
    assert "fetch-depth: 0" in RELEASE
    # The scan targets the pushed digest, and a finding fails the job.
    scan_block = RELEASE[scan_at : RELEASE.index("SBOM (syft")]
    assert "steps.build.outputs.digest" in scan_block
    assert 'exit-code: "1"' in scan_block
