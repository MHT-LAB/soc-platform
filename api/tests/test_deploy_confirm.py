"""deploy.sh step 2d: show the commits that are about to run here, and ask for a typed yes.

Same fake cosign/docker/curl and throwaway git clone as the source-check tests. The answer
is read from the terminal; the tests point it at a file with SOC_TEST_TTY (refused for root,
like SOC_TEST_BIN) or run with no controlling terminal at all. Every "no" must leave the host
as it was: image.env untouched, no compose call.
"""

import re
from pathlib import Path

import pytest
from test_deploy_db import OLD_IMAGE, DbHost
from test_deploy_prepare import PrepHost
from test_deploy_source_check import DEPLOY, Host, git

NO_PROMPT = {"SOC_DEPLOY_ASSUME_YES": ""}
NEW_COMMIT_LINE = re.compile(r"^  [0-9a-f]{4,} (.*)$", re.MULTILINE)


def advance(host: Host, *subjects: str) -> list[str]:
    """Merge new commits to main (origin) and bring the host's clone up to date."""
    work = host.tmp / "work"
    git(work, "checkout", "-q", "main")
    shas = []
    for subject in subjects:
        git(work, "commit", "-q", "--allow-empty", "-m", subject)
        shas.append(git(work, "rev-parse", "HEAD"))
    git(work, "push", "-q", "origin", "main")
    git(host.src, "pull", "-q", "--ff-only", "origin", "main")
    host.main = shas[-1]
    return shas


def fresh_host(tmp: Path, **kw: bool) -> DbHost:
    host = DbHost(tmp, **kw)
    (host.state / "pgdata").mkdir()
    return host


def answer(tmp: Path, text: str) -> dict[str, str]:
    tty = tmp / "tty"
    tty.write_text(text)
    return {**NO_PROMPT, "SOC_TEST_TTY": str(tty)}


def listed(stdout: str) -> list[str]:
    return NEW_COMMIT_LINE.findall(stdout)


def unchanged(host: DbHost) -> bool:
    return (
        host.image_env.read_text().startswith(f"SOC_API_IMAGE={OLD_IMAGE}\n") and not host.calls()
    )


def running_old(
    tmp_path: Path, old: str | None = None, **kw: bool
) -> tuple[DbHost, dict[str, str]]:
    host = fresh_host(tmp_path, **kw)
    host.with_previous_image()
    return host, {"FAKE_OLD_REV": old if old is not None else host.first}


def test_it_lists_the_commits_since_the_running_image_and_asks(tmp_path: Path) -> None:
    host, env = running_old(tmp_path)
    advance(host, "add the thing", "fix the other thing")
    # Only what was merged after the running image's commit: the new two and the
    # commit "b" that followed it, not the commit the image was built from.
    r = host.deploy(**env, **answer(tmp_path, "yes\n"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert listed(r.stdout) == ["fix the other thing", "add the thing", "b"]
    assert "Type yes to deploy" in r.stdout
    assert "confirmed by the operator" in r.stdout
    assert host.image_env.read_text().startswith("SOC_API_IMAGE=ghcr.io/mht-lab/soc-api@sha256:a")


@pytest.mark.parametrize("typed", ["no\n", "\n", "", "y\n", "YES\n", "yes please\n", " yes\n"])
def test_anything_but_yes_leaves_the_host_unchanged(tmp_path: Path, typed: str) -> None:
    host, env = running_old(tmp_path)
    r = host.deploy(**env, **answer(tmp_path, typed))
    assert r.returncode == 1, r.stdout
    assert "declined at the confirmation" in r.stdout
    assert unchanged(host)


def test_there_is_no_answer_without_a_terminal_and_stdin_cannot_give_one(tmp_path: Path) -> None:
    host, env = running_old(tmp_path)
    r = host.deploy(detached=True, stdin="yes\n", **env, **NO_PROMPT)
    assert r.returncode == 1, r.stdout
    assert "no terminal to confirm on" in r.stdout
    assert unchanged(host)


def test_a_first_deploy_shows_the_last_ten_commits_and_asks(tmp_path: Path) -> None:
    host = fresh_host(tmp_path)  # no image.env: nothing is running
    advance(host, *[f"change {i}" for i in range(12)])
    r = host.deploy(**answer(tmp_path, "yes\n"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "a first deploy" in r.stdout
    lines = listed(r.stdout)
    assert len(lines) == 10 and lines[0] == "change 11" and lines[-1] == "change 2"


def test_a_first_deploy_can_be_declined(tmp_path: Path) -> None:
    host = fresh_host(tmp_path)
    r = host.deploy(**answer(tmp_path, "no\n"))
    assert r.returncode == 1
    assert not host.image_env.exists() and not host.calls()


def test_an_unknown_running_commit_is_treated_like_a_first_deploy(tmp_path: Path) -> None:
    host, env = running_old(tmp_path, old="1" * 40)  # not in this clone
    r = host.deploy(**env, **answer(tmp_path, "no\n"))
    assert "a first deploy" in r.stdout and "last 10 commits" in r.stdout
    assert unchanged(host)


def test_a_long_list_is_capped_at_fifty(tmp_path: Path) -> None:
    host, env = running_old(tmp_path)
    advance(host, *[f"change {i}" for i in range(55)])
    r = host.deploy(**env, **answer(tmp_path, "no\n"))
    assert len(listed(r.stdout)) == 50
    assert "56" in r.stdout and "and 6 more" in r.stdout  # 55 new plus "b"
    assert unchanged(host)


def test_the_same_commit_says_so(tmp_path: Path) -> None:
    host, env = running_old(tmp_path)
    env["FAKE_OLD_REV"] = host.main
    r = host.deploy(**env, **answer(tmp_path, "yes\n"))
    assert r.returncode == 0
    assert "built from the same commit" in r.stdout and listed(r.stdout) == []


def test_an_older_image_is_called_out_as_a_step_back(tmp_path: Path) -> None:
    host, env = running_old(tmp_path)
    env["FAKE_OLD_REV"] = host.main
    r = host.deploy(**env, FAKE_LABELS=Host.labels(host.first), **answer(tmp_path, "no\n"))
    assert "OLDER than the running one" in r.stdout
    assert listed(r.stdout) == ["b"]
    assert unchanged(host)


def test_commit_text_cannot_inject_terminal_control_characters(tmp_path: Path) -> None:
    host, env = running_old(tmp_path)
    advance(host, "evil\x1b[2J\x07text " + "x" * 300)
    r = host.deploy(**env, **answer(tmp_path, "no\n"))
    assert "\x1b" not in r.stdout and "\x07" not in r.stdout
    assert all(len(line) <= 120 for line in r.stdout.splitlines() if "evil" in line)
    assert "evil[2Jtext" in r.stdout


def test_every_signature_and_source_check_comes_before_the_question(tmp_path: Path) -> None:
    host, env = running_old(tmp_path)
    r = host.deploy(**env, FAKE_LABELS=Host.labels(host.unmerged), **answer(tmp_path, "yes\n"))
    assert r.returncode == 1 and "not on main" in r.stdout
    assert "Type yes" not in r.stdout
    assert unchanged(host)


def test_a_cosign_refusal_comes_before_the_question(tmp_path: Path) -> None:
    host, env = running_old(tmp_path)
    r = host.deploy(**env, FAKE_COSIGN_SHA_RC="1", **answer(tmp_path, "yes\n"))
    assert r.returncode == 1 and "Type yes" not in r.stdout
    assert unchanged(host)


# ---- --prepare asks too ----


def test_prepare_asks_and_a_no_writes_nothing(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    r = host.prepare(**answer(tmp_path, "no\n"))
    assert r.returncode == 1, r.stdout
    assert "Type yes to prepare" in r.stdout
    assert not host.image_env.exists()
    assert not any(" pull " in c for c in host.all_calls())


def test_prepare_with_a_yes_pulls(tmp_path: Path) -> None:
    host = PrepHost(tmp_path)
    r = host.prepare(**answer(tmp_path, "yes\n"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert host.image_env.exists()


# ---- the test-only switches ----


def test_the_skip_switches_are_refused_for_root_before_path_changes() -> None:
    """The real deploy runs as root; neither switch may work there. (Tests never run as
    root, so this checks the guard is present, names both, and comes first.)"""
    text = DEPLOY.read_text()
    guard = text.index('"$EUID" -eq 0 ]]; then\n  echo "FAILED: SOC_DEPLOY_ASSUME_YES')
    assert 'SOC_DEPLOY_ASSUME_YES:-}" || -n "${SOC_TEST_TTY:-}"' in text
    assert guard < text.index("export PATH=")
    assert "SOC_DEPLOY_ASSUME_YES=" not in text and "SOC_TEST_TTY=" not in text.replace(
        'tty="${SOC_TEST_TTY:-/dev/tty}"', ""
    )
