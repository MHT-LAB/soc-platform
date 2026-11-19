"""The rotate command (soc_api.rotate.cli): plan, approve, record. No key changes anywhere."""

import io
import json
import stat
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from rotate_support import COMMIT, key_text, make_register

from soc_api.rotate import state as st
from soc_api.rotate.cli import (
    ATTENTION,
    DECLINED,
    FAILED,
    OK,
    REFUSED,
    Args,
    Config,
    ConfigError,
    UsageError,
    main,
    parse_args,
    run,
)

NOW = datetime(2026, 11, 18, 15, 0, tzinfo=UTC)  # 10:00 in New York, so the local day is the 18th
SECRET = "VALUE-that-must-never-be-printed-9f8e7d6c5b4a"


class Env:
    """A register, a state folder, a fake clock and a recorded conversation."""

    def __init__(self, root: Path, files: dict[str, str]) -> None:
        self.keys = make_register(root, files)
        self.state_dir = root / "state"
        self.state_dir.mkdir()
        self.cfg = Config(self.keys, self.state_dir, COMMIT)
        self.said: list[str] = []
        self.asked: list[str] = []
        self.moment = NOW

    def go(self, args: Args, answer: bool = True) -> int:
        def confirm(prompt: str) -> bool:
            self.asked.append(prompt)
            return answer

        return run(self.cfg, args, confirm, self.said.append, lambda: self.moment)

    def text(self) -> str:
        return "\n".join(self.said)

    def state(self) -> st.State:
        return st.load(self.state_dir / "state.json")

    def everything_written(self) -> str:
        parts = [self.text()]
        parts += [p.read_text() for p in self.state_dir.iterdir()]
        return "\n".join(parts)


def two_keys() -> dict[str, str]:
    return {
        "auto-key": key_text("auto-key", method="automatic"),
        "hand-key": key_text("hand-key", check="Send a test"),
        "age-key": key_text("age-key", method="none"),
    }


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path, two_keys())


# ---- arguments and settings ----


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([], Args("approve")),
        (["--plan"], Args("plan")),
        (["--plan", "--quiet"], Args("plan", quiet=True)),
        (["--record", "a-key"], Args("record", key_id="a-key")),
        (
            ["--record", "a-key", "--date", "2026-11-14", "--due", "2026-12-15"],
            Args("record", key_id="a-key", on=date(2026, 11, 14), due=date(2026, 12, 15)),
        ),
    ],
)
def test_good_arguments(argv: list[str], expected: Args) -> None:
    assert parse_args(argv) == expected


@pytest.mark.parametrize(
    "argv",
    [
        ["--quiet"],
        ["--plan", "--apply"],
        ["--plan", "--quiet", "x"],
        ["--record"],
        ["--record", "Bad Id"],
        ["--record", "a-key", "--date"],
        ["--record", "a-key", "--date", "yesterday"],
        ["--record", "a-key", "--date", "2026-02-30"],
        ["--record", "a-key", "--date", "2026-11-14", "--date", "2026-11-15"],
        ["--record", "a-key", "--when", "2026-11-14"],
        ["--apply", "abc"],
        ["a-key"],
    ],
)
def test_wrong_arguments_are_refused(argv: list[str]) -> None:
    with pytest.raises(UsageError):
        parse_args(argv)


def test_settings_name_the_problem_never_a_value() -> None:
    with pytest.raises(ConfigError, match="SOC_ROTATE_COMMIT"):
        Config.from_env({})
    with pytest.raises(ConfigError, match="SOC_ROTATE_COMMIT"):
        Config.from_env({"SOC_ROTATE_COMMIT": SECRET})
    cfg = Config.from_env({"SOC_ROTATE_COMMIT": COMMIT})
    assert (str(cfg.keys_dir), str(cfg.state_dir)) == ("/keys", "/state")


def test_main_refuses_without_its_settings(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SOC_ROTATE_COMMIT", raising=False)
    assert main(["--plan"]) == REFUSED
    assert "SOC_ROTATE_COMMIT" in capsys.readouterr().out
    assert main(["--bogus"]) == REFUSED


# ---- the plan (what the daily timer runs) ----


def test_a_plan_with_no_records_asks_for_attention_and_writes_counts_only(env: Env) -> None:
    assert env.go(Args("plan")) == ATTENTION
    assert env.asked == []
    status = json.loads((env.state_dir / "status.json").read_text())
    assert status["counts"]["no_record"] == 2 and status["session"] == "2026-12-07"
    raw = (env.state_dir / "status.json").read_text()
    assert "auto-key" not in raw and "hand-key" not in raw  # counts, never names
    assert stat.S_IMODE((env.state_dir / "status.json").stat().st_mode) == 0o600
    record = (env.state_dir / "record.txt").read_text().strip()
    assert record.startswith("rotate 2026-11-18T15:00:00Z plan ") and "result=attention" in record
    assert not (env.state_dir / "state.json").exists()  # a plan never writes the state


def test_a_quiet_plan_prints_one_summary_line_and_the_record(env: Env) -> None:
    env.go(Args("plan", quiet=True))
    assert env.said[0].startswith("plan: overdue=0 no_record=2")
    assert len(env.said) == 2 and env.said[1].startswith("rotate ")


def test_when_everything_is_recent_the_plan_exits_clean(env: Env) -> None:
    st.save(
        env.state_dir / "state.json",
        st.State(
            keys={
                "auto-key": st.KeyState(date(2026, 11, 14), "recorded"),
                "hand-key": st.KeyState(date(2026, 11, 14), "recorded"),
            }
        ),
    )
    assert env.go(Args("plan")) == OK
    assert "result=ok" in env.text()


def test_an_old_key_still_live_asks_for_attention(env: Env) -> None:
    st.save(
        env.state_dir / "state.json",
        st.State(
            keys={
                "auto-key": st.KeyState(date(2026, 11, 14), "failed", revoke_pending=True),
                "hand-key": st.KeyState(date(2026, 11, 14), "recorded"),
            }
        ),
    )
    assert env.go(Args("plan")) == ATTENTION
    assert "REVOKE-PENDING" in env.text()


def test_a_register_with_a_problem_is_refused_before_anything_is_written(tmp_path: Path) -> None:
    e = Env(tmp_path, {"good": key_text("good"), "bad": key_text("wrong-id")})
    assert e.go(Args("plan")) == REFUSED
    assert "id must equal the file name" in e.text() and "nothing was changed" in e.text()
    assert sorted(p.name for p in e.state_dir.iterdir()) == ["record.txt"]
    assert "refused-register" in (e.state_dir / "record.txt").read_text()


def test_a_state_file_that_is_not_ours_is_refused_and_left_alone(env: Env) -> None:
    (env.state_dir / "state.json").write_text("{broken")
    for args in (Args("plan"), Args("approve"), Args("record", key_id="hand-key")):
        assert env.go(args) == REFUSED
    assert (env.state_dir / "state.json").read_text() == "{broken"
    assert env.asked == []


# ---- approve ----


def test_approving_records_this_exact_plan_for_thirty_minutes(env: Env) -> None:
    assert env.go(Args("approve")) == OK
    assert len(env.asked) == 1 and "30 minutes" in env.asked[0]
    state = env.state()
    assert state.approval is not None and state.approval.commit == COMMIT
    plan_hash = state.approval.plan_hash
    assert f"plan={plan_hash}" in (env.state_dir / "record.txt").read_text()
    assert st.approval_problem(state, plan_hash, COMMIT, NOW + timedelta(minutes=29)) is None
    assert st.approval_problem(state, plan_hash, COMMIT, NOW + timedelta(minutes=31)) == "expired"
    assert "makes no change to any key" in env.text()


def test_not_typing_yes_changes_nothing(env: Env) -> None:
    assert env.go(Args("approve"), answer=False) == DECLINED
    assert not (env.state_dir / "state.json").exists()
    assert "declined" in (env.state_dir / "record.txt").read_text()


def test_with_nothing_automatic_due_nothing_is_asked(tmp_path: Path) -> None:
    e = Env(tmp_path, {"hand-key": key_text("hand-key")})
    assert e.go(Args("approve")) == OK
    assert e.asked == [] and "nothing to approve" in e.text()
    assert not (e.state_dir / "state.json").exists()


def test_a_later_change_makes_the_old_approval_useless(env: Env) -> None:
    env.go(Args("approve"))
    approved = env.state().approval
    assert approved is not None
    # the old key gets recorded as rotated: the plan the approval covered no longer exists
    env.go(Args("record", key_id="auto-key", on=date(2026, 11, 18)))
    new_plan = st.approval_problem(env.state(), "0" * 12, COMMIT, NOW)
    assert new_plan == "plan_changed"


def test_no_terminal_means_no(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from soc_api.rotate.cli import tty_confirm

    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))  # piped input is not a terminal
    assert tty_confirm("Type yes: ") is False
    assert "no terminal" in capsys.readouterr().out


# ---- record (a person did a key by hand) ----


def test_recording_a_manual_rotation(env: Env) -> None:
    assert env.go(Args("record", key_id="hand-key", on=date(2026, 11, 14))) == OK
    key = env.state().keys["hand-key"]
    assert (key.last_rotated, key.outcome, key.revoke_pending) == (
        date(2026, 11, 14),
        "recorded",
        False,
    )
    record = (env.state_dir / "record.txt").read_text().strip()
    assert "record id=hand-key date=2026-11-14 next_due=2027-02-12 result=recorded" in record
    assert "makes no vendor call" in env.text()
    status = json.loads((env.state_dir / "status.json").read_text())
    assert status["counts"]["no_record"] == 1  # the other key still has none


def test_the_date_defaults_to_today_in_new_york_not_utc(env: Env) -> None:
    env.moment = datetime(2026, 11, 19, 2, 30, tzinfo=UTC)  # 21:30 on the 18th in New York
    assert env.go(Args("record", key_id="hand-key")) == OK
    assert env.state().keys["hand-key"].last_rotated == date(2026, 11, 18)


def test_a_due_date_set_by_a_person_is_kept(env: Env) -> None:
    env.go(Args("record", key_id="hand-key", on=date(2026, 10, 24), due=date(2026, 12, 15)))
    assert env.state().keys["hand-key"].due_override == date(2026, 12, 15)
    assert "next_due=2026-12-15" in (env.state_dir / "record.txt").read_text()


def test_recording_again_replaces_the_entry_and_clears_the_old_key_flag(env: Env) -> None:
    st.save(
        env.state_dir / "state.json",
        st.State(keys={"auto-key": st.KeyState(date(2026, 9, 1), "failed", revoke_pending=True)}),
    )
    env.go(Args("record", key_id="auto-key", on=date(2026, 11, 18)))
    key = env.state().keys["auto-key"]
    assert key.last_rotated == date(2026, 11, 18) and key.revoke_pending is False


@pytest.mark.parametrize(
    "args",
    [
        Args("record", key_id="no-such-key"),
        Args("record", key_id="age-key"),  # replaced on exposure only: not tracked
        Args("record", key_id="hand-key", on=date(2026, 11, 19)),  # tomorrow
        Args("record", key_id="hand-key", on=date(2026, 11, 14), due=date(2026, 11, 13)),
    ],
)
def test_a_record_that_makes_no_sense_is_refused(env: Env, args: Args) -> None:
    assert env.go(args) == REFUSED
    assert env.asked == [] and not (env.state_dir / "state.json").exists()


def test_not_typing_yes_records_nothing(env: Env) -> None:
    assert env.go(Args("record", key_id="hand-key"), answer=False) == DECLINED
    assert not (env.state_dir / "state.json").exists()


def test_a_state_write_that_fails_is_reported(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(st, "save", boom)
    assert env.go(Args("record", key_id="hand-key")) == FAILED
    assert "could not write state.json" in env.text()


# ---- nothing secret, nothing that can drive a terminal ----


def test_text_in_unread_fields_never_appears_anywhere(tmp_path: Path) -> None:
    files = {
        "hand-key": key_text("hand-key", extra=f'note = "{SECRET}"'),
        "auto-key": key_text("auto-key", method="automatic", extra=f'purpose_extra = "{SECRET}"'),
    }
    e = Env(tmp_path, files)
    for args in (Args("plan"), Args("approve"), Args("record", key_id="hand-key")):
        e.go(args)
    assert SECRET not in e.everything_written()


def test_terminal_control_characters_in_a_key_file_never_reach_the_output(tmp_path: Path) -> None:
    files = {
        "hand-key": key_text(
            "hand-key", name="evil\\u001b[2Jname", check="proof\\u001b]0;x\\u0007"
        ),
    }
    e = Env(tmp_path, files)
    e.go(Args("plan"))
    assert "\x1b" not in e.everything_written() and "\x07" not in e.everything_written()
