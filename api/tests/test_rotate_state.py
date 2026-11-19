"""The rotator's memory (soc_api.rotate.state): written whole, refused when odd, never a value."""

import json
import os
import stat
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from rotate_support import COMMIT

from soc_api.rotate import state as st

NOW = datetime(2026, 11, 18, 15, 0, tzinfo=UTC)


def sample() -> st.State:
    return st.State(
        keys={
            "soc-lc-posture": st.KeyState(
                date(2026, 11, 14), "rotated", False, None, "2026-11-14T09:00:00Z"
            ),
            "n8n-customer": st.KeyState(
                date(2026, 10, 24), "recorded", True, date(2026, 12, 15), "2026-10-24T09:00:00Z"
            ),
        },
        approval=st.Approval("0123456789ab", COMMIT, NOW),
    )


def test_no_file_means_an_empty_state(tmp_path: Path) -> None:
    s = st.load(tmp_path / "state.json")
    assert s.keys == {} and s.approval is None


def test_a_save_and_a_load_agree(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    st.save(path, sample())
    back = st.load(path)
    assert back == sample()
    assert back.keys["n8n-customer"].due_override == date(2026, 12, 15)
    assert back.keys["n8n-customer"].revoke_pending is True


def test_the_file_is_mode_600_and_no_temporary_file_is_left(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    st.save(path, sample())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_a_failed_write_leaves_the_old_file_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.json"
    st.save(path, sample())
    before = path.read_text()

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        st.save(path, st.State())
    monkeypatch.undo()
    assert path.read_text() == before
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_the_saved_file_holds_ids_dates_and_outcomes_only(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    st.save(path, sample())
    doc = json.loads(path.read_text())
    assert set(doc) == {"version", "keys", "approval"}
    for entry in doc["keys"].values():
        assert set(entry) <= {
            "last_rotated",
            "outcome",
            "revoke_pending",
            "due_override",
            "updated",
        }


@pytest.mark.parametrize(
    "doc",
    [
        [],
        {"version": 2, "keys": {}},
        {"version": 1, "keys": []},
        {"version": 1, "keys": {"Bad Id": {"last_rotated": "2026-01-01", "outcome": "rotated"}}},
        {"version": 1, "keys": {"a-key": {"last_rotated": "2026-01-01", "outcome": "magic"}}},
        {"version": 1, "keys": {"a-key": {"last_rotated": "yesterday", "outcome": "rotated"}}},
        {
            "version": 1,
            "keys": {
                "a-key": {
                    "last_rotated": "2026-01-01",
                    "outcome": "rotated",
                    "revoke_pending": "no",
                }
            },
        },
        {
            "version": 1,
            "keys": {},
            "approval": {"plan_hash": "zz", "commit": COMMIT, "approved_at": "x"},
        },
        {
            "version": 1,
            "keys": {},
            "approval": {"plan_hash": "0123456789ab", "commit": "short", "approved_at": "x"},
        },
        {
            "version": 1,
            "keys": {},
            "approval": {
                "plan_hash": "0123456789ab",
                "commit": COMMIT,
                "approved_at": "2026-11-18",
            },
        },
    ],
)
def test_a_file_that_is_not_ours_is_refused(tmp_path: Path, doc: object) -> None:
    path = tmp_path / "state.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(st.StateError):
        st.load(path)


def test_garbage_and_oversize_files_are_refused_and_left_alone(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{not json")
    with pytest.raises(st.StateError):
        st.load(path)
    assert path.read_text() == "{not json"
    path.write_text(" " * (st.MAX_STATE_BYTES + 1))
    with pytest.raises(st.StateError, match="too large"):
        st.load(path)


def test_an_error_names_no_value(tmp_path: Path) -> None:
    secret = "VALUE-that-must-never-be-printed-9f8e7d6c5b4a"
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {"version": 1, "keys": {"a-key": {"last_rotated": secret, "outcome": "rotated"}}}
        )
    )
    with pytest.raises(st.StateError) as exc:
        st.load(path)
    assert secret not in str(exc.value)


def test_an_approval_covers_only_its_own_plan_commit_and_window() -> None:
    s = sample()
    assert st.approval_problem(s, "0123456789ab", COMMIT, NOW + timedelta(minutes=29)) is None
    assert st.approval_problem(s, "0123456789ab", COMMIT, NOW + timedelta(minutes=31)) == "expired"
    assert st.approval_problem(s, "ffffffffffff", COMMIT, NOW) == "plan_changed"
    assert st.approval_problem(s, "0123456789ab", "cd" * 20, NOW) == "commit_changed"
    assert (
        st.approval_problem(s, "0123456789ab", COMMIT, NOW - timedelta(minutes=10))
        == "from_the_future"
    )
    assert st.approval_problem(st.State(), "0123456789ab", COMMIT, NOW) == "no_approval"
