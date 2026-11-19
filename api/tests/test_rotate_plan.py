"""Dates, status and the plan hash (soc_api.rotate.plan)."""

from datetime import date, timedelta
from pathlib import Path

import pytest
from rotate_support import COMMIT, key_text, make_register

from soc_api.rotate.keys import KeyFile, Register, load_register
from soc_api.rotate.plan import (
    build_plan,
    classify,
    first_monday,
    following_session,
    render,
    session_on_or_after,
)
from soc_api.rotate.state import KeyState, State

TODAY = date(2026, 11, 18)
SESSION = date(2026, 12, 7)  # the first Monday of December 2026
AFTER = date(2027, 1, 4)


def key(**kw: object) -> KeyFile:
    base: dict[str, object] = {
        "id": "a-key", "name": "A key", "vendor": "limacharlie", "method": "manual",
        "sensitive": False, "period_days": 90, "ready": True, "check": "",
    }  # fmt: skip
    return KeyFile(**(base | kw))  # type: ignore[arg-type]


def ks(last: date, **kw: object) -> KeyState:
    return KeyState(**({"last_rotated": last, "outcome": "recorded"} | kw))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("year", "month", "expected"),
    [
        (2026, 11, date(2026, 11, 2)),
        (2026, 12, SESSION),
        (2027, 1, AFTER),
        (2027, 2, date(2027, 2, 1)),
    ],
)
def test_first_monday(year: int, month: int, expected: date) -> None:
    assert first_monday(year, month) == expected
    assert expected.weekday() == 0 and expected.day <= 7


def test_the_session_on_the_day_counts_and_the_day_after_moves_on() -> None:
    assert session_on_or_after(SESSION) == SESSION
    assert session_on_or_after(SESSION + timedelta(days=1)) == AFTER
    assert session_on_or_after(date(2026, 11, 2)) == date(2026, 11, 2)
    assert session_on_or_after(date(2026, 11, 3)) == SESSION
    assert following_session(SESSION) == AFTER
    assert following_session(AFTER) == date(2027, 2, 1)  # and across the year end, the other way


@pytest.mark.parametrize(
    ("due", "status"),
    [
        (date(2026, 11, 17), "overdue"),
        (date(2026, 11, 18), "due_soon"),  # due today is not yet late
        (date(2026, 11, 25), "due_soon"),  # seven days
        (date(2026, 11, 26), "this_session"),
        (date(2027, 1, 3), "this_session"),  # would go overdue before the session after next
        (date(2027, 1, 4), "ok"),
    ],
)
def test_status_by_due_date(due: date, status: str) -> None:
    row = classify(key(), ks(due - timedelta(days=90)), TODAY, AFTER)
    assert row.due == due and row.status == status


def test_a_date_set_by_a_person_replaces_last_plus_period() -> None:
    row = classify(key(), ks(date(2026, 10, 24), due_override=date(2026, 12, 15)), TODAY, AFTER)
    assert row.due == date(2026, 12, 15) and row.status == "this_session"


def test_no_record_and_not_ready() -> None:
    assert classify(key(), None, TODAY, AFTER).status == "no_record"
    not_ready = classify(key(ready=False), ks(date(2020, 1, 1)), TODAY, AFTER)
    assert not_ready.status == "not_ready"  # never nagged, however old


def test_the_old_key_still_live_is_flagged_only_for_ready_keys() -> None:
    assert classify(key(), ks(TODAY, revoke_pending=True), TODAY, AFTER).revoke_pending
    assert not classify(
        key(ready=False), ks(TODAY, revoke_pending=True), TODAY, AFTER
    ).revoke_pending


def register(*keys: KeyFile) -> Register:
    return Register({k.id: k for k in keys}, [])


def test_the_plan_sorts_overdue_first_then_sensitive_and_counts() -> None:
    reg = register(
        key(id="fine", period_days=90),
        key(id="late-std"),
        key(id="late-sens", sensitive=True, period_days=30),
        key(id="never"),
        key(id="later", ready=False),
    )
    state = State(
        keys={
            "fine": ks(TODAY),
            "late-std": ks(TODAY - timedelta(days=100)),
            "late-sens": ks(TODAY - timedelta(days=40)),
            "later": ks(TODAY),
        }
    )
    plan = build_plan(reg, state, TODAY, COMMIT)
    assert [r.key.id for r in plan.rows] == ["late-sens", "late-std", "never", "fine", "later"]
    c = plan.counts
    assert (c["overdue"], c["no_record"], c["ok"], c["not_ready"], c["sensitive_overdue"]) == (
        2,
        1,
        1,
        1,
        1,
    )
    assert plan.needs_attention


def test_what_an_apply_would_rotate() -> None:
    reg = register(
        key(id="auto-late", method="automatic"),
        key(id="auto-ok", method="automatic"),
        key(id="auto-pending", method="automatic"),
        key(id="auto-later", method="automatic", ready=False),
        key(id="by-hand-late"),
        key(id="exposure-only", method="none", period_days=None),
    )
    state = State(
        keys={
            "auto-late": ks(TODAY - timedelta(days=100)),
            "auto-ok": ks(TODAY),
            "auto-pending": ks(TODAY, revoke_pending=True),
            "auto-later": ks(TODAY - timedelta(days=100)),
            "by-hand-late": ks(TODAY - timedelta(days=100)),
            "gone": ks(TODAY),
        }
    )
    plan = build_plan(reg, state, TODAY, COMMIT)
    assert {r.key.id for r in plan.automatic_actions} == {"auto-late", "auto-pending"}
    assert {r.key.id for r in plan.manual_session} == {"by-hand-late"}
    assert (plan.untracked, plan.unknown_state) == (
        1,
        1,
    )  # a "none" key and a state entry with no file


def test_the_plan_hash_covers_the_commit_and_the_automatic_actions_only() -> None:
    reg = register(key(id="auto-late", method="automatic"), key(id="by-hand"))
    old = ks(TODAY - timedelta(days=100))
    base = build_plan(reg, State(keys={"auto-late": old, "by-hand": ks(TODAY)}), TODAY, COMMIT)
    assert len(base.plan_hash) == 12 and int(base.plan_hash, 16) >= 0
    # a manual key changing, or the order of the register, does not move it
    other_manual = build_plan(reg, State(keys={"auto-late": old, "by-hand": old}), TODAY, COMMIT)
    assert other_manual.plan_hash == base.plan_hash
    # a different register commit does
    assert (
        build_plan(reg, State(keys={"auto-late": old}), TODAY, "cd" * 20).plan_hash
        != base.plan_hash
    )
    # so does a different set of automatic actions
    rotated = build_plan(reg, State(keys={"auto-late": ks(TODAY)}), TODAY, COMMIT)
    assert rotated.plan_hash != base.plan_hash and rotated.automatic_actions == ()


def test_the_rendered_plan_is_fixed_text(tmp_path: Path) -> None:
    folder = make_register(
        tmp_path,
        {
            "auto-key": key_text("auto-key", method="automatic"),
            "hand-key": key_text("hand-key", check="Send a test"),
            "later-key": key_text("later-key", ready=False),
        },
    )
    reg = load_register(folder)
    plan = build_plan(reg, State(keys={"hand-key": ks(TODAY - timedelta(days=95))}), TODAY, COMMIT)
    text = "\n".join(render(plan))
    assert f"register commit {COMMIT[:12]}" in text and "Next session 2026-12-07" in text
    assert (
        "Automatic keys to rotate (1):" in text
        and "Manual keys for the 2026-12-07 session (1):" in text
    )
    assert "5 days overdue" in text and "proof: Send a test" in text
    assert "Not ready, skipped (1): later-key" in text
    assert all(32 <= ord(c) < 127 or c == "\n" for c in text)
