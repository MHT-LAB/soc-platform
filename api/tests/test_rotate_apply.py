"""The apply step (soc_api.rotate.apply) against in-memory fakes: order, rollback, refusals."""

from datetime import date, timedelta
from pathlib import Path

import pytest
from rotate_fakes import (
    NEW_ID,
    NEW_VALUE,
    OID,
    OLD_ID,
    OLD_VALUE,
    PERMS,
    SENTINELS,
    SPEC_NAME,
    Harness,
    World,
    unreadable,
)
from rotate_support import key_text

from soc_api.rotate import apply as ap
from soc_api.rotate import state as st
from soc_api.rotate.codes import ATTENTION, FAILED, OK, REFUSED
from soc_api.rotate.lc import VendorKey

HAPPY = [
    "get SOC_LC_OID",
    "vendor.list",
    "create x-20261118",
    "get AUTO_KEY_VALUE",
    "set AUTO_KEY_VALUE",
    "install",
    "restart",
    "check",
    "sleep 600",
    "check",
    "delete old",
    "discard_prev",
]


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def untouched(h: Harness) -> None:
    """The refusal happened before any change anywhere."""
    mutating = ("create", "set ", "install", "restart", "restore", "delete", "sleep")
    assert not [c for c in h.world.log if c.startswith(mutating)], h.world.log
    assert h.world.secrets["AUTO_KEY_VALUE"] == OLD_VALUE and h.world.env == OLD_VALUE


# ---- the good run ----


def test_the_steps_run_in_the_designed_order_and_the_old_key_goes_last(h: Harness) -> None:
    h.approve()
    assert h.apply() == OK, h.text()
    assert h.world.log == HAPPY
    assert h.world.env == NEW_VALUE and h.world.secrets["AUTO_KEY_VALUE"] == NEW_VALUE
    assert set(h.world.keys) == {NEW_ID}  # the old key is gone, the new one stays


def test_the_state_records_the_new_key_and_consumes_the_approval(h: Harness) -> None:
    h.approve()
    h.apply()
    key = h.state().keys["auto-key"]
    assert (key.last_rotated.isoformat(), key.outcome) == ("2026-11-18", "rotated")
    assert (key.vendor_key_id, key.old_key_id, key.revoke_pending) == (NEW_ID, "", False)
    assert h.state().approval is None
    record = (h.state_dir / "record.txt").read_text()
    assert "apply " in record and "id=auto-key" in record and "result=rotated" in record
    assert f"old={OLD_ID[-4:]}" in record and f"new={NEW_ID[-4:]}" in record
    assert "next_due=2027-02-16" in record  # today plus the 90-day period


def test_the_next_rotation_finds_its_key_by_the_recorded_id(h: Harness) -> None:
    h.approve()
    h.apply()
    h.moment += timedelta(days=91)  # due again
    h.world.log.clear()
    h.world.checks = [True, True]
    h.approve()
    assert h.apply() == OK, h.text()
    assert "create x-20270217" in h.world.log  # the dated name for the new day
    assert "delete new" in h.world.log  # the key replaced is the one made last time (NEW_ID)
    assert "refused" not in h.text()
    again = h.state().keys["auto-key"]
    assert again.vendor_key_id == "newkeyid0003" and again.last_rotated.isoformat() == "2027-02-17"


# ---- nothing is ever revoked unless both checks passed ----


@pytest.mark.parametrize("checks", [[False], [True, False]])
def test_a_failed_check_undoes_everything_and_never_touches_the_old_key(
    h: Harness, checks: list[bool]
) -> None:
    h.world.checks = [*checks]
    h.approve()
    assert h.apply() == FAILED
    log = h.world.log
    assert "delete old" not in log and "delete new" in log
    assert h.world.env == OLD_VALUE and h.world.secrets["AUTO_KEY_VALUE"] == OLD_VALUE
    assert set(h.world.keys) == {OLD_ID}
    assert log.index("restore") < log.index("delete new")  # the service is healthy again first
    assert "rolled-back" in h.text() and "ROLLBACK-INCOMPLETE" not in h.text()


@pytest.mark.parametrize(
    ("step", "expect_secret_restored", "expect_file_restored"),
    [
        ("create", False, False),
        ("get", False, False),
        ("install", True, False),
        ("restart", True, True),
    ],
)
def test_a_failure_at_each_step_undoes_exactly_what_was_done(
    h: Harness, step: str, expect_secret_restored: bool, expect_file_restored: bool
) -> None:
    if step == "get":
        # the second read (the value), not the organization id
        original = h.world.get

        def flaky(path: str, name: str):  # type: ignore[no-untyped-def]
            if name == "AUTO_KEY_VALUE":
                h.world.fail.add("get")
            return original(path, name)

        h.world.get = flaky  # type: ignore[method-assign]
    else:
        h.world.fail.add(step)
    h.approve()
    assert h.apply() == FAILED
    log = h.world.log
    assert "delete old" not in log
    assert ("restore" in log) == expect_file_restored
    assert (log.count("set AUTO_KEY_VALUE") == 2) == expect_secret_restored
    assert h.world.env == OLD_VALUE and h.world.secrets["AUTO_KEY_VALUE"] == OLD_VALUE
    assert set(h.world.keys) == {OLD_ID}  # a key that was made is deleted again


def test_when_the_undo_itself_fails_a_person_is_told_exactly_what(h: Harness) -> None:
    h.world.checks = [False]
    h.world.fail.add("restore")
    h.approve()
    assert h.apply() == FAILED
    assert "ROLLBACK-INCOMPLETE" in h.text() and "NEEDS A PERSON" in h.text()
    assert "consumer_fake_restore" in h.text()
    assert "delete old" not in h.world.log


def test_an_interrupt_in_the_middle_still_undoes_the_work_then_propagates(h: Harness) -> None:
    h.world.interrupt_on_check = True
    h.approve()
    with pytest.raises(KeyboardInterrupt):
        h.apply()
    assert "delete new" in h.world.log and "delete old" not in h.world.log
    assert h.world.env == OLD_VALUE and h.world.secrets["AUTO_KEY_VALUE"] == OLD_VALUE


def test_an_unexpected_error_in_one_undo_step_does_not_stop_the_others(h: Harness) -> None:
    h.world.checks = [False]

    def broken_restore(env_file: str) -> None:
        raise ValueError("a bug, not a vendor error")

    h.world.restore = broken_restore  # type: ignore[method-assign]
    h.approve()
    assert h.apply() == FAILED
    assert "consumer_unexpected_error" in h.text() and "ROLLBACK-INCOMPLETE" in h.text()
    assert h.world.secrets["AUTO_KEY_VALUE"] == OLD_VALUE  # still put back
    assert set(h.world.keys) == {OLD_ID}  # and the new key still deleted


def test_an_interrupted_run_still_saves_its_state_and_leaves_its_record(h: Harness) -> None:
    h.world.interrupt_on_check = True
    h.approve()
    with pytest.raises(KeyboardInterrupt):
        h.apply()
    record = (h.state_dir / "record.txt").read_text()
    assert "failed-interrupted-rolled-back" in record
    assert h.state().approval is None  # the approval was used up


def test_a_hangup_or_terminate_is_turned_into_the_same_interrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import signal

    for sig in (signal.SIGHUP, signal.SIGTERM):
        monkeypatch.setattr(signal, "signal", signal.signal)  # keep the real one
        saved = signal.getsignal(sig)
        try:
            ap.stop_on_hangup()
            with pytest.raises(KeyboardInterrupt):
                os.kill(os.getpid(), sig)
        finally:
            signal.signal(sig, saved)


# ---- the revoke ----


def test_a_failed_revoke_is_remembered_and_the_next_run_only_finishes_it(h: Harness) -> None:
    h.world.fail.add("delete")
    h.approve()
    assert h.apply() == OK  # the new key works; that is what matters most
    key = h.state().keys["auto-key"]
    assert key.revoke_pending is True and key.old_key_id == OLD_ID and key.vendor_key_id == NEW_ID
    assert "REVOKE-PENDING" in (h.state_dir / "record.txt").read_text()
    # next run: only the revoke is done, nothing new is created
    h.world.fail.clear()
    h.world.keys[OLD_ID] = VendorKey(OLD_ID, SPEC_NAME, frozenset(PERMS))
    h.world.log.clear()
    h.approve()
    assert h.apply() == OK, h.text()
    assert not any(c.startswith("create") for c in h.world.log)
    assert "delete old" in h.world.log
    done = h.state().keys["auto-key"]
    assert (done.revoke_pending, done.old_key_id, done.vendor_key_id) == (False, "", NEW_ID)


def test_a_pending_revoke_for_a_key_already_gone_is_cleared(h: Harness) -> None:
    h.world.fail.add("delete")
    h.approve()
    h.apply()
    h.world.fail.clear()
    h.world.keys.pop(OLD_ID, None)  # someone removed it by hand
    h.approve()
    assert h.apply() == OK
    assert h.state().keys["auto-key"].revoke_pending is False


def test_a_pending_revoke_never_deletes_a_key_that_was_renamed(h: Harness) -> None:
    h.world.fail.add("delete")
    h.approve()
    h.apply()
    h.world.fail.clear()
    h.world.keys[OLD_ID] = VendorKey(OLD_ID, "something-else", frozenset(PERMS))
    h.world.log.clear()
    h.approve()
    assert h.apply() == FAILED
    assert "delete old" not in h.world.log


def test_a_revoke_left_pending_on_a_later_rotation_can_still_be_finished(h: Harness) -> None:
    """Regression: after the first rotation the live key carries a dated name."""
    h.approve()
    h.apply()
    h.moment += timedelta(days=91)
    h.world.fail.add("delete")
    h.world.checks = [True, True]
    h.approve()
    h.apply()
    assert h.state().keys["auto-key"].revoke_pending is True
    h.world.fail.clear()
    h.world.log.clear()
    h.approve()
    assert h.apply() == OK, h.text()
    assert "delete new" in h.world.log  # x-20261118, the key made by the first rotation
    assert h.state().keys["auto-key"].revoke_pending is False


def test_a_key_is_found_again_by_name_when_its_recorded_id_is_lost(h: Harness) -> None:
    """Regression: a state rebuilt by --record has no vendor id; the dated key must be found."""
    h.approve()
    h.apply()
    state = h.state()
    state.keys["auto-key"] = st.KeyState(date(2026, 11, 18), "recorded")  # what --record writes
    h.put_state(state)
    h.moment += timedelta(days=91)
    h.world.log.clear()
    h.world.checks = [True, True]
    h.approve()
    assert h.apply() == OK, h.text()
    assert "delete new" in h.world.log


@pytest.mark.parametrize(
    ("name", "ours"),
    [
        ("x", True),
        ("x-20261118", True),
        ("x-2026111", False),
        ("x-202611180", False),
        ("x-evil", False),
        ("xx-20261118", False),
        ("x-20261118-copy", False),
        ("y", False),
    ],
)
def test_only_the_exact_name_or_the_name_and_a_date_are_ours(name: str, ours: bool) -> None:
    assert ap.is_ours(name, "x") is ours


def test_an_unfinished_rotation_without_a_recorded_id_is_refused_not_guessed(h: Harness) -> None:
    h.world.keys["newkeyid0009"] = VendorKey("newkeyid0009", "x-20261001", frozenset(PERMS))
    h.approve()
    assert h.apply() == FAILED
    assert "refused-old_key_ambiguous" in h.text()
    untouched(h)


# ---- refusals before any change ----


def test_a_live_key_with_other_permissions_is_refused(h: Harness) -> None:
    h.world.keys[OLD_ID] = VendorKey(OLD_ID, SPEC_NAME, frozenset({*PERMS, "dr.set"}))
    h.approve()
    assert h.apply() == FAILED
    untouched(h)
    assert "permissions differ" in h.text() and "dr.set" in h.text()
    assert "refused-perms_differ" in h.text()


def test_a_missing_or_doubled_old_key_is_refused(h: Harness) -> None:
    h.world.keys = {}
    h.approve()
    h.apply()
    assert "refused-old_key_missing" in h.text()
    untouched(h)


def test_two_live_keys_with_the_name_are_ambiguous_and_refused(tmp_path: Path) -> None:
    world = World(
        keys={
            OLD_ID: VendorKey(OLD_ID, SPEC_NAME, frozenset(PERMS)),
            "otherkey0003": VendorKey("otherkey0003", SPEC_NAME, frozenset(PERMS)),
        }
    )
    h = Harness(tmp_path, world)
    h.approve()
    assert h.apply() == FAILED
    assert "refused-old_key_ambiguous" in h.text()
    untouched(h)


def test_a_leftover_key_with_todays_name_is_refused(h: Harness) -> None:
    leftover = VendorKey("leftover0004", "x-20261118", frozenset(PERMS))
    # with no recorded id, two keys are ours: which is the old one is not guessed
    h.world.keys["leftover0004"] = leftover
    h.approve()
    assert h.apply() == FAILED
    assert "refused-old_key_ambiguous" in h.text()
    untouched(h)
    # with the old key known by its recorded id, today's name being taken is the reason
    h.put_state(
        st.State(keys={"auto-key": st.KeyState(date(2026, 8, 1), "rotated", vendor_key_id=OLD_ID)})
    )
    h.said.clear()
    h.approve()
    assert h.apply() == FAILED
    assert "refused-new_name_taken" in h.text()
    untouched(h)


def test_a_recorded_key_that_vanished_is_refused(h: Harness) -> None:
    recorded = st.KeyState(date(2026, 1, 1), "rotated", vendor_key_id="gone00000005")
    h.put_state(st.State(keys={"auto-key": recorded}))
    h.approve()
    assert h.apply() == FAILED
    assert "refused-recorded_key_missing" in h.text()
    untouched(h)


# ---- the approval ----


def test_without_an_approval_nothing_runs_and_the_rights_are_never_read(h: Harness) -> None:
    assert h.apply() == REFUSED
    assert h.rights_read == 0 and h.world.log == []
    assert "there is no approval" in h.text()


def test_a_plan_hash_that_is_not_the_current_plan_is_refused(h: Harness) -> None:
    h.approve()
    assert h.apply("0" * 12) == REFUSED
    assert "not the one that was approved" in h.text() and h.world.log == []


def test_an_old_approval_is_refused(h: Harness) -> None:
    h.approve(age=timedelta(minutes=31))
    assert h.apply() == REFUSED
    assert "older than 30 minutes" in h.text() and h.world.log == []


def test_an_approval_for_another_register_commit_is_refused(h: Harness) -> None:
    h.approve(commit="cd" * 20)
    assert h.apply() == REFUSED
    assert "register changed" in h.text() and h.world.log == []


def test_an_approval_is_good_for_one_apply_only(h: Harness) -> None:
    plan_hash = h.approve()
    assert h.apply(plan_hash) == OK
    h.world.log.clear()
    assert h.apply(plan_hash) == REFUSED
    assert h.world.log == []


def test_an_approval_is_used_up_even_when_the_run_fails(h: Harness) -> None:
    h.world.fail.add("create")
    h.approve()
    assert h.apply() == FAILED
    assert h.state().approval is None


def test_bad_rights_are_refused_without_using_up_the_approval(h: Harness) -> None:
    h.approve()
    assert h.apply(read=unreadable()) == REFUSED
    assert "missing LC_ROTATOR_KEY" in h.text()
    assert h.state().approval is not None and h.world.log == []


def test_a_second_apply_at_the_same_time_is_refused(h: Harness) -> None:
    h.approve()
    held = ap.ApplyLock(h.state_dir / "apply.lock")
    try:
        assert h.apply() == REFUSED
    finally:
        held.release()
    assert "lock" in h.text() and h.world.log == []


def test_a_register_with_a_problem_or_a_bad_state_is_refused(h: Harness) -> None:
    (h.keys_dir / "junk.toml").write_text("not toml =")
    assert h.apply("0" * 12) == REFUSED
    assert "problem(s) in the key register" in h.text() and h.world.log == []


def test_a_state_file_that_is_not_ours_is_refused(h: Harness) -> None:
    (h.state_dir / "state.json").write_text("{broken")
    assert h.apply("0" * 12) == REFUSED
    assert h.world.log == []


# ---- scope of a run ----


def test_nothing_automatic_due_means_nothing_to_apply(tmp_path: Path) -> None:
    h = Harness(tmp_path, files={"hand-key": key_text("hand-key")})
    h.approve()
    assert h.apply() == OK
    assert "nothing to apply" in h.text().lower() and h.rights_read == 0


def test_the_first_failure_stops_the_run_and_later_keys_are_untouched(tmp_path: Path) -> None:
    files = {
        "auto-a": key_text("auto-a", method="automatic"),
        "auto-b": key_text("auto-b", method="automatic"),
    }
    world = World()
    world.fail.add("create")
    h = Harness(tmp_path, world, files)
    h.approve()
    assert h.apply() == FAILED
    assert world.log.count("create x-20261118") == 1  # the second key was never tried
    assert "Stopped at the first failure" in h.text()


def test_a_key_this_build_cannot_rotate_is_named_and_skipped(tmp_path: Path) -> None:
    other = key_text("auto-key", method="automatic").replace("posture_check", "reconcile_check")
    h = Harness(tmp_path, files={"auto-key": other})
    h.approve()
    assert h.apply() == ATTENTION
    assert "skipped auto-key: this build has no such health check yet" in h.text()
    untouched(h)


# ---- nothing secret anywhere ----


def test_no_key_value_or_right_appears_in_any_output_or_file(h: Harness) -> None:
    h.approve()
    h.apply()
    out = h.everything_written()
    for sentinel in SENTINELS:
        assert sentinel not in out
    assert OID not in out  # not a secret, but the output carries ids as their last four only


def test_no_value_leaks_on_a_failed_and_undone_run_either(h: Harness) -> None:
    h.world.checks = [False]
    h.approve()
    h.apply()
    out = h.everything_written()
    for sentinel in SENTINELS:
        assert sentinel not in out


# ---- preflight ----


def test_preflight_reads_and_checks_but_changes_nothing(h: Harness) -> None:
    assert h.preflight() == OK, h.text()
    untouched(h)
    assert "preflight" in h.text() and "result=ok" in h.text()
    assert not (h.state_dir / "state.json").exists()  # no approval needed, no state written
    for sentinel in SENTINELS:
        assert sentinel not in h.everything_written()


def test_preflight_reports_a_permission_mismatch(h: Harness) -> None:
    h.world.keys[OLD_ID] = VendorKey(OLD_ID, SPEC_NAME, frozenset({"dr.list"}))
    assert h.preflight() == FAILED
    assert "problem-perms_differ" in h.text()
    untouched(h)


def test_preflight_reports_an_unreadable_secret(h: Harness) -> None:
    h.world.fail.add("get")
    assert h.preflight() == FAILED
    assert "problem-org_id_fake_get" in h.text()


def test_preflight_with_bad_rights_is_refused(h: Harness) -> None:
    from rotate_fakes import unreadable as bad

    rc = ap.run_preflight(
        keys_dir=h.keys_dir,
        state_dir=h.state_dir,
        commit="ab" * 20,
        read=bad(),  # type: ignore[arg-type]
        build=lambda _r: h.world.deps(),
        say=h.said.append,
        now=lambda: h.moment,
    )
    assert rc == REFUSED and h.world.log == []
