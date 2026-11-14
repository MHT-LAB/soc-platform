"""The console's degraded banner: shown on every page when the pipeline is degraded.

The conditions are the pager's STALE ones (pages stuck, new alerts not becoming cases, a failed
page, the catch-up worker quiet, an old backup), decided by the worker's own function with its
own limits. Real Postgres and the real soc_console login for the conditions; plain numbers for
the wording.
"""

from typing import Any

import psycopg
import pytest
from conftest import ROLE_PASSWORD, TestDb
from fastapi.testclient import TestClient
from test_worker_db import Fixture

from soc_api import banner
from soc_api import db as soc_db
from soc_api.config import Settings
from soc_api.main import create_console_app

LOGIN = "operator@example.com"
HEADERS = {"Tailscale-User-Login": LOGIN}
HEALTHY: dict[str, Any] = {
    "oldest_pending_page_s": None,
    "failed_last_24h": 0,
    "oldest_unassigned_alert_s": None,
    "reconcile_sources": 0,
    "reconcile_quiet_s": None,
    "backup_age_s": 60.0,
}


# ---- the wording, without a database ----


def test_a_healthy_pipeline_gives_no_notices() -> None:
    assert banner.notices(HEALTHY) == []


@pytest.mark.parametrize(
    ("change", "words"),
    [
        ({"oldest_pending_page_s": 1500}, "waiting to go out for 25 minutes"),
        ({"failed_last_24h": 2}, "failed to send in the last 24 hours"),
        ({"oldest_unassigned_alert_s": 3 * 3600}, "oldest has waited 3 hours"),
        (
            {"reconcile_sources": 1, "reconcile_quiet_s": 2400.0},
            "catch-up worker has not completed a run for 40 minutes",
        ),
        ({"backup_age_s": 14 * 3600.0}, "backup is 14 hours old"),
    ],
)
def test_each_condition_is_named_with_its_age(change: dict[str, Any], words: str) -> None:
    [line] = banner.notices({**HEALTHY, **change})
    assert words in line


@pytest.mark.parametrize(
    "change",
    [
        {"oldest_pending_page_s": 600},
        {"oldest_unassigned_alert_s": 600},
        {"reconcile_sources": 1, "reconcile_quiet_s": 1800.0},
        {"reconcile_sources": 0, "reconcile_quiet_s": 99999.0},
        {"backup_age_s": 13 * 3600.0},
    ],
)
def test_the_limits_are_the_pagers_and_a_value_at_the_limit_is_not_degraded(
    change: dict[str, Any],
) -> None:
    assert banner.notices({**HEALTHY, **change}) == []


def test_several_conditions_give_several_lines() -> None:
    change = {"oldest_pending_page_s": 900, "backup_age_s": 20 * 3600.0, "failed_last_24h": 1}
    assert len(banner.notices({**HEALTHY, **change})) == 3


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(5, "under a minute"), (60, "1 minute"), (7199, "119 minutes"), (7200, "2 hours"),
     (3 * 86400, "3 days")],
)  # fmt: skip
def test_ages_read_in_plain_words(seconds: float, text: str) -> None:
    assert banner.age(seconds) == text


# ---- the pages, with a database ----


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def app(fx: Fixture, **over: Any) -> TestClient:
    base: dict[str, Any] = {
        "env": "prod",
        "console_users": LOGIN,
        "version": "edge",
        "git_sha": "a" * 40,
        "console_database_url": fx.db.sqlalchemy_url("soc_console", ROLE_PASSWORD),
    }
    return TestClient(create_console_app(Settings(**{**base, **over})))


def pages(fx: Fixture) -> list[str]:
    case = fx.one("SELECT id FROM soc_case LIMIT 1")
    paths = ["/console", "/console/cases"]
    if case:
        paths.append(f"/console/case/{case[0]}")
    return paths


def shown(fx: Fixture, path: str) -> str:
    c = app(fx)
    r = c.get(path, headers=HEADERS)
    assert r.status_code == 200, path
    return r.text


def one_case(fx: Fixture) -> None:
    fx.alert()
    fx.assign()


def test_a_healthy_pipeline_has_no_banner_on_any_page(fx: Fixture) -> None:
    one_case(fx)
    for path in pages(fx):
        assert "Pipeline degraded" not in shown(fx, path), path


def test_a_page_waiting_too_long_shows_the_banner_on_every_page(fx: Fixture) -> None:
    one_case(fx)
    fx.run("UPDATE notification SET created_at = now() - interval '25 minutes'")
    for path in pages(fx):
        text = shown(fx, path)
        assert "Pipeline degraded" in text and "waiting to go out for 25 minutes" in text, path


def test_a_page_waiting_five_minutes_is_not_degraded(fx: Fixture) -> None:
    one_case(fx)
    fx.run("UPDATE notification SET created_at = now() - interval '5 minutes'")
    assert "Pipeline degraded" not in shown(fx, "/console")


def test_a_failed_page_shows_the_banner(fx: Fixture) -> None:
    one_case(fx)
    fx.run("UPDATE notification SET status = 'failed'")
    assert "failed to send in the last 24 hours" in shown(fx, "/console/cases")


def test_an_alert_that_is_not_becoming_a_case_shows_the_banner(fx: Fixture) -> None:
    fx.alert(age_min=45)
    text = shown(fx, "/console")
    assert "New alerts are not becoming cases" in text and "45 minutes" in text


def test_a_quiet_catch_up_worker_shows_the_banner(fx: Fixture) -> None:
    fx.run(
        "INSERT INTO reconcile_cursor (source_id, window_end, last_success, started_at) "
        "SELECT id, now(), now() - interval '50 minutes', now() - interval '3 hours' "
        "FROM source WHERE slug = 'src-a'"
    )
    assert "catch-up worker has not completed a run for 50 minutes" in shown(fx, "/console")


def test_a_fresh_catch_up_worker_is_not_degraded(fx: Fixture) -> None:
    fx.run(
        "INSERT INTO reconcile_cursor (source_id, window_end, last_success, started_at) "
        "SELECT id, now(), now() - interval '2 minutes', now() - interval '3 hours' "
        "FROM source WHERE slug = 'src-a'"
    )
    assert "Pipeline degraded" not in shown(fx, "/console")


def test_an_old_backup_shows_the_banner(fx: Fixture) -> None:
    fx.run("UPDATE backup_state SET last_ok_at = now() - interval '14 hours'")
    assert "last good database backup is 14 hours old" in shown(fx, "/console")


def test_a_backup_twelve_hours_old_is_not_degraded(fx: Fixture) -> None:
    fx.run("UPDATE backup_state SET last_ok_at = now() - interval '12 hours'")
    assert "Pipeline degraded" not in shown(fx, "/console")


def test_the_banner_goes_away_when_the_condition_clears(fx: Fixture) -> None:
    fx.run("UPDATE backup_state SET last_ok_at = now() - interval '14 hours'")
    assert "Pipeline degraded" in shown(fx, "/console")
    fx.run("UPDATE backup_state SET last_ok_at = now()")
    assert "Pipeline degraded" not in shown(fx, "/console")


def test_the_banner_says_nothing_from_clients_or_alerts(fx: Fixture) -> None:
    fx.run("UPDATE client SET name = 'Zebra Dental Ltd' WHERE slug = 'client-a'")
    fx.alert(host="zebra-host.internal", rule="zebra.Rule", age_min=45)
    text = shown(fx, "/console")
    banner_html = text[
        text.index('class="degraded"') : text.index("</div>", text.index("degraded"))
    ]
    for word in ("Zebra", "zebra", "client-a", "internal"):
        assert word not in banner_html


def test_a_console_that_cannot_reach_the_database_says_so_without_detail(fx: Fixture) -> None:
    url = "postgresql+psycopg://soc_console:pw-secret@127.0.0.1:1/soc"
    r = app(fx, console_database_url=url).get("/console", headers=HEADERS)
    assert r.status_code == 200 and banner.UNREADABLE in r.text
    assert "pw-secret" not in r.text and "127.0.0.1:1" not in r.text


def test_without_a_database_login_there_is_no_banner(fx: Fixture) -> None:
    r = app(fx, console_database_url="").get("/console", headers=HEADERS)
    assert r.status_code == 200 and "Pipeline degraded" not in r.text


def test_a_refused_request_never_reaches_the_database_or_shows_the_banner(
    fx: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from soc_api.cases import CaseDb

    def boom(self: CaseDb) -> dict[str, Any]:
        raise AssertionError("the database was asked before the identity check")

    monkeypatch.setattr(CaseDb, "console_health", boom)
    c = app(fx)
    assert c.get("/console").status_code == 403
    assert c.get("/console", headers={"Tailscale-User-Login": "x@example.com"}).status_code == 403


# ---- the function ----


def test_only_the_console_login_can_call_it_and_it_runs_as_the_writer(fx: Fixture) -> None:
    def can(role: str) -> bool:
        return bool(
            fx.one("SELECT has_function_privilege(%s, 'console_health()', 'EXECUTE')", (role,))[0]
        )

    assert can("soc_console") and not can("public")
    for role in ("soc_app", "soc_ingest", "soc_worker", "soc_reconcile"):
        assert not can(role), role
        with fx.db.connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM console_health()")
    row = fx.one(
        "SELECT p.prosecdef, p.proconfig, r.rolname, r.rolcanlogin FROM pg_proc p "
        "JOIN pg_roles r ON r.oid = p.proowner WHERE p.proname = 'console_health'"
    )
    assert row[0] is True and row[2] == "soc_console_writer" and row[3] is False
    assert row[1] and any(x.startswith("search_path=pg_catalog") for x in row[1])


def test_the_login_reads_no_table_and_the_writer_sees_only_the_health_columns(
    fx: Fixture,
) -> None:
    with fx.db.connect("soc_console") as c:
        for table in ("backup_state", "reconcile_cursor"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(f"SELECT * FROM {table}")  # noqa: S608 - fixed names

    def can(table: str, column: str, privilege: str) -> bool:
        return bool(
            fx.one(
                "SELECT has_column_privilege('soc_console_writer', %s, %s, %s)",
                (table, column, privilege),
            )[0]
        )

    for table, columns in (
        ("backup_state", ("started_at", "last_ok_at")),
        ("reconcile_cursor", ("last_success", "started_at")),
    ):
        for column in columns:
            assert can(table, column, "SELECT") and not can(table, column, "UPDATE"), column
    assert not can("backup_state", "last_bytes", "SELECT")
    assert not can("reconcile_cursor", "last_error", "SELECT")
    assert not can("reconcile_cursor", "window_end", "SELECT")


def test_downgrading_removes_it_and_upgrading_brings_it_back(db: TestDb, fx: Fixture) -> None:
    url = db.sqlalchemy_url()
    soc_db.downgrade(url, "0009")
    with db.connect() as c:
        assert c.execute("SELECT to_regprocedure('console_health()')").fetchone() == (None,)
        assert c.execute(
            "SELECT count(*) FROM pg_policies WHERE policyname = 'console_health_read'"
        ).fetchone() == (0,)
        assert c.execute(
            "SELECT has_column_privilege('soc_console_writer', 'backup_state', "
            "'last_ok_at', 'SELECT')"
        ).fetchone() == (False,)
    soc_db.upgrade(url)
    with fx.db.connect("soc_console") as c:
        assert c.execute("SELECT * FROM console_health()").fetchone() is not None
