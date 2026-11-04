"""Migration 0008: what the database remembers about backups, and who may read or write it.

Real Postgres, real logins. The backup script marks a good dump as the superuser; the pager
worker may ask how old the last one is and how big, and nothing more.
"""

from typing import Any

import psycopg
import pytest
from conftest import TestDb
from test_worker_db import Fixture

from soc_api import db as soc_db

SERVICE_ROLES = ("soc_app", "soc_ingest", "soc_console", "soc_reconcile", "soc_worker")


@pytest.fixture
def fx(db: TestDb) -> Fixture:
    return Fixture(db)


def health(fx: Fixture) -> tuple[Any, ...]:
    with fx.worker() as w:
        row = w.execute("SELECT * FROM backup_health()").fetchone()
    assert row is not None
    return row


def set_state(fx: Fixture, *, ok_hours_ago: float | None, started_hours_ago: float) -> None:
    fx.run(
        "UPDATE backup_state SET started_at = now() - make_interval(secs => %s::float8 * 3600), "
        "last_ok_at = CASE WHEN %s::float8 IS NULL THEN NULL "
        "ELSE now() - make_interval(secs => %s::float8 * 3600) END, "
        "last_bytes = CASE WHEN %s::float8 IS NULL THEN NULL ELSE 1234 END",
        (started_hours_ago, ok_hours_ago, ok_hours_ago, ok_hours_ago),
    )


# ---- backup_health ----


def test_a_new_database_has_no_backup_and_its_age_runs_from_the_migration(fx: Fixture) -> None:
    age, size = health(fx)
    assert size is None and 0 <= age < 60


def test_without_a_backup_the_age_runs_from_when_the_state_began(fx: Fixture) -> None:
    set_state(fx, ok_hours_ago=None, started_hours_ago=20)
    age, size = health(fx)
    assert size is None and 71990 <= age <= 72100


def test_with_a_backup_the_age_runs_from_the_last_good_one(fx: Fixture) -> None:
    set_state(fx, ok_hours_ago=2, started_hours_ago=500)
    age, size = health(fx)
    assert size == 1234 and 7190 <= age <= 7300


def test_marking_a_dump_resets_the_age_and_records_the_size(fx: Fixture) -> None:
    set_state(fx, ok_hours_ago=30, started_hours_ago=500)
    fx.run("SELECT backup_mark_ok(48000000)")
    age, size = health(fx)
    assert size == 48_000_000 and 0 <= age < 60


@pytest.mark.parametrize("bad", ["0", "-5", "NULL"])
def test_a_dump_of_no_bytes_is_refused_and_changes_nothing(fx: Fixture, bad: str) -> None:
    set_state(fx, ok_hours_ago=30, started_hours_ago=500)
    with pytest.raises(psycopg.errors.RaiseException):
        fx.run(f"SELECT backup_mark_ok({bad}::bigint)")
    age, size = health(fx)
    assert size == 1234 and 108000 <= age <= 108200


def test_it_reports_two_numbers_and_nothing_else(fx: Fixture) -> None:
    with fx.worker() as w:
        cur = w.execute("SELECT * FROM backup_health()")
        names = [d.name for d in cur.description or []]
        rows = cur.fetchall()
    assert names == ["age_s", "bytes"] and len(rows) == 1


def test_there_is_only_ever_one_row(fx: Fixture) -> None:
    assert fx.one("SELECT count(*) FROM backup_state") == (1,)
    with pytest.raises(psycopg.errors.UniqueViolation):
        fx.run("INSERT INTO backup_state (id) VALUES (true)")
    with pytest.raises(psycopg.errors.CheckViolation):
        fx.run("INSERT INTO backup_state (id) VALUES (false)")


# ---- who may do what ----


def can_execute(fx: Fixture, role: str, function: str) -> bool:
    row = fx.one("SELECT has_function_privilege(%s, %s::regprocedure, 'EXECUTE')", (role, function))
    return bool(row[0])


def test_no_service_role_may_record_a_backup(fx: Fixture) -> None:
    for role in (*SERVICE_ROLES, "soc_worker_writer", "public"):
        assert not can_execute(fx, role, "backup_mark_ok(bigint)"), role


def test_the_worker_login_really_cannot_record_a_backup(fx: Fixture) -> None:
    with fx.worker() as w, pytest.raises(psycopg.errors.InsufficientPrivilege):
        w.execute("SELECT backup_mark_ok(1000)")
    assert health(fx)[1] is None  # nothing was recorded


def test_only_the_worker_login_can_ask_how_old_the_last_backup_is(fx: Fixture) -> None:
    for role in ("soc_app", "soc_ingest", "soc_console", "soc_reconcile", "public"):
        assert not can_execute(fx, role, "backup_health()"), role
    assert can_execute(fx, "soc_worker", "backup_health()")
    for role in ("soc_app", "soc_ingest", "soc_console", "soc_reconcile"):
        with fx.db.connect(role) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM backup_health()")


def test_the_health_function_is_a_definer_with_a_pinned_search_path(fx: Fixture) -> None:
    row = fx.one(
        "SELECT p.prosecdef, p.proconfig, r.rolname FROM pg_proc p "
        "JOIN pg_roles r ON r.oid = p.proowner WHERE p.proname = 'backup_health'"
    )
    assert row[0] is True and row[2] == "soc_worker_writer"
    assert row[1] and any(x.startswith("search_path=pg_catalog") for x in row[1])
    mark = fx.one("SELECT p.prosecdef, p.proconfig FROM pg_proc p WHERE proname = 'backup_mark_ok'")
    assert mark[0] is False  # it runs with the caller's rights: the superuser's
    assert mark[1] and any(x.startswith("search_path=pg_catalog") for x in mark[1])


def test_no_login_can_read_or_write_the_table(fx: Fixture) -> None:
    for role in SERVICE_ROLES:
        with fx.db.connect(role) as c:
            for query in (
                "SELECT * FROM backup_state",
                "UPDATE backup_state SET last_bytes = 1",
                "DELETE FROM backup_state",
            ):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    c.execute(query)


def test_the_worker_writer_reads_three_columns_and_changes_nothing(fx: Fixture) -> None:
    def rights(column: str, privilege: str) -> bool:
        row = fx.one(
            "SELECT has_column_privilege('soc_worker_writer', 'backup_state', %s, %s)",
            (column, privilege),
        )
        return bool(row[0])

    for column in ("started_at", "last_ok_at", "last_bytes"):
        assert rights(column, "SELECT"), column
    assert not rights("id", "SELECT")
    for column in ("id", "started_at", "last_ok_at", "last_bytes"):
        for privilege in ("INSERT", "UPDATE"):
            assert not rights(column, privilege), (column, privilege)
    delete = fx.one("SELECT has_table_privilege('soc_worker_writer', 'backup_state', 'DELETE')")
    assert delete == (False,)


def test_the_table_has_row_level_security_on(fx: Fixture) -> None:
    assert fx.one("SELECT relrowsecurity FROM pg_class WHERE relname = 'backup_state'") == (True,)


# ---- the migration itself ----


def test_downgrading_removes_it_all_and_upgrading_brings_it_back(db: TestDb, fx: Fixture) -> None:
    url = db.sqlalchemy_url()
    soc_db.downgrade(url, "0007")
    with db.connect() as c:
        assert c.execute("SELECT to_regprocedure('backup_health()')").fetchone() == (None,)
        assert c.execute("SELECT to_regprocedure('backup_mark_ok(bigint)')").fetchone() == (None,)
        assert c.execute("SELECT to_regclass('backup_state')").fetchone() == (None,)
        assert c.execute(
            "SELECT count(*) FROM pg_policies WHERE policyname = 'worker_backup_read'"
        ).fetchone() == (0,)
    soc_db.upgrade(url)
    assert health(fx)[1] is None
