"""The deploy-time database steps: the soc_ingest login and the seed CLI."""

import base64
import hashlib
import hmac
import json
from pathlib import Path

import psycopg
import pytest
from conftest import SEED_FILE, TestDb

from soc_api import db as soc_db
from soc_api import seed as soc_seed

PASSWORD = "p" * 40  # noqa: S105 - throwaway test value


def scram_matches(verifier: str, password: str) -> bool:
    """Recompute a SCRAM-SHA-256 stored verifier from the password (RFC 5802)."""
    scheme, rest = verifier.split("$", 1)
    params, keys = rest.split("$", 1)
    iterations, salt = params.split(":", 1)
    stored_key, _server_key = keys.split(":", 1)
    salted = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), base64.b64decode(salt), int(iterations)
    )
    client_key = hmac.new(salted, b"Client Key", "sha256").digest()
    return scheme == "SCRAM-SHA-256" and (
        base64.b64encode(hashlib.sha256(client_key).digest()).decode() == stored_key
    )


def role_row(db: TestDb) -> tuple[bool, int, str | None]:
    with db.connect() as c:
        row = c.execute(
            "SELECT rolcanlogin, rolconnlimit, rolpassword FROM pg_authid "
            "WHERE rolname = 'soc_ingest'"
        ).fetchone()
    assert row is not None
    return row


# ---- soc_ingest login ----


def test_logins_gives_soc_ingest_a_scram_login_with_a_connection_cap(db: TestDb) -> None:
    # The fixture's own login shortcut is undone so this test sees the real default.
    with db.connect() as c:
        c.execute("ALTER ROLE soc_ingest NOLOGIN PASSWORD NULL CONNECTION LIMIT -1")
    assert role_row(db)[0] is False
    soc_db.set_ingest_login(db.sqlalchemy_url(), PASSWORD)
    can_login, limit, verifier = role_row(db)
    assert can_login is True
    assert limit == soc_db.INGEST_CONNECTION_LIMIT
    assert verifier is not None
    assert scram_matches(verifier, PASSWORD)
    assert not scram_matches(verifier, PASSWORD + "x")


def test_logins_never_sends_the_plain_password_to_the_server(
    db: TestDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[object] = []
    real = psycopg.Connection.execute

    def spy(self: psycopg.Connection, query: object, *args: object, **kw: object) -> object:
        sent.append(query.as_string(self) if hasattr(query, "as_string") else query)  # type: ignore[attr-defined]
        return real(self, query, *args, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(psycopg.Connection, "execute", spy)
    soc_db.set_ingest_login(db.sqlalchemy_url(), PASSWORD)
    assert sent
    assert all(PASSWORD not in str(q) for q in sent)


def test_logins_is_idempotent_and_a_new_password_replaces_the_old(db: TestDb) -> None:
    soc_db.set_ingest_login(db.sqlalchemy_url(), PASSWORD)
    soc_db.set_ingest_login(db.sqlalchemy_url(), "q" * 40)
    verifier = role_row(db)[2]
    assert verifier is not None
    assert scram_matches(verifier, "q" * 40)
    assert not scram_matches(verifier, PASSWORD)


def test_logins_leaves_soc_ingest_without_table_privileges(db: TestDb) -> None:
    soc_db.set_ingest_login(db.sqlalchemy_url(), PASSWORD)
    with db.connect() as c:
        granted = c.execute(
            "SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'soc_ingest'"
        ).fetchone()
        flags = c.execute(
            "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles "
            "WHERE rolname = 'soc_ingest'"
        ).fetchone()
    assert granted == (0,)
    assert flags == (False, False, False, False)


@pytest.mark.parametrize("password", ["", "short", "x" * 31])
def test_logins_refuses_a_short_or_missing_password(db: TestDb, password: str) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_ingest NOLOGIN")
    with pytest.raises(ValueError, match="at least"):
        soc_db.set_ingest_login(db.sqlalchemy_url(), password)
    assert role_row(db)[0] is False


def test_deploy_command_migrates_then_sets_the_login(
    db: TestDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    soc_db.downgrade(db.sqlalchemy_url(), "base")
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    assert soc_db.main(["deploy"]) == 0
    with db.connect() as c:
        assert c.execute("SELECT count(*) FROM client").fetchone() == (1,)  # Unassigned
    verifier = role_row(db)[2]
    assert verifier is not None
    assert scram_matches(verifier, PASSWORD)


def test_deploy_command_without_a_password_fails_after_migrating(
    db: TestDb, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.delenv("SOC_INGEST_DB_PASSWORD", raising=False)
    assert soc_db.main(["deploy"]) == 2
    assert "at least" in capsys.readouterr().out


def test_db_cli_rejects_unknown_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_MIGRATE_URL", "postgresql+psycopg://x@localhost/x")
    assert soc_db.main(["drop"]) == 2
    assert soc_db.main([]) == 2


# ---- seed CLI ----


def counts(db: TestDb) -> dict[str, int]:
    with db.connect() as c:
        return {
            t: c.execute(f"SELECT count(*) FROM {t}").fetchone()[0]  # type: ignore[index]  # noqa: S608
            for t in ("client", "site", "endpoint", "source")
        }


def write_seed(tmp_path: Path, **overrides: object) -> Path:
    data = json.loads(SEED_FILE.read_text())
    data.update(overrides)
    path = tmp_path / "seed.json"
    path.write_text(json.dumps(data))
    return path


def test_seed_twice_changes_nothing_the_second_time(db: TestDb) -> None:
    soc_seed.seed(db.sqlalchemy_url(), SEED_FILE)
    first = counts(db)
    soc_seed.seed(db.sqlalchemy_url(), SEED_FILE)
    assert counts(db) == first
    assert first == {"client": 2, "site": 1, "endpoint": 2, "source": 1}


def test_seed_accepts_several_sources_and_no_sites(db: TestDb, tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    path.write_text(
        json.dumps(
            {
                "client": {
                    "slug": "mht",
                    "name": "MHT",
                    "tenant_id": "org-1",
                    "status": "internal",
                },
                "sources": [
                    {"slug": "lc-main", "type": "limacharlie", "external_id": "org-1"},
                    {"slug": "lc-second", "type": "limacharlie", "external_id": "org-1"},
                ],
            }
        )
    )
    soc_seed.seed(db.sqlalchemy_url(), path)
    assert counts(db) == {"client": 2, "site": 0, "endpoint": 0, "source": 2}


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"client": {"slug": "acme-demo", "name": "Other Name"}}, "client 'acme-demo'"),
        (
            {"source": {"slug": "acme-lc", "type": "edr-webhook", "external_id": "other-org"}},
            "source 'acme-lc' exists with different external_id",
        ),
        (
            {"sites": [{"name": "Acme HQ", "controller_site_id": "changed"}]},
            "site 'Acme HQ'",
        ),
    ],
)
def test_seed_refuses_a_row_that_clashes_and_changes_nothing(
    db: TestDb, tmp_path: Path, change: dict[str, object], message: str
) -> None:
    soc_seed.seed(db.sqlalchemy_url(), SEED_FILE)
    before = counts(db)
    clash = write_seed(tmp_path, **change)
    with pytest.raises(soc_seed.SeedConflict, match=message):
        soc_seed.seed(db.sqlalchemy_url(), clash)
    assert counts(db) == before


def test_seed_cannot_point_an_existing_source_at_another_client(db: TestDb, tmp_path: Path) -> None:
    soc_seed.seed(db.sqlalchemy_url(), SEED_FILE)
    path = tmp_path / "other.json"
    path.write_text(
        json.dumps(
            {
                "client": {"slug": "other", "name": "Other"},
                "sources": [{"slug": "acme-lc", "type": "edr-webhook"}],
            }
        )
    )
    with pytest.raises(soc_seed.SeedConflict, match="client_id"):
        soc_seed.seed(db.sqlalchemy_url(), path)
    with db.connect() as c:
        row = c.execute(
            "SELECT c.slug FROM source s JOIN client c ON c.id = s.client_id "
            "WHERE s.slug = 'acme-lc'"
        ).fetchone()
    assert row == ("acme-demo",)


def test_seed_is_all_or_nothing(db: TestDb, tmp_path: Path) -> None:
    # The new client row is inserted first; the bad endpoint must undo it.
    path = write_seed(
        tmp_path,
        client={"slug": "fresh", "name": "Fresh"},
        sites=[],
        endpoints=[{"sensor_id": "s1", "hostname": "h", "platform": "linux", "site": "Nope"}],
        source={"slug": "fresh-src", "type": "x"},
    )
    with pytest.raises(soc_seed.SeedConflict, match="unknown site"):
        soc_seed.seed(db.sqlalchemy_url(), path)
    assert counts(db) == {"client": 1, "site": 0, "endpoint": 0, "source": 0}


def test_seed_cli_exit_codes(
    db: TestDb, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert soc_seed.main([]) == 2
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    assert soc_seed.main([str(SEED_FILE)]) == 0
    clash = write_seed(tmp_path, client={"slug": "acme-demo", "name": "Different"})
    assert soc_seed.main([str(clash)]) == 1
    assert "nothing changed" in capsys.readouterr().out


# ---- soc_worker login (optional until the worker is set up on the host) ----


def worker_row(db: TestDb) -> tuple[bool, int, str | None]:
    with db.connect() as c:
        row = c.execute(
            "SELECT rolcanlogin, rolconnlimit, rolpassword FROM pg_authid "
            "WHERE rolname = 'soc_worker'"
        ).fetchone()
    assert row is not None
    return row


def test_worker_login_is_a_scram_verifier_with_its_own_connection_cap(db: TestDb) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_worker NOLOGIN PASSWORD NULL CONNECTION LIMIT -1")
    soc_db.set_worker_login(db.sqlalchemy_url(), PASSWORD)
    can_login, limit, verifier = worker_row(db)
    assert can_login is True and limit == soc_db.WORKER_CONNECTION_LIMIT
    assert verifier is not None and scram_matches(verifier, PASSWORD)
    assert not scram_matches(verifier, "x" * 40)


@pytest.mark.parametrize("password", ["", "short", "x" * 31])
def test_worker_login_refuses_a_short_password(db: TestDb, password: str) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_worker NOLOGIN")
    with pytest.raises(ValueError, match="soc_worker password must be at least"):
        soc_db.set_worker_login(db.sqlalchemy_url(), password)
    assert worker_row(db)[0] is False


def test_deploy_sets_the_worker_login_when_its_password_is_given(
    db: TestDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_worker NOLOGIN PASSWORD NULL")
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    monkeypatch.setenv("SOC_WORKER_DB_PASSWORD", "w" * 40)
    assert soc_db.main(["deploy"]) == 0
    verifier = worker_row(db)[2]
    assert verifier is not None and scram_matches(verifier, "w" * 40)


def test_deploy_without_a_worker_password_leaves_the_worker_login_alone(
    db: TestDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_worker NOLOGIN PASSWORD NULL")
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    monkeypatch.delenv("SOC_WORKER_DB_PASSWORD", raising=False)
    assert soc_db.main(["deploy"]) == 0
    assert worker_row(db)[0] is False and worker_row(db)[2] is None


def test_deploy_stops_on_a_worker_password_that_is_set_but_too_short(
    db: TestDb, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    monkeypatch.setenv("SOC_WORKER_DB_PASSWORD", "short")
    assert soc_db.main(["deploy"]) == 2
    assert "soc_worker password must be at least" in capsys.readouterr().out


# ---- rollback to an older release ----


def test_a_database_newer_than_the_code_is_left_alone_so_a_rollback_can_deploy(
    db: TestDb, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """What an older image's migrate job sees after a newer release migrated."""
    with db.connect() as c:
        c.execute("UPDATE alembic_version SET version_num = '9999_from_the_future'")
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    assert soc_db.main(["deploy"]) == 0
    assert "newer than this release" in capsys.readouterr().out
    with db.connect() as c:
        assert c.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "9999_from_the_future",
        )
    verifier = role_row(db)[2]
    assert verifier is not None and scram_matches(verifier, PASSWORD)  # logins still ran


def test_a_known_revision_still_upgrades_normally(db: TestDb) -> None:
    soc_db.downgrade(db.sqlalchemy_url(), "0001")
    assert soc_db.newer_revision(db.sqlalchemy_url()) is None
    soc_db.upgrade(db.sqlalchemy_url())
    with db.connect() as c:
        assert c.execute("SELECT version_num FROM alembic_version").fetchone() == ("0007",)


# ---- soc_console login (optional until the console reads cases) ----


def console_row(db: TestDb) -> tuple[bool, int, str | None]:
    with db.connect() as c:
        row = c.execute(
            "SELECT rolcanlogin, rolconnlimit, rolpassword FROM pg_authid "
            "WHERE rolname = 'soc_console'"
        ).fetchone()
    assert row is not None
    return row


def test_console_login_is_a_scram_verifier_with_its_own_connection_cap(db: TestDb) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_console NOLOGIN PASSWORD NULL CONNECTION LIMIT -1")
    soc_db.set_console_login(db.sqlalchemy_url(), PASSWORD)
    can_login, limit, verifier = console_row(db)
    assert can_login is True and limit == soc_db.CONSOLE_CONNECTION_LIMIT
    assert verifier is not None and scram_matches(verifier, PASSWORD)
    assert not scram_matches(verifier, "x" * 40)


@pytest.mark.parametrize("password", ["", "short", "x" * 31])
def test_console_login_refuses_a_short_password(db: TestDb, password: str) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_console NOLOGIN")
    with pytest.raises(ValueError, match="soc_console password must be at least"):
        soc_db.set_console_login(db.sqlalchemy_url(), password)
    assert console_row(db)[0] is False


def test_deploy_sets_the_console_login_when_its_password_is_given(
    db: TestDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_console NOLOGIN PASSWORD NULL")
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    monkeypatch.setenv("SOC_CONSOLE_DB_PASSWORD", "c" * 40)
    assert soc_db.main(["deploy"]) == 0
    verifier = console_row(db)[2]
    assert verifier is not None and scram_matches(verifier, "c" * 40)


def test_deploy_without_a_console_password_leaves_the_console_login_alone(
    db: TestDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_console NOLOGIN PASSWORD NULL")
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    monkeypatch.delenv("SOC_CONSOLE_DB_PASSWORD", raising=False)
    assert soc_db.main(["deploy"]) == 0
    assert console_row(db)[0] is False and console_row(db)[2] is None


def test_deploy_stops_on_a_console_password_that_is_set_but_too_short(
    db: TestDb, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    monkeypatch.setenv("SOC_CONSOLE_DB_PASSWORD", "short")
    assert soc_db.main(["deploy"]) == 2
    assert "soc_console password must be at least" in capsys.readouterr().out


# ---- soc_reconcile login (optional until the catch-up worker is set up) ----


def reconcile_row(db: TestDb) -> tuple[bool, int, str | None]:
    with db.connect() as c:
        row = c.execute(
            "SELECT rolcanlogin, rolconnlimit, rolpassword FROM pg_authid "
            "WHERE rolname = 'soc_reconcile'"
        ).fetchone()
    assert row is not None
    return row


def test_reconcile_login_is_a_scram_verifier_with_its_own_connection_cap(db: TestDb) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_reconcile NOLOGIN PASSWORD NULL CONNECTION LIMIT -1")
    soc_db.set_reconcile_login(db.sqlalchemy_url(), PASSWORD)
    can_login, limit, verifier = reconcile_row(db)
    assert can_login is True and limit == soc_db.RECONCILE_CONNECTION_LIMIT
    assert verifier is not None and scram_matches(verifier, PASSWORD)
    assert not scram_matches(verifier, "x" * 40)


@pytest.mark.parametrize("password", ["", "short", "x" * 31])
def test_reconcile_login_refuses_a_short_password(db: TestDb, password: str) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_reconcile NOLOGIN")
    with pytest.raises(ValueError, match="soc_reconcile password must be at least"):
        soc_db.set_reconcile_login(db.sqlalchemy_url(), password)
    assert reconcile_row(db)[0] is False


def test_deploy_sets_the_reconcile_login_when_its_password_is_given(
    db: TestDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_reconcile NOLOGIN PASSWORD NULL")
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    monkeypatch.setenv("SOC_RECONCILE_DB_PASSWORD", "r" * 40)
    assert soc_db.main(["deploy"]) == 0
    verifier = reconcile_row(db)[2]
    assert verifier is not None and scram_matches(verifier, "r" * 40)


def test_deploy_without_a_reconcile_password_leaves_the_reconcile_login_alone(
    db: TestDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    with db.connect() as c:
        c.execute("ALTER ROLE soc_reconcile NOLOGIN PASSWORD NULL")
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    monkeypatch.delenv("SOC_RECONCILE_DB_PASSWORD", raising=False)
    assert soc_db.main(["deploy"]) == 0
    assert reconcile_row(db)[0] is False and reconcile_row(db)[2] is None


def test_deploy_stops_on_a_reconcile_password_that_is_set_but_too_short(
    db: TestDb, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SOC_MIGRATE_URL", db.sqlalchemy_url())
    monkeypatch.setenv("SOC_INGEST_DB_PASSWORD", PASSWORD)
    monkeypatch.setenv("SOC_RECONCILE_DB_PASSWORD", "short")
    assert soc_db.main(["deploy"]) == 2
    assert "soc_reconcile password must be at least" in capsys.readouterr().out
