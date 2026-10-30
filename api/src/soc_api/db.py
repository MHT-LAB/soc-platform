"""Database migrations.

The schema lives in Alembic migrations (soc_api/migrations). Run them as the
owner role, never as the roles the services use:

    SOC_MIGRATE_URL=postgresql+psycopg://owner@host/db python -m soc_api.db upgrade

`logins` gives the soc_ingest role its password (from SOC_INGEST_DB_PASSWORD) and,
when SOC_WORKER_DB_PASSWORD is set, the soc_worker role its password, and when
SOC_CONSOLE_DB_PASSWORD is set, the soc_console role its password;
`deploy` is `upgrade` then `logins`, which is what the deploy script runs.
"""

import os
import sys
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from psycopg import sql
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

MIGRATIONS = Path(__file__).parent / "migrations"


def _config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def newer_revision(url: str) -> str | None:
    """The database's revision if this code does not know it (a newer release ran)."""
    known = {s.revision for s in ScriptDirectory.from_config(_config(url)).walk_revisions()}
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            heads = MigrationContext.configure(conn).get_current_heads()
    finally:
        engine.dispose()
    return next((h for h in heads if h not in known), None)


def upgrade(url: str, revision: str = "head") -> None:
    # A manual rollback (deploy.sh <older tag>) runs the older image's migrate job
    # against a schema a newer release already moved forward. Migrations are
    # expand-then-contract, so the older code works with it; Alembic would instead stop
    # with "can't locate revision" and the rollback would be refused.
    if revision == "head" and (newer := newer_revision(url)):
        print(f"database is at revision {newer}, newer than this release; not migrating")
        return
    command.upgrade(_config(url), revision)


def downgrade(url: str, revision: str) -> None:
    command.downgrade(_config(url), revision)


# The role is created NOLOGIN by the migration. This is the only place it gets a
# login, a connection cap and a password.
INGEST_ROLE = "soc_ingest"
INGEST_CONNECTION_LIMIT = 10
WORKER_ROLE = "soc_worker"
WORKER_CONNECTION_LIMIT = 5
CONSOLE_ROLE = "soc_console"
CONSOLE_CONNECTION_LIMIT = 5
RECONCILE_ROLE = "soc_reconcile"
RECONCILE_CONNECTION_LIMIT = 3
MIN_PASSWORD_LENGTH = 32


def _set_login(url: str, role: str, limit: int, password: str) -> None:
    """Let `role` log in with `password`. Safe to run on every deploy.

    The password is turned into a SCRAM-SHA-256 verifier here, on the client, so
    the server (and its error log) never sees the plain value. Nothing else about
    the role changes: it still has no table privileges.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"the {role} password must be at least {MIN_PASSWORD_LENGTH} characters")
    # Exactly the parts psycopg understands, taken from the SQLAlchemy URL.
    sa = make_url(url)
    with psycopg.connect(
        host=sa.host,
        port=sa.port,
        dbname=sa.database,
        user=sa.username,
        password=sa.password,
        connect_timeout=10,
        autocommit=True,
    ) as conn:
        verifier = conn.pgconn.encrypt_password(
            password.encode(), role.encode(), b"scram-sha-256"
        ).decode()
        conn.execute(
            sql.SQL("ALTER ROLE {} LOGIN CONNECTION LIMIT {} PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(limit), sql.Literal(verifier)
            )
        )


def set_ingest_login(url: str, password: str) -> None:
    _set_login(url, INGEST_ROLE, INGEST_CONNECTION_LIMIT, password)


def set_worker_login(url: str, password: str) -> None:
    _set_login(url, WORKER_ROLE, WORKER_CONNECTION_LIMIT, password)


def set_console_login(url: str, password: str) -> None:
    _set_login(url, CONSOLE_ROLE, CONSOLE_CONNECTION_LIMIT, password)


def set_reconcile_login(url: str, password: str) -> None:
    _set_login(url, RECONCILE_ROLE, RECONCILE_CONNECTION_LIMIT, password)


def main(argv: list[str]) -> int:
    url = os.environ.get("SOC_MIGRATE_URL")
    if not url or argv not in (["upgrade"], ["downgrade"], ["logins"], ["deploy"]):
        print(
            "usage: SOC_MIGRATE_URL=<owner url> python -m soc_api.db "
            "upgrade|downgrade|logins|deploy"
        )
        return 2
    if argv == ["downgrade"]:
        downgrade(url, "-1")
        return 0
    if argv in (["upgrade"], ["deploy"]):
        upgrade(url)
    if argv in (["logins"], ["deploy"]):
        password = os.environ.get("SOC_INGEST_DB_PASSWORD", "")
        try:
            set_ingest_login(url, password)
            # Optional until the worker is set up on the host; once the variable is
            # set it must be valid.
            worker_password = os.environ.get("SOC_WORKER_DB_PASSWORD", "")
            if worker_password:
                set_worker_login(url, worker_password)
            console_password = os.environ.get("SOC_CONSOLE_DB_PASSWORD", "")
            if console_password:
                set_console_login(url, console_password)
            reconcile_password = os.environ.get("SOC_RECONCILE_DB_PASSWORD", "")
            if reconcile_password:
                set_reconcile_login(url, reconcile_password)
        except ValueError as exc:
            print(exc)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
