"""Database migrations.

The schema lives in Alembic migrations (soc_api/migrations). Run them as the
owner role, never as the roles the services use:

    SOC_MIGRATE_URL=postgresql+psycopg://owner@host/db python -m soc_api.db upgrade

`logins` gives the soc_ingest role its password (from SOC_INGEST_DB_PASSWORD);
`deploy` is `upgrade` then `logins`, which is what the deploy script runs.
"""

import os
import sys
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy.engine import make_url

MIGRATIONS = Path(__file__).parent / "migrations"


def _config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def upgrade(url: str, revision: str = "head") -> None:
    command.upgrade(_config(url), revision)


def downgrade(url: str, revision: str) -> None:
    command.downgrade(_config(url), revision)


# The role is created NOLOGIN by the migration. This is the only place it gets a
# login, a connection cap and a password.
INGEST_ROLE = "soc_ingest"
INGEST_CONNECTION_LIMIT = 10
MIN_PASSWORD_LENGTH = 32


def set_ingest_login(url: str, password: str) -> None:
    """Let soc_ingest log in with `password`. Safe to run on every deploy.

    The password is turned into a SCRAM-SHA-256 verifier here, on the client, so
    the server (and its error log) never sees the plain value. Nothing else about
    the role changes: it still has no table privileges.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"the {INGEST_ROLE} password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
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
            password.encode(), INGEST_ROLE.encode(), b"scram-sha-256"
        ).decode()
        conn.execute(
            sql.SQL("ALTER ROLE {} LOGIN CONNECTION LIMIT {} PASSWORD {}").format(
                sql.Identifier(INGEST_ROLE),
                sql.Literal(INGEST_CONNECTION_LIMIT),
                sql.Literal(verifier),
            )
        )


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
        except ValueError as exc:
            print(exc)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
