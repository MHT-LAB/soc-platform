"""Database migrations.

The schema lives in Alembic migrations (soc_api/migrations). Run them as the
owner role, never as the roles the services use:

    SOC_MIGRATE_URL=postgresql+psycopg://owner@host/db python -m soc_api.db upgrade
"""

import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

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


def main(argv: list[str]) -> int:
    url = os.environ.get("SOC_MIGRATE_URL")
    if not url or argv not in (["upgrade"], ["downgrade"]):
        print("usage: SOC_MIGRATE_URL=<owner url> python -m soc_api.db upgrade|downgrade")
        return 2
    if argv == ["upgrade"]:
        upgrade(url)
    else:
        downgrade(url, "-1")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
