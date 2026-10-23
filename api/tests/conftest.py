"""Test environment.

soc_api.main builds the app when it is imported, and prod refuses to start
without a console allowlist. Tests default to dev; the tests that care about
prod build their own Settings with env="prod" (explicit arguments win over the
environment).
"""

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from sqlalchemy.engine import URL

from soc_api import db as soc_db

os.environ["SOC_ENV"] = "dev"


# ---- Postgres for the schema tests ----
# SOC_TEST_DATABASE_URL points at a throwaway server and a role that can create
# databases and roles (CI uses a postgres service container). Without it the
# schema tests skip locally; with SOC_REQUIRE_DB=1 (set in CI) they fail instead,
# so a misconfigured job can't pass by skipping.

ROLE_PASSWORD = "test-only-password"  # noqa: S105 - throwaway test cluster
SEED_FILE = Path(__file__).resolve().parents[2] / "fixtures" / "acme-demo" / "seed.json"


@dataclass
class TestDb:
    __test__ = False  # not a test class

    name: str
    params: dict[str, str]

    def sqlalchemy_url(self, user: str | None = None, password: str | None = None) -> str:
        """The admin's URL by default (with its password, if the server wants one)."""
        if user is None:
            user, password = self.params.get("user", "postgres"), self.params.get("password")
        return URL.create(
            "postgresql+psycopg",
            username=user,
            password=password,
            host=self.params.get("host", "127.0.0.1"),
            port=int(self.params.get("port", "5432")),
            database=self.name,
        ).render_as_string(hide_password=False)

    def connect(self, role: str | None = None) -> psycopg.Connection:
        """Connect as the admin (role=None) or really log in as an app role."""
        params = {**self.params, "dbname": self.name}
        if role:
            params.update(user=role, password=ROLE_PASSWORD)
        return psycopg.connect(make_conninfo(**params), autocommit=True)


@pytest.fixture
def db() -> Iterator[TestDb]:
    url = os.environ.get("SOC_TEST_DATABASE_URL")
    if not url:
        if os.environ.get("SOC_REQUIRE_DB"):
            pytest.fail("SOC_REQUIRE_DB is set but SOC_TEST_DATABASE_URL is not")
        pytest.skip("SOC_TEST_DATABASE_URL not set")
    params = conninfo_to_dict(url)
    name = f"soc_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(make_conninfo(**params), autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    test_db = TestDb(name=name, params=params)
    soc_db.upgrade(test_db.sqlalchemy_url())
    # Roles are cluster-wide; give them a login so tests connect as the real thing.
    with test_db.connect() as admin:
        for role in ("soc_app", "soc_ingest"):
            admin.execute(f"ALTER ROLE {role} LOGIN PASSWORD '{ROLE_PASSWORD}'")
    yield test_db
    with psycopg.connect(make_conninfo(**params), autocommit=True) as admin:
        admin.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
