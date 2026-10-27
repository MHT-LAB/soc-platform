"""The compose file's database wiring, checked statically (the live checks are in
scripts/test-db-stack.sh, which needs Docker)."""

from pathlib import Path
from typing import Any

import pytest
import yaml

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
COMPOSE: dict[str, Any] = yaml.safe_load((DEPLOY / "compose.yml").read_text())
OVERLAY: dict[str, Any] = yaml.safe_load((DEPLOY / "compose.stage-a.yml").read_text())
SERVICES = COMPOSE["services"]


def test_the_database_network_is_internal() -> None:
    assert COMPOSE["networks"]["db"] == {"internal": True}


def test_only_api_db_and_migrate_are_on_the_database_network() -> None:
    on_db = {n for n, s in SERVICES.items() if "db" in s.get("networks", [])}
    assert on_db == {"api", "db", "migrate"}
    # The tunnel (overlay) keeps the default network only.
    assert "networks" not in OVERLAY["services"]["tunnel"]
    # db and migrate are not on the default network the tunnel shares.
    assert SERVICES["db"]["networks"] == ["db"]
    assert SERVICES["migrate"]["networks"] == ["db"]
    assert SERVICES["api"]["networks"] == ["default", "db"]


def test_the_database_publishes_nothing_on_the_host() -> None:
    assert "ports" not in SERVICES["db"]
    assert SERVICES["db"].get("network_mode") is None


def test_api_does_not_depend_on_the_database() -> None:
    # A database outage must answer 503, not stop /healthz or fail a deploy.
    assert "depends_on" not in SERVICES["api"]


def test_up_never_starts_the_migration_job() -> None:
    assert SERVICES["migrate"]["profiles"] == ["migrate"]
    assert SERVICES["migrate"]["restart"] == "no"
    assert SERVICES["db"]["profiles"] == ["db"]


@pytest.mark.parametrize("name", ["db", "migrate"])
def test_database_services_are_hardened_like_the_others(name: str) -> None:
    svc = SERVICES[name]
    assert svc["read_only"] is True
    assert svc["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in svc["security_opt"]
    assert "mem_limit" in svc
    assert "pids_limit" in svc


def test_database_runs_unprivileged_with_a_digest_pinned_image() -> None:
    db = SERVICES["db"]
    assert db["user"] == "999:999"
    assert "@sha256:" in db["image"]


def test_the_database_image_matches_the_one_ci_tests_against() -> None:
    ci = (DEPLOY.parent / ".github" / "workflows" / "ci.yml").read_text()
    assert SERVICES["db"]["image"] in ci


def test_the_healthcheck_uses_tcp_so_the_init_server_does_not_count() -> None:
    assert "127.0.0.1" in SERVICES["db"]["healthcheck"]["test"]


def test_db_env_files_are_required_and_never_given_to_the_public_app() -> None:
    assert SERVICES["db"]["env_file"][0]["required"] is True
    assert SERVICES["migrate"]["env_file"][0]["required"] is True
    for name in ("api", "console"):
        paths = [e["path"] for e in SERVICES[name].get("env_file", [])]
        assert not any("db.env" in p or "db-owner.env" in p for p in paths)


def test_the_owner_url_never_reaches_a_long_running_service() -> None:
    for name in ("api", "console", "db"):
        env = SERVICES[name].get("environment", {})
        assert "SOC_MIGRATE_URL" not in env
