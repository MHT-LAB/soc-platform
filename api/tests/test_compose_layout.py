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


def test_only_api_db_migrate_and_worker_are_on_the_database_network() -> None:
    on_db = {n for n, s in SERVICES.items() if "db" in s.get("networks", [])}
    assert on_db == {"api", "db", "migrate", "worker"}
    # The tunnel (overlay) keeps the default network only.
    assert "networks" not in OVERLAY["services"]["tunnel"]
    # db and migrate are not on the default network the tunnel shares.
    assert SERVICES["db"]["networks"] == ["db", "dbhost"]
    assert SERVICES["migrate"]["networks"] == ["db"]
    assert SERVICES["api"]["networks"] == ["default", "db"]


def test_the_database_publishes_one_port_on_the_hosts_loopback_only() -> None:
    # For the console (host network). Never 0.0.0.0, never a LAN address, nothing else.
    assert SERVICES["db"]["ports"] == ["127.0.0.1:5432:5432"]
    assert SERVICES["db"].get("network_mode") is None
    for name, svc in SERVICES.items():
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name} publishes {port} beyond loopback"


def test_the_publish_goes_through_a_network_only_the_database_is_on_and_that_cannot_route_out() -> (
    None
):
    # Docker publishes no port from an internal-only network, so the database needs one
    # more network; it must not become a way in for other containers or a way out.
    on = {n for n, s in SERVICES.items() if "dbhost" in s.get("networks", [])}
    assert on == {"db"}
    opts = COMPOSE["networks"]["dbhost"]["driver_opts"]
    assert opts["com.docker.network.bridge.enable_ip_masquerade"] == "false"
    assert "internal" not in COMPOSE["networks"]["dbhost"]
    assert COMPOSE["networks"]["db"] == {"internal": True}


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
        assert not {"db.env", "db-owner.env"} & set(env_files(name))


def test_the_owner_url_never_reaches_a_long_running_service() -> None:
    for name in ("api", "console", "db"):
        env = SERVICES[name].get("environment", {})
        assert "SOC_MIGRATE_URL" not in env


# ---- the pager worker ----

WORKER = SERVICES["worker"]


def test_the_worker_is_on_the_database_and_egress_networks_and_never_on_default() -> None:
    assert WORKER["networks"] == ["db", "egress"]  # `default` is the tunnel's network
    assert COMPOSE["networks"]["egress"] == {}  # outbound for pushes: not internal
    on_egress = {n for n, s in SERVICES.items() if "egress" in s.get("networks", [])}
    assert on_egress == {"worker"}
    assert "networks" not in OVERLAY["services"]["tunnel"]


def test_the_worker_listens_on_nothing_and_publishes_nothing() -> None:
    assert "ports" not in WORKER and "expose" not in WORKER
    assert WORKER.get("network_mode") is None


def test_the_worker_is_hardened_like_the_other_services() -> None:
    assert WORKER["read_only"] is True
    assert WORKER["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in WORKER["security_opt"]
    assert "mem_limit" in WORKER and "pids_limit" in WORKER
    assert "user" not in WORKER or WORKER["user"] != "0"
    assert WORKER["tmpfs"] == ["/tmp"]  # noqa: S108 - the health file lives here


def test_the_worker_is_optional_and_does_not_hold_up_a_deploy() -> None:
    assert WORKER["profiles"] == ["worker"]  # `up -d` never starts it without the profile
    assert "depends_on" not in WORKER  # a database outage must not fail a deploy
    assert WORKER["image"] == SERVICES["api"]["image"]
    assert WORKER["command"] == ["python", "-m", "soc_api.worker"]


def test_the_worker_has_a_healthcheck_on_its_own_heartbeat_file() -> None:
    test = " ".join(WORKER["healthcheck"]["test"])
    assert "/tmp/worker-health" in test  # noqa: S108
    from soc_api.config import Settings

    assert Settings().health_file == "/tmp/worker-health"  # noqa: S108


def env_files(name: str) -> dict[str, bool]:
    return {Path(e["path"]).name: e["required"] for e in SERVICES[name].get("env_file", [])}


def test_the_worker_secrets_go_to_the_worker_and_the_login_password_to_migrate_only() -> None:
    assert env_files("worker") == {"worker.env": True, "policy.env": False, "pager-ack.env": False}
    assert env_files("migrate") == {
        "db-owner.env": True,
        "worker-owner.env": False,
        "console-owner.env": False,
    }
    for name in ("api", "console", "db", "tunnel"):
        names = env_files(name) if name in SERVICES else {}
        assert not {"worker.env", "worker-owner.env", "policy.env"} & set(names), name
    assert "worker.env" not in " ".join(
        e["path"] for e in OVERLAY["services"]["tunnel"].get("env_file", [])
    )


def test_the_worker_never_gets_the_owner_the_ingest_or_the_edr_credentials() -> None:
    names = set(env_files("worker"))
    assert not names & {"db.env", "db-owner.env", "ingest.env", "console.env", "lc.env"}
    env = WORKER.get("environment", {})
    assert not {k for k in env if k.startswith(("SOC_MIGRATE", "SOC_INGEST", "SOC_LC"))}


# ---- the console's case pages ----


def test_the_console_form_secret_and_database_login_go_to_the_console_only() -> None:
    assert env_files("console") == {
        "lc.env": False,
        "console.env": False,
        "console-db.env": False,
        "pager-ack.env": False,
    }
    for name in ("api", "worker", "db", "migrate"):
        names = set(env_files(name))
        assert "console-db.env" not in names, name
    for name in ("api", "worker", "console", "db"):
        assert "console-owner.env" not in set(env_files(name)), name
    assert "console-db.env" not in " ".join(
        e["path"] for e in OVERLAY["services"]["tunnel"].get("env_file", [])
    )


def test_the_console_stays_on_the_host_network_and_never_gets_the_owner_credentials() -> None:
    console = SERVICES["console"]
    assert console["network_mode"] == "host" and "networks" not in console
    assert "ports" not in console
    env = console.get("environment", {})
    assert not {k for k in env if k.startswith(("SOC_MIGRATE", "SOC_INGEST", "SOC_WORKER"))}
    assert not {"db.env", "db-owner.env", "ingest.env", "worker.env"} & set(env_files("console"))


def test_the_phone_ack_key_goes_to_the_console_and_the_worker_only() -> None:
    holders = {n for n in SERVICES if "pager-ack.env" in env_files(n)}
    assert holders == {"console", "worker"}
    assert "pager-ack.env" not in " ".join(
        e["path"] for e in OVERLAY["services"]["tunnel"].get("env_file", [])
    )
    # the worker still never gets the form secret or the console's database login
    assert not {"console-db.env", "console-owner.env"} & set(env_files("worker"))
