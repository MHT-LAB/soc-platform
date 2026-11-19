"""The rotate service's wiring, checked statically: it must not be able to reach a vendor, a
secret or the database, because this build only plans and records."""

from pathlib import Path
from typing import Any

import yaml

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
COMPOSE: dict[str, Any] = yaml.safe_load((DEPLOY / "compose.yml").read_text())
SERVICES = COMPOSE["services"]
ROTATE = SERVICES["rotate"]


def test_it_runs_only_when_asked_and_never_restarts() -> None:
    assert ROTATE["profiles"] == ["rotate"]  # `up -d` never starts it
    assert ROTATE["restart"] == "no"
    assert ROTATE["entrypoint"] == ["python", "-m", "soc_api.rotate"]
    assert "command" not in ROTATE  # the script's arguments are appended to the entrypoint
    assert "depends_on" not in ROTATE
    assert ROTATE["image"] == SERVICES["api"]["image"]


def test_it_has_no_network_at_all() -> None:
    assert ROTATE["network_mode"] == "none"
    assert "networks" not in ROTATE and "ports" not in ROTATE and "expose" not in ROTATE


def test_it_is_given_no_secret_and_no_settings_file() -> None:
    assert "env_file" not in ROTATE
    assert set(ROTATE["environment"]) == {
        "SOC_ENV",
        "SOC_ROTATE_COMMIT",
        "SOC_ROTATE_KEYS_DIR",
        "SOC_ROTATE_STATE",
    }


def test_the_register_is_read_only_and_there_is_one_writable_folder() -> None:
    vols = ROTATE["volumes"]
    assert len(vols) == 2
    assert vols[0].endswith("/keys:/keys:ro")
    assert vols[1].endswith("/rotate:/state") and not vols[1].endswith(":ro")


def test_it_is_hardened_like_the_other_one_shot_services() -> None:
    assert ROTATE["read_only"] is True
    assert ROTATE["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in ROTATE["security_opt"]
    assert ROTATE["tmpfs"] == ["/tmp"]  # noqa: S108 - the container's scratch space
    assert "mem_limit" in ROTATE and "pids_limit" in ROTATE
    assert "user" not in ROTATE or ROTATE["user"] != "0"


def test_only_the_rotate_script_ever_turns_the_profile_on() -> None:
    for script in DEPLOY.glob("*.sh"):
        if script.name == "rotate.sh":
            continue
        text = script.read_text()
        assert ",rotate" not in text and "=rotate" not in text and "--profile rotate" not in text, (
            f"{script.name} must not turn the rotate profile on"
        )
    assert "--profile rotate run" in (DEPLOY / "rotate.sh").read_text()


def test_the_daily_plan_only_plans() -> None:
    service = (DEPLOY / "systemd" / "soc-rotate-plan.service").read_text()
    assert "ExecStart=/opt/soc-platform/deploy/rotate.sh --plan --quiet" in service
    timer = (DEPLOY / "systemd" / "soc-rotate-plan.timer").read_text()
    assert "OnCalendar=*-*-* 09:00:00 America/New_York" in timer
    assert "Persistent=true" in timer
