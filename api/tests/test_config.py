"""Prod must fail closed: no console allowlist, no start."""

import os
import subprocess
import sys

import pytest
from pydantic import ValidationError

from soc_api.config import Settings


@pytest.mark.parametrize("users", ["", "   ", ",", " , ,"])
def test_prod_refuses_to_start_without_console_users(users: str) -> None:
    with pytest.raises(ValidationError, match="SOC_CONSOLE_USERS"):
        Settings(env="prod", console_users=users)


def test_env_defaults_to_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    # Forgetting SOC_ENV must never open the console.
    monkeypatch.delenv("SOC_ENV")
    assert Settings(console_users="a@example.com").env == "prod"
    with pytest.raises(ValidationError, match="SOC_CONSOLE_USERS"):
        Settings(console_users="")


def test_prod_starts_with_a_login_and_dev_may_omit_it() -> None:
    assert Settings(env="prod", console_users="a@example.com").console_allowlist == {
        "a@example.com"
    }
    assert Settings(env="dev").console_allowlist == set()


def test_validation_error_does_not_echo_secrets() -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(env="prod", console_users="", lc_api_key="super-secret-value")  # type: ignore[arg-type]
    assert "super-secret-value" not in str(exc.value)


def test_importing_the_app_in_prod_without_users_exits_nonzero() -> None:
    """The real startup path: uvicorn imports soc_api.main, which builds the app."""
    env = {
        **os.environ,
        "SOC_ENV": "prod",
        "SOC_CONSOLE_USERS": "",
        "SOC_LC_API_KEY": "super-secret-value",
    }
    r = subprocess.run(
        [sys.executable, "-c", "import soc_api.main"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode != 0
    assert "SOC_CONSOLE_USERS" in r.stderr
    assert "super-secret-value" not in r.stderr + r.stdout
