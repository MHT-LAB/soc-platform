"""Runtime configuration.

Everything comes from environment variables prefixed with SOC_ (or env files
mounted by the deploy script). Nothing secret is ever baked into the image.
"""

from functools import lru_cache
from typing import Literal, Self

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # hide_input_in_errors: a failed validation must not echo the settings it was
    # given, which would put the EDR key in the container logs.
    model_config = SettingsConfigDict(env_prefix="SOC_", hide_input_in_errors=True)

    # "prod" hides the interactive API docs; "dev" shows them for local work.
    env: Literal["dev", "prod"] = "prod"
    # Stamped into the image at build time by CI.
    version: str = "0.0.0-dev"
    git_sha: str = "unknown"
    # The digest-pinned image reference the deploy script verified and ran.
    image_ref: str = ""

    # Console access. Requests must arrive through `tailscale serve`, which
    # adds the caller's verified tailnet login. A comma-separated list of the
    # logins allowed in. Required in prod; only dev may leave it empty.
    console_users: str = ""

    # cloudflared readiness endpoint on the compose network (never published).
    tunnel_ready_url: str = "http://tunnel:2000/ready"

    # Read-only EDR platform API access, for the sensor fleet panel.
    lc_oid: str = ""
    lc_api_key: SecretStr = SecretStr("")

    @model_validator(mode="after")
    def require_console_users_in_prod(self) -> Self:
        # An empty allowlist accepts any login header, so prod refuses to start
        # without one rather than defaulting to open.
        if self.env == "prod" and not self.console_allowlist:
            raise ValueError("SOC_CONSOLE_USERS must list at least one login when SOC_ENV=prod")
        return self

    @property
    def console_allowlist(self) -> set[str]:
        return {u.strip().lower() for u in self.console_users.split(",") if u.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
