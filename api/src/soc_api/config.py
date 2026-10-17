"""Runtime configuration.

Everything comes from environment variables prefixed with SOC_ (or env files
mounted by the deploy script). Nothing secret is ever baked into the image.
"""

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOC_")

    # "prod" hides the interactive API docs; "dev" shows them for local work.
    env: Literal["dev", "prod"] = "prod"
    # Stamped into the image at build time by CI.
    version: str = "0.0.0-dev"
    git_sha: str = "unknown"
    # The digest-pinned image reference the deploy script verified and ran.
    image_ref: str = ""

    # Console access. Requests must arrive through `tailscale serve`, which
    # adds the caller's verified tailnet login. Optionally restrict to a
    # comma-separated list of logins.
    console_users: str = ""

    # cloudflared readiness endpoint on the compose network (never published).
    tunnel_ready_url: str = "http://tunnel:2000/ready"

    # Read-only EDR platform API access, for the sensor fleet panel.
    lc_oid: str = ""
    lc_api_key: SecretStr = SecretStr("")

    @property
    def console_allowlist(self) -> set[str]:
        return {u.strip().lower() for u in self.console_users.split(",") if u.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
