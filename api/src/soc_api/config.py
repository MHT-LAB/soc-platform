"""Runtime configuration.

Everything comes from environment variables prefixed with SOC_ (or env files
mounted by the deploy script). Nothing secret is ever baked into the image.
"""

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
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
    # logins allowed in. Read by the console service only; the console app
    # refuses to build in prod without it, and only dev may leave it empty.
    console_users: str = ""

    # cloudflared readiness endpoint, published on the host's loopback only. The
    # console service runs on the host network, so it reaches it there.
    tunnel_ready_url: str = "http://127.0.0.1:2000/ready"

    # Read-only EDR platform API access, for the sensor fleet panel.
    lc_oid: str = ""
    lc_api_key: SecretStr = SecretStr("")

    # Ingest (public app only; read from ingest.env, never from the image).
    # SOC_INGEST_SECRETS is JSON: {"<source slug>": ["<current>", "<next>"]}. Two
    # secrets per source let a rotation happen without downtime. A source with no
    # entry does not exist as far as the internet can tell.
    ingest_secrets: SecretStr = SecretStr("")
    # A role that can only call ingest_alert() (soc_ingest). Empty -> every
    # delivery that passes authentication gets a 503 rather than a lost 200.
    ingest_database_url: SecretStr = SecretStr("")
    # Replay window on the signed gen_time (ms epoch inside the body).
    ingest_max_age_seconds: int = 3600
    ingest_max_future_seconds: int = 300
    # Requests per minute, per client IP and per source. Failed auth costs double.
    ingest_rate_per_ip: int = 60
    ingest_rate_per_source: int = 600

    @property
    def console_allowlist(self) -> set[str]:
        return {u.strip().lower() for u in self.console_users.split(",") if u.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
