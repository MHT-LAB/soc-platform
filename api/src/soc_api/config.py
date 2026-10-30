"""Runtime configuration.

Everything comes from environment variables prefixed with SOC_ (or env files
mounted by the deploy script). Nothing secret is ever baked into the image.
"""

import re
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
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

    # The pager worker (its own service; worker.env holds the first two).
    # A role that can only call the worker functions (soc_worker).
    worker_database_url: SecretStr = SecretStr("")
    # The ntfy topic is the secret: anyone who knows it can read and post to it.
    ntfy_topic: SecretStr = SecretStr("")
    ntfy_server: str = "https://ntfy.sh"
    # JSON object: detection category -> ntfy priority 0-5 (0 = case, no push).
    page_policy: str = ""
    # Bounded so a typo cannot silence the pager (cap 0) or hammer the database (tick 0).
    worker_tick_seconds: float = Field(default=5.0, ge=1.0, le=60.0)
    # At most this many pushes per window; the rest wait (and one notice says so).
    page_cap: int = Field(default=10, ge=1, le=1000)
    page_cap_window_seconds: int = Field(default=600, ge=60, le=86400)
    health_file: str = "/tmp/worker-health"  # noqa: S108 - the container's own tmpfs

    # The console's case pages. The URL is for soc_console (no table privileges; four
    # functions), host 127.0.0.1 because the console runs on the host network. The secret
    # signs the one-use form tokens that stop another site from pressing Ack or Close.
    console_database_url: SecretStr = SecretStr("")
    console_secret: SecretStr = SecretStr("")
    # Signs the Acknowledge link on a phone notification. Held by the console and the worker
    # only (env/pager-ack.env); never the form secret, because this one crosses the push server.
    ack_key: SecretStr = SecretStr("")

    # The catch-up worker (a later PR; env/reconcile-db.env): a role that can only call
    # ingest_alert() and the cursor functions (soc_reconcile).
    reconcile_database_url: SecretStr = SecretStr("")
    # How long after an urgent page was sent it is sent again if nobody acknowledged it.
    repage_first_seconds: int = Field(default=900, ge=1, le=86400)
    repage_second_seconds: int = Field(default=3600, ge=2, le=604800)
    # The console's own address as people open it (https://<tailnet name>), no path. When
    # set, a form post must come from exactly this origin, whatever Host the proxy
    # forwards; the pager's click link (P5c) points here too.
    console_base_url: str = ""

    @model_validator(mode="after")
    def _repages_in_order(self) -> "Settings":
        if self.repage_second_seconds <= self.repage_first_seconds:
            raise ValueError("SOC_REPAGE_SECOND_SECONDS must be longer than the first")
        return self

    @field_validator("console_base_url")
    @classmethod
    def _bare_https_origin(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if value and not re.fullmatch(
            r"https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?", value
        ):
            raise ValueError(
                "SOC_CONSOLE_BASE_URL must be https://host[:port], lower case, no path"
            )
        return value

    @property
    def console_allowlist(self) -> set[str]:
        return {u.strip().lower() for u in self.console_users.split(",") if u.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
