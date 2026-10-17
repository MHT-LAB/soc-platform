"""Runtime configuration.

Everything comes from environment variables prefixed with SOC_ (or secret files
mounted by the deploy script). Nothing secret is ever baked into the image.
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOC_")

    # "prod" hides the interactive API docs; "dev" shows them for local work.
    env: Literal["dev", "prod"] = "prod"
    # Stamped into the image at build time by CI.
    version: str = "0.0.0-dev"
    git_sha: str = "unknown"


@lru_cache
def get_settings() -> Settings:
    return Settings()
