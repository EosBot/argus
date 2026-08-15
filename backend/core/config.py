"""Application configuration via pydantic-settings.

All settings are read from environment variables with sensible defaults
for local development. In production, override via .env or actual env vars.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -- Application -----------------------------------------------------------
    app_name: str = "ARGUS 2.0 Backend"
    app_version: str = "2.0.0"
    debug: bool = False
    environment: Literal["development", "staging", "production"] = "development"
    host: str = "0.0.0.0"
    port: int = 8000

    # -- CORS ------------------------------------------------------------------
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # -- JWT / Auth ------------------------------------------------------------
    jwt_secret_key: str = Field(
        default="change-me-in-production-32-char-min",
        min_length=16,
    )
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # -- PostgreSQL ------------------------------------------------------------
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "argus"
    postgres_password: str = "argus_default"
    postgres_db: str = "argus"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # -- Redis -----------------------------------------------------------------
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str | None = None
    redis_db: int = 0
    redis_default_ttl: int = 3600

    @property
    def redis_url(self) -> str:
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # -- Neo4j -----------------------------------------------------------------
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "argus_default"
    neo4j_database: str = "neo4j"

    # -- LiteLLM ---------------------------------------------------------------
    litellm_base_url: str = "http://localhost:4000"
    litellm_model: str = "ollama/llama-3"
    litellm_temperature: float = 0.7
    litellm_max_tokens: int = 2048

    # -- Rate limiting ---------------------------------------------------------
    rate_limit_default_max: int = 100
    rate_limit_default_window: int = 60

    # -- Tor -------------------------------------------------------------------
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    tor_control_host: str = "127.0.0.1"
    tor_control_port: int = 9051
    tor_control_password: str = ""

    @model_validator(mode="after")
    def reject_insecure_production_defaults(self) -> "Settings":
        """Fail closed when production starts with published development secrets."""
        if self.environment == "production":
            insecure = {
                "JWT_SECRET_KEY": self.jwt_secret_key == "change-me-in-production-32-char-min",
                "POSTGRES_PASSWORD": self.postgres_password == "argus_default",
                "NEO4J_PASSWORD": self.neo4j_password == "argus_default",
                "TOR_CONTROL_PASSWORD": not self.tor_control_password or self.tor_control_password == "argus_default",
            }
            invalid = [name for name, failed in insecure.items() if failed]
            if invalid:
                raise ValueError(f"Segredos de produção ausentes ou inseguros: {', '.join(invalid)}")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton of Settings."""
    return Settings()


settings = get_settings()
