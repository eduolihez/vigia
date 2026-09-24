"""Application settings, loaded from environment variables / .env."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(default="sqlite+aiosqlite:///./vigia.db", alias="DATABASE_URL")

    ollama_host: str = Field(default="http://localhost:11434", alias="OLLAMA_HOST")
    planner_model: str = Field(default="qwen3.6:35b", alias="VIGIA_PLANNER_MODEL")
    extractor_model: str = Field(default="granite4.1:8b", alias="VIGIA_EXTRACTOR_MODEL")

    secret_key: str = Field(default="dev-insecure-change-me", alias="VIGIA_SECRET_KEY")

    scan_max_steps: int = Field(default=60, alias="VIGIA_SCAN_MAX_STEPS")
    scan_max_minutes: int = Field(default=20, alias="VIGIA_SCAN_MAX_MINUTES")


@lru_cache
def get_settings() -> Settings:
    return Settings()
