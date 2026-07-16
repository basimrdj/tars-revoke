from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="TARS_",
        extra="ignore",
    )

    data_dir: Path = Path(".tars")
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8747, ge=1024, le=65535)
    codex_bin: Path | None = None
    codex_model: str | None = None
    codex_timeout_seconds: int = Field(default=900, ge=10, le=3600)
    log_level: str = "INFO"

    @field_validator("data_dir", "codex_bin", mode="before")
    @classmethod
    def expand_path(cls, value: object) -> object:
        if value in (None, ""):
            return None
        return Path(str(value)).expanduser()

def load_settings(**overrides: Any) -> Settings:
    return Settings(**overrides)
