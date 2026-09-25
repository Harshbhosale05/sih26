from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg2://smscope:smscope@db:5432/securemailscope"
    data_dir: Path = Path("/data")

    # Hard ceiling on upload size. Enforced while streaming, not after.
    max_upload_bytes: int = 2 * 1024 * 1024 * 1024

    # Wall-clock limit applied to every external tool invocation.
    tool_timeout_seconds: int = 300

    cors_origins: str = "http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def captures_dir(self) -> Path:
        return self.data_dir / "captures"

    @property
    def tmp_dir(self) -> Path:
        return self.data_dir / "tmp"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.captures_dir.mkdir(parents=True, exist_ok=True)
    settings.tmp_dir.mkdir(parents=True, exist_ok=True)
    return settings
