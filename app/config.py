from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-opus-5-5"

    admin_password: str = "change-me"
    secret_key: str = "dev-secret-change-me"

    expiry_warning_months: int = 6
    default_validity_years: int = 2
    max_upload_mb: int = 10

    data_dir: Path = Path("data")
    database_url: str = ""

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite:///{self.data_dir / 'cpr.db'}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
