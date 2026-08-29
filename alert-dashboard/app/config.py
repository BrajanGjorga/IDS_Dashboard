from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import URL


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    database_url_override: str | None = None
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "ids_dashboard_db"
    db_user: str = "postgres"
    db_password: str = ""
    app_host: str = "0.0.0.0"
    app_port: int = 8001
    log_level: str = "INFO"
    log_file: Path = PROJECT_ROOT / "logs" / "alert-dashboard.log"
    session_secret: str = ""
    session_https_only: bool = False

    @property
    def database_url(self) -> str:
        if self.database_url_override:
            if self.database_url_override.startswith("postgresql://"):
                return self.database_url_override.replace(
                    "postgresql://", "postgresql+psycopg://", 1
                )
            if self.database_url_override.startswith("postgres://"):
                return self.database_url_override.replace(
                    "postgres://", "postgresql+psycopg://", 1
                )
            return self.database_url_override
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.db_user,
            password=self.db_password,
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        ).render_as_string(hide_password=False)

    @classmethod
    def from_env(cls, env_file: Path | None = None) -> "Settings":
        load_dotenv(env_file or PROJECT_ROOT / ".env")
        return cls(
            database_url_override=os.getenv("DATABASE_URL") or None,
            db_host=os.getenv("DB_HOST", "localhost"),
            db_port=int(os.getenv("DB_PORT", "5432")),
            db_name=os.getenv("DB_NAME", "alert_dashboard"),
            db_user=os.getenv("DB_USER", "alert_dashboard"),
            db_password=os.getenv("DB_PASSWORD", ""),
            app_host=os.getenv("APP_HOST", "127.0.0.1"),
            app_port=int(os.getenv("APP_PORT", "8001")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            session_secret=os.getenv("SESSION_SECRET", ""),
            session_https_only=os.getenv("SESSION_HTTPS_ONLY", "false").lower()
            in {"1", "true", "yes", "on"},
        )
