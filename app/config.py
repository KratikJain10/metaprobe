"""
Application settings managed via environment variables.

Uses pydantic-settings to load configuration from .env files
and environment variables with type validation and defaults.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # MongoDB
    MONGO_URI: str = "mongodb://mongodb:27017"
    MONGO_DB_NAME: str = "metadata_inventory"

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"
    CACHE_TTL_SECONDS: int = 3600  # 1 hour

    # HTTP client
    REQUEST_TIMEOUT: int = 30  # seconds

    # Rate limiting
    RATE_LIMIT: str = "30/minute"

    # CORS
    CORS_ORIGINS: list[str] = ["*"]

    # Application
    APP_VERSION: str = "2.0.0"
    LOG_LEVEL: str = "INFO"


# Singleton settings instance
settings = Settings()
