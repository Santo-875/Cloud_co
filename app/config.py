"""Runtime configuration settings for Cloud Copilot."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment or defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Cloud Copilot"
    version: str = "0.1.0"
    debug: bool = False

    # Security & Proxies
    trusted_proxy_headers: bool = False  # If false, ignore X-Forwarded-For

    # LLM Settings
    gemini_api_key: str | None = None
    use_mock_llm: bool = False

    # In-memory Store Limits
    store_max_entries: int = 100
    store_ttl_seconds: int = 3600

    # Rate Limiting (/chat endpoint)
    chat_rate_limit_per_minute: int = 10


settings = Settings()
