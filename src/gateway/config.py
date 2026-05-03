"""Settings loaded from environment variables / .env file.

Uses pydantic-settings so values are typed, validated, and easy to autocomplete.
Edit `.env` (not this file) to change values.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Backend API keys (empty string = "not configured") ---
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    llama_base_url: str = "http://localhost:11434"

    # --- Gateway settings ---
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8000
    gateway_api_key: str = "dev-secret-key"

    # --- Redis (used in W5+, unused in W1) ---
    redis_url: str = "redis://localhost:6379/0"

    # --- Detection thresholds (used in W2+) ---
    l1_block_threshold: float = 0.7   # tuned for our trained model (catches DAN, AIM)
    l1_pass_threshold: float = 0.2

    # --- Rate limit (W7) ---
    rate_limit_per_minute: int = 60

    # --- Logging ---
    log_level: str = "INFO"


settings = Settings()
