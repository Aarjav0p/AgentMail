"""AgentMail relay configuration — all settings from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment / .env file."""

    # --- Database ---
    database_url: str = "postgresql+asyncpg://localhost/agentmail"

    # --- Relay identity ---
    relay_domain: str = "agentmail"

    # --- Vault ---
    vault_ttl_minutes: int = 15
    vault_max_entries: int = 500

    # --- Message TTLs (RETENTION-01: 60d read / 30d unread) ---
    # Read messages: kept 60 days from read_at (webmail history window).
    # Unread messages: kept 30 days from created_at (abandoned-mailbox reclamation).
    read_ttl_days: int = 60
    unread_ttl_days: int = 30

    # --- Quotas ---
    default_quota_bytes: int = 5_242_880  # 5 MiB

    # --- Admin ---
    admin_token: str = ""

    # --- Dashboard / Supabase (DASH-01) ---
    supabase_url: str = "https://example.supabase.co"
    supabase_jwt_secret: str = ""
    encryption_key: str = ""
    cors_origins: str = "http://localhost:5173"

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 10000  # Render default

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
