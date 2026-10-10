# app/core/config.py
# ─────────────────────────────────────────────────────────
# All configuration loaded from environment variables.
# Never hardcode secrets here — use .env file locally,
# Kubernetes secrets in production.
# ─────────────────────────────────────────────────────────

from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── App ───────────────────────────────────────────────
    APP_NAME: str = "E2E Encrypted Workspace API"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # ── Database ──────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://postgres:changeme@localhost:5432/encryptedws"

    # ── Auth / JWT ────────────────────────────────────────
    JWT_SECRET: str                        # Required — set in .env
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24     # 24 hours

    # ── NATS (real-time sync) ─────────────────────────────
    NATS_URL: str = "nats://localhost:4222"

    # ── OpenTelemetry ─────────────────────────────────────
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"
    OTEL_SERVICE_NAME: str = "encrypted-workspace-backend"

    # ── Security ──────────────────────────────────────────
    # Allowed origins for CORS (frontend URLs)
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Audit log pseudonymisation secret
    # HMAC(AUDIT_SECRET, user_id) → pseudonym stored in audit log
    # Required — set in .env
    AUDIT_SECRET: str = ""

    # ── Admin Console ─────────────────────────────────────
    # Comma-separated list of emails that may open the Admin Console,
    # e.g. ADMIN_EMAILS=admin@test.com,me@college.edu
    ADMIN_EMAILS: str = ""

    # ── Abuse protection ──────────────────────────────────
    # Max new accounts per client IP per window (0 = disabled)
    REGISTER_MAX_PER_WINDOW: int = 5
    REGISTER_WINDOW_SECONDS: int = 3600

    # Username lookups per user per minute (anti-enumeration; 0 = disabled)
    LOOKUP_MAX_PER_MINUTE: int = 30
    # Username search-as-you-type suggestions per user per minute
    SEARCH_MAX_PER_MINUTE: int = 60

    # ── Network log (Admin Console) ───────────────────────
    NETWORK_LOG_SIZE: int = 500          # requests kept in memory
    NETWORK_LOG_ENABLED: bool = True

    @property
    def admin_email_set(self) -> set[str]:
        from app.security.password_policy import canonicalize_email
        return {
            canonicalize_email(e) for e in self.ADMIN_EMAILS.split(",") if e.strip()
        }

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    """
    Returns cached settings instance.
    lru_cache ensures Settings() is only instantiated once.
    Use as a FastAPI dependency: Depends(get_settings)
    """
    return Settings()
