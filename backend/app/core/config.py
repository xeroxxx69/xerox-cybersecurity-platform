from typing import List, Optional, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Core Application Settings
    PROJECT_NAME: str = "XEROX"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:4173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:4173",
        "http://127.0.0.1:3000",
        "https://xeroxxx69.github.io",
        "https://ghoshankan429-sys.github.io",
        "https://xeroxxx69.github.io",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        origins: List[str] = []
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    origins = [i.strip().rstrip("/") for i in json.loads(v) if isinstance(i, str)]
                except Exception:
                    origins = [i.strip().rstrip("/") for i in v.strip("[]").replace('"', "").replace("'", "").split(",") if i.strip()]
            else:
                origins = [i.strip().rstrip("/") for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            origins = [i.rstrip("/") for i in v if isinstance(i, str)]
        else:
            return v

        # Ensure canonical GitHub Pages origins are always recognized
        for default_origin in ["https://xeroxxx69.github.io", "https://ghoshankan429-sys.github.io"]:
            if default_origin not in origins:
                origins.append(default_origin)
        return origins

    # Security & Auth
    SECRET_KEY: str = "xerox_development_secret_key_change_in_production_32_chars_min"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Session & Cookie Security
    SESSION_COOKIE_NAME: str = "xerox_session"
    SESSION_EXPIRE_SECONDS: int = 86400 * 7  # 7 days
    COOKIE_SECURE: bool = False  # Auto-enabled in production or when COOKIE_SAMESITE=="none"
    COOKIE_SAMESITE: str = "lax"  # Auto-switched to "none" in production for cross-site auth
    COOKIE_HTTPONLY: bool = True
    COOKIE_DOMAIN: Optional[str] = None

    def model_post_init(self, __context) -> None:
        # Keep the active GitHub Pages origin allowed even when hosting env vars override defaults.
        pages_origin = "https://xeroxxx69.github.io"
        if pages_origin not in self.CORS_ORIGINS:
            self.CORS_ORIGINS.append(pages_origin)

        if self.ENVIRONMENT == "production":
            self.COOKIE_SECURE = True
            if self.COOKIE_SAMESITE == "lax":
                self.COOKIE_SAMESITE = "none"
            self.DEBUG = False

    # Brute Force Protection
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_SECONDS: int = 300  # 5 minutes lockout

    # Database (PostgreSQL primary, fallback to SQLite for local development/testing)
    DATABASE_URL: str = "sqlite+aiosqlite:///./xerox.db"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_database_url(cls, v: str) -> str:
        if isinstance(v, str):
            v_clean = v.strip()
            # Auto-normalize standard postgres:// or postgresql:// to asyncpg driver
            if v_clean.startswith("postgres://"):
                return "postgresql+asyncpg://" + v_clean[len("postgres://"):]
            if v_clean.startswith("postgresql://") and not v_clean.startswith("postgresql+"):
                return "postgresql+asyncpg://" + v_clean[len("postgresql://"):]
            return v_clean
        return v

    # Cache (Redis primary, fallback to in-memory/fakeredis)
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL_SECONDS: int = 86400  # 24 hours

    # External APIs
    VIRUSTOTAL_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # Screenshot Storage & Validation
    SCREENSHOT_STORAGE_DIR: str = "storage/screenshots"
    MAX_SCREENSHOT_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
    MAX_IMAGE_WIDTH: int = 4096
    MAX_IMAGE_HEIGHT: int = 4096
    ALLOWED_IMAGE_TYPES: List[str] = ["image/png", "image/jpeg", "image/webp"]

    # File Upload Storage & Validation
    FILE_STORAGE_DIR: str = "storage/files"
    MAX_FILE_SIZE_BYTES: int = 15 * 1024 * 1024  # 15 MB

    # Workers & Auditing
    ASYNC_AUDIT_LOGGING: bool = True
    MAX_WORKERS: int = 4


settings = Settings()
