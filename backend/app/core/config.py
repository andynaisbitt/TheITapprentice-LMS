# Backend\app\core\config.py
"""Application configuration with security validation"""
from pydantic_settings import BaseSettings
from pydantic import field_validator, ValidationError
from typing import List
import sys

class Settings(BaseSettings):
    # Database - NO DEFAULT (must be set in .env)
    DATABASE_URL: str

    # JWT - NO DEFAULT (must be set in .env)
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Cookie Security Settings
    COOKIE_NAME: str = "itapp_access_token"
    COOKIE_MAX_AGE: int = 1800  # 30 minutes in seconds
    COOKIE_SECURE: bool = False  # Set to True in production (HTTPS only)
    COOKIE_HTTPONLY: bool = True
    COOKIE_SAMESITE: str = "lax"

    # CSRF Protection - NO DEFAULT (must be set in .env to persist across restarts)
    CSRF_SECRET_KEY: str
    CSRF_TOKEN_EXPIRE_MINUTES: int = 60

    # Google OAuth (optional)
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = ""

    # Email Service (v1.7 - optional)
    SENDGRID_API_KEY: str = ""
    EMAIL_FROM: str = "noreply@example.com"
    EMAIL_FROM_NAME: str = "The IT Apprentice"

    # SMTP Alternative (optional)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True

    # Plugin System (v1.7.1 - LMS Edition)
    PLUGINS_ENABLED: dict = {
        "tutorials": True,       # Enable tutorials plugin
        "typing_game": True,     # Enable typing game plugin (v1.9 - ACTIVE)
        "courses": True,         # Enable courses plugin (v1.8 - ACTIVE)
        "quizzes": False,        # Enable quizzes plugin (coming soon)
    }

    # App
    DEBUG: bool = False  # Changed default to False for security
    FRONTEND_URL: str = "http://localhost:5173"
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",  # Primary development frontend
        "http://localhost:5174",  # Alternative frontend port
        "http://localhost:8100",  # Backend (for docs/testing)
    ]

    # Admin
    ADMIN_EMAIL: str = "admin@itapprentice.com"
    ADMIN_PASSWORD: str  # NO DEFAULT (must be set in .env)

    # Environment
    ENVIRONMENT: str = "development"  # Options: development, production

    # Validators
    @field_validator('SECRET_KEY')
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Ensure SECRET_KEY is strong enough"""
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        if v in ["your-secret-key", "change-this-password", "secret"]:
            raise ValueError("SECRET_KEY cannot be a common/default value")
        return v

    @field_validator('CSRF_SECRET_KEY')
    @classmethod
    def validate_csrf_key(cls, v: str) -> str:
        """Ensure CSRF_SECRET_KEY is strong enough"""
        if len(v) < 32:
            raise ValueError("CSRF_SECRET_KEY must be at least 32 characters long")
        return v

    @field_validator('ADMIN_PASSWORD')
    @classmethod
    def validate_admin_password(cls, v: str) -> str:
        """Ensure admin password is not a default"""
        if v in ["admin123", "password", "change-this-password", "admin"]:
            raise ValueError("ADMIN_PASSWORD cannot be a common/default password")
        if len(v) < 12:
            raise ValueError("ADMIN_PASSWORD must be at least 12 characters long")
        return v

    @field_validator('DATABASE_URL')
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Ensure database URL is configured"""
        if "user:password@localhost" in v or v == "postgresql://user:password@localhost:5432/itapprentice_db":
            raise ValueError("DATABASE_URL must be configured with real credentials")
        return v

    class Config:
        env_file = ".env"

# Initialize settings with error handling
try:
    settings = Settings()
    print(f"[OK] Configuration loaded successfully (DEBUG={settings.DEBUG})")
except ValidationError as e:
    print("=" * 80)
    print("[ERROR] CONFIGURATION ERROR - Missing or invalid environment variables")
    print("=" * 80)
    for error in e.errors():
        field = error['loc'][0]
        msg = error['msg']
        print(f"\n{field}: {msg}")
    print("\n" + "=" * 80)
    print("Please check your .env file and ensure all required variables are set.")
    print("See Backend/.env.example for the required configuration.")
    print("=" * 80)
    sys.exit(1)