import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    APP_NAME: str = "R7 - Reconnaissance Platform"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Security & Authentication
    SECRET_KEY: str = os.getenv("SECRET_KEY", "r7-defense-grade-cyber-reconnaissance-secret-key-2026")

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./recon7.db")
    DB_ECHO: bool = False

    # AI Gateway (LiteLLM)
    AI_ENABLED: bool = True
    LITELLM_MODEL: str = os.getenv("LITELLM_MODEL", "anthropic/claude-3-5-sonnet-20241022")
    ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY", None)
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY", None)

    # Search Providers & OSINT (SerpAPI / Google Custom Search / GitHub / Censys)
    SERPAPI_API_KEY: Optional[str] = os.getenv("SERPAPI_API_KEY", None)
    GOOGLE_SEARCH_API_KEY: Optional[str] = os.getenv("GOOGLE_SEARCH_API_KEY", None)
    GOOGLE_SEARCH_ENGINE_ID: Optional[str] = os.getenv("GOOGLE_SEARCH_ENGINE_ID", None)
    GITHUB_TOKEN: Optional[str] = os.getenv("GITHUB_TOKEN", None)
    CENSYS_API_ID: Optional[str] = os.getenv("CENSYS_API_ID", None)
    CENSYS_API_SECRET: Optional[str] = os.getenv("CENSYS_API_SECRET", None)
    SEARCH_CACHE_TTL_DAYS: int = int(os.getenv("SEARCH_CACHE_TTL_DAYS", "7"))

    # Subprocess Executable Binaries (Defaults to system PATH resolution)
    MASSCAN_BIN: str = os.getenv("MASSCAN_BIN", "masscan")
    NMAP_BIN: str = os.getenv("NMAP_BIN", "nmap")
    SUBFINDER_BIN: str = os.getenv("SUBFINDER_BIN", "subfinder")
    HTTPX_BIN: str = os.getenv("HTTPX_BIN", "httpx")
    NUCLEI_BIN: str = os.getenv("NUCLEI_BIN", "nuclei")
    THEHARVESTER_BIN: str = os.getenv("THEHARVESTER_BIN", "theHarvester")
    EXIFTOOL_BIN: str = os.getenv("EXIFTOOL_BIN", "exiftool")

    # Timeouts & Limits
    SUBPROCESS_TIMEOUT_SECONDS: int = 180
    MASSCAN_TIMEOUT_SECONDS: int = 120
    NMAP_TIMEOUT_SECONDS: int = 300
    NUCLEI_TIMEOUT_SECONDS: int = 300
    HTTPX_TIMEOUT_SECONDS: int = 60
    WORKER_POLL_INTERVAL_SECONDS: int = 3
    MAX_CONCURRENT_SCANS_PER_TENANT: int = 2

    # Scopes
    ALLOW_ALL_SCOPES_DEV: bool = os.getenv("ALLOW_ALL_SCOPES_DEV", "true").lower() == "true"


settings = Settings()
