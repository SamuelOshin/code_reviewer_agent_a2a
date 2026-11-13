# app/core/config.py

import re

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

# Shortest API key accepted at startup (P1-07). 32 characters of a random token is
# far beyond guessing range; shorter values are usually placeholders or typos.
MIN_API_KEY_LENGTH = 32
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
_ORIGIN_RE = re.compile(r"^https?://[a-z0-9.-]+(:[0-9]{1,5})?$")


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    """Application Settings"""
    
    # Application
    ENVIRONMENT: str = "development"  # development, staging, production
    
    # Server
    PORT: int = 8000
    
    # GitHub
    GITHUB_TOKEN: str
    # Required and non-empty (P1-07): every webhook must carry a valid HMAC signature.
    # Without it anyone could forge pull_request events and make the bot comment.
    GITHUB_WEBHOOK_SECRET: str

    # API access (P1-07, F-04). Callers of /rpc and /a2a/* must send
    # "Authorization: Bearer <API_KEY>". Required, at least MIN_API_KEY_LENGTH
    # characters, so the review endpoints are never open by accident.
    API_KEY: str

    # Hosts that may receive push notifications (A2A pushNotificationConfig.url),
    # comma-separated, exact hostname match. Empty (the default) disables push
    # notifications: results are only returned to the caller. URLs must also be
    # https and resolve to public addresses only (SSRF guard).
    PUSH_URL_ALLOWED_HOSTS: str = ""

    # Browser origins allowed by CORS, comma-separated (e.g. https://app.example.com).
    # Empty (the default) sends no CORS headers, which is right for server-to-server
    # A2A clients. "*" is not accepted.
    CORS_ALLOWED_ORIGINS: str = ""

    # Most calls accepted in one JSON-RPC batch. Each call can start a full PR
    # review, so an unbounded batch is a cheap way to burn LLM quota.
    JSONRPC_MAX_BATCH_SIZE: int = Field(10, ge=1, le=100)
    
    # LLM configuration (tracker section 4, D-06). Provider and model are settings only.
    # Format: "<provider>:<model-id>", provider one of google, openai, anthropic,
    # openai-compatible. No default: pick a model in .env (see .env.example).
    LLM_MODEL: str = ""
    # Optional per-role models; empty means use LLM_MODEL
    LLM_MODEL_SECURITY: str = ""
    LLM_MODEL_PERFORMANCE: str = ""
    LLM_MODEL_BEST_PRACTICES: str = ""
    LLM_MODEL_SUMMARY: str = ""
    # Optional comma-separated fallback models, tried in order when a call fails
    LLM_FALLBACK_MODELS: str = ""
    # auto, native, tool or prompted. auto uses native schema output where supported
    LLM_STRUCTURED_OUTPUT_MODE: str = "auto"
    LLM_TEMPERATURE: float = 0.3
    LLM_MAX_TOKENS: int = Field(4000, gt=0)
    # Retries for transient provider errors, applied the same way for every provider
    LLM_MAX_RETRIES: int = Field(2, ge=0)
    LLM_TIMEOUT_SECONDS: float = Field(120.0, gt=0)

    # Provider credentials (only the ones your models use are needed)
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    GOOGLE_API_KEY: str = ""
    # Any OpenAI Chat Completions compatible server: local models or gateways
    OPENAI_COMPATIBLE_BASE_URL: str = ""
    OPENAI_COMPATIBLE_API_KEY: str = ""

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": True,
        "extra": "allow"
    }

    @field_validator("GITHUB_WEBHOOK_SECRET")
    @classmethod
    def _webhook_secret_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("GITHUB_WEBHOOK_SECRET must be set to a non-empty value")
        return value

    @field_validator("API_KEY")
    @classmethod
    def _api_key_strong_enough(cls, value: str) -> str:
        if value != value.strip() or len(value) < MIN_API_KEY_LENGTH:
            raise ValueError(
                f"API_KEY must be at least {MIN_API_KEY_LENGTH} characters with no "
                "surrounding whitespace (e.g. python -c \"import secrets; "
                "print(secrets.token_urlsafe(32))\")"
            )
        return value

    @field_validator("PUSH_URL_ALLOWED_HOSTS")
    @classmethod
    def _valid_push_hosts(cls, value: str) -> str:
        for host in _split_csv(value):
            if not _HOSTNAME_RE.match(host.lower()):
                raise ValueError(
                    f"PUSH_URL_ALLOWED_HOSTS entry {host!r} must be a bare hostname "
                    "(no scheme, port, path or wildcard)"
                )
        return value

    @field_validator("CORS_ALLOWED_ORIGINS")
    @classmethod
    def _valid_cors_origins(cls, value: str) -> str:
        for origin in _split_csv(value):
            if not _ORIGIN_RE.match(origin.lower()):
                raise ValueError(
                    f"CORS_ALLOWED_ORIGINS entry {origin!r} must be scheme://host[:port] "
                    "with no path; '*' is not allowed"
                )
        return value

    @property
    def push_url_allowed_hosts(self) -> frozenset[str]:
        """Allowlisted push hosts, lowercased."""
        return frozenset(h.lower() for h in _split_csv(self.PUSH_URL_ALLOWED_HOSTS))

    @property
    def cors_allowed_origins(self) -> list[str]:
        """Allowed CORS origins, without trailing slashes."""
        return [o.rstrip("/") for o in _split_csv(self.CORS_ALLOWED_ORIGINS)]

    @property
    def LLM_PROVIDER(self) -> str:  # noqa: N802 - kept for existing callers
        """Provider of the default model, derived from LLM_MODEL."""
        provider, sep, _ = self.LLM_MODEL.partition(":")
        return provider.strip().lower() if sep else ""

settings = Settings()