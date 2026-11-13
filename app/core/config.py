# app/core/config.py

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application Settings"""
    
    # Application
    ENVIRONMENT: str = "development"  # development, staging, production
    
    # Server
    PORT: int = 8000
    
    # GitHub
    GITHUB_TOKEN: str
    GITHUB_WEBHOOK_SECRET: str
    
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

    @property
    def LLM_PROVIDER(self) -> str:  # noqa: N802 - kept for existing callers
        """Provider of the default model, derived from LLM_MODEL."""
        provider, sep, _ = self.LLM_MODEL.partition(":")
        return provider.strip().lower() if sep else ""

settings = Settings()