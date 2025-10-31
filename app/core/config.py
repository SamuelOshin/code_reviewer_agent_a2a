# app/core/config.py

from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    """Application Settings"""
    
    # Application
    APP_NAME: str = "Code Review Summarizer Agent"
    ENVIRONMENT: str = "development"  # development, staging, production
    DEBUG: bool = False
    VERSION: str = "1.0.0"
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ALLOWED_ORIGINS: List[str] = ["*"]
    
    # GitHub
    GITHUB_TOKEN: str
    GITHUB_WEBHOOK_SECRET: str
    
    # LLM Configuration
    LLM_PROVIDER: str = "google"  # openai, anthropic, or google (gemini)
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    GOOGLE_API_KEY: str = ""
    
    # LLM Model Settings
    # Default models per provider:
    # - google: gemini-1.5-pro, gemini-1.5-flash
    # - openai: gpt-4-turbo-preview, gpt-4o
    # - anthropic: claude-3-5-sonnet-20241022, claude-3-opus-20240229
    LLM_MODEL: str = "gemini-1.5-flash"
    LLM_TEMPERATURE: float = 0.3
    LLM_MAX_TOKENS: int = 4000
    
    # Telex Integration
    TELEX_URL: str = ""  # Primary Telex endpoint
    TELEX_WEBHOOK_URL: str = ""  # Webhook URL (deprecated, use TELEX_URL)
    TELEX_API_KEY: str = ""
    TELEX_CHANNEL: str = "#code-reviews"
    
    # A2A Configuration
    A2A_AGENT_URL: str = ""
    A2A_AGENT_NAME: str = "Code Review Summarizer"
    
    # Security
    SECRET_KEY: str
    
    
    DATABASE_URL: str = "sqlite:///./code_review_agent.db"
    
    # Redis (Optional - for caching)
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": True,
        "extra": "allow"
    }

settings = Settings()