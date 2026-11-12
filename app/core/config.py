# app/core/config.py

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
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": True,
        "extra": "allow"
    }

settings = Settings()