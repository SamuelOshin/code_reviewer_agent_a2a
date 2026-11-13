"""Settings must not require values the app never reads (F-07)."""

import pytest

from app.core.config import Settings

REMOVED_SETTINGS = [
    "SECRET_KEY",
    "APP_NAME",
    "DEBUG",
    "VERSION",
    "HOST",
    "ALLOWED_ORIGINS",
    "A2A_AGENT_URL",
    "A2A_AGENT_NAME",
    "DATABASE_URL",
    "REDIS_URL",
]


def test_settings_load_without_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "dummy")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "dummy")

    settings = Settings(_env_file=None)

    assert settings.GITHUB_TOKEN == "dummy"


def test_required_settings_are_github_and_api_key(monkeypatch):
    for name in ("GITHUB_TOKEN", "GITHUB_WEBHOOK_SECRET", "SECRET_KEY", "API_KEY"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(Exception) as exc:
        Settings(_env_file=None)

    missing = {err["loc"][0] for err in exc.value.errors()}
    assert missing == {"GITHUB_TOKEN", "GITHUB_WEBHOOK_SECRET", "API_KEY"}


@pytest.mark.parametrize("name", REMOVED_SETTINGS)
def test_unused_settings_are_gone(name):
    assert name not in Settings.model_fields
