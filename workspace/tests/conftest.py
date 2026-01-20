import pytest

@pytest.fixture
def disable_turnstile(monkeypatch):
    monkeypatch.delenv("TURNSTILE_SECRET_KEY", raising=False)
