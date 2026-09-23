"""Shared pytest fixtures: import path + environment isolation."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_ENV_VARS = (
    "PAYLOAD_SECRET",
    "ENTROPY_PATH",
    "APP_PATH",
    "BASE_PATH",
    "ROUTE_PATH",
    "SERVER_URL",
    "HOST",
    "PORT",
)


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Every test starts with config env vars unset (restored afterwards)."""
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)
