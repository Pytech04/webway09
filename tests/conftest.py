import ipaddress
import sys
from pathlib import Path

import pytest

# Make the app importable when pytest is run from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import server


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(server, "API_TOKEN", "")
    monkeypatch.setattr(server, "ALLOW_UNAUTHENTICATED", False)
    monkeypatch.setattr(server, "ALLOW_PRIVATE_HOSTS", False)
    monkeypatch.setattr(server, "RATE_LIMIT_MAX", 1000)
    monkeypatch.setattr(server, "RATE_LIMIT_WINDOW", 60)
    server._rate_events.clear()
    server.app.config.update(TESTING=True)
    return server.app.test_client()


@pytest.fixture
def fake_public_dns(monkeypatch):
    monkeypatch.setattr(
        server,
        "_resolve_host",
        lambda hostname, port: [ipaddress.ip_address("93.184.216.34")],
    )
    return "93.184.216.34"
