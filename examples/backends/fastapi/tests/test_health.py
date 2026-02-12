"""Tests for GET /health."""

from unittest.mock import patch

import pytest


def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["mode"] == "token-handler"


def test_health_cedar_unavailable_by_default(client):
    """Without Cedar initialization, cedar status is 'unavailable'."""
    resp = client.get("/health")
    assert resp.json()["cedar"] == "unavailable"


def test_health_cedar_ready_when_initialized(client):
    """When Cedar is initialized, status should be 'ready'."""
    with patch("app.cedar_engine._initialized", True):
        resp = client.get("/health")
        assert resp.json()["cedar"] == "ready"
