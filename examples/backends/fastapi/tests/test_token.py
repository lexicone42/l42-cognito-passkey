"""Tests for GET /auth/token."""

import time
from unittest.mock import AsyncMock, patch

import pytest


def test_get_token_unauthenticated(client):
    resp = client.get("/auth/token")
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "Not authenticated"


def test_get_token_returns_tokens(auth_session, valid_id_token, valid_access_token):
    resp = auth_session.get("/auth/token")
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"] == valid_access_token
    assert data["id_token"] == valid_id_token
    assert data["auth_method"] == "direct"


def test_get_token_excludes_refresh_token(auth_session):
    resp = auth_session.get("/auth/token")
    assert resp.status_code == 200
    assert "refresh_token" not in resp.json()


def test_get_token_expired_returns_401(
    client, expired_id_token, valid_access_token, jwks_response, csrf_headers
):
    """Expired tokens stored in session should return 401."""
    # Patch at the usage site (session_ep imports verify_id_token from cognito)
    with patch("app.routes.session_ep.verify_id_token", new_callable=AsyncMock, return_value={}):
        client.post(
            "/auth/session",
            json={
                "access_token": valid_access_token,
                "id_token": expired_id_token,
                "refresh_token": "test-refresh",
                "auth_method": "direct",
            },
            headers=csrf_headers,
        )

    resp = client.get("/auth/token")
    assert resp.status_code == 401
    assert resp.json()["error"] == "Token expired"
