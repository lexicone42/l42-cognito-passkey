"""Tests for GET /auth/callback (OAuth redirect handler)."""

from unittest.mock import AsyncMock, patch

import pytest


def test_callback_with_error_redirects_to_login(client):
    resp = client.get(
        "/auth/callback",
        params={"error": "access_denied", "error_description": "User cancelled"},
        follow_redirects=False,
    )
    assert resp.status_code == 307
    assert "/login" in resp.headers["location"]
    assert "error" in resp.headers["location"]


def test_callback_without_code_redirects_to_login(client):
    resp = client.get("/auth/callback", follow_redirects=False)
    assert resp.status_code == 307
    location = resp.headers["location"]
    assert "/login" in location
    assert "Missing" in location or "authorization+code" in location


def test_callback_exchanges_code_and_stores_tokens(
    client, valid_id_token, valid_access_token
):
    mock_tokens = {
        "access_token": valid_access_token,
        "id_token": valid_id_token,
        "refresh_token": "oauth-refresh-token",
    }

    with patch(
        "app.routes.callback.exchange_code_for_tokens",
        new_callable=AsyncMock,
        return_value=mock_tokens,
    ):
        resp = client.get(
            "/auth/callback",
            params={"code": "auth-code-123", "state": "test-state"},
            follow_redirects=False,
        )

    assert resp.status_code == 307
    assert "/auth/success" in resp.headers["location"]
    assert "state=test-state" in resp.headers["location"]

    # Tokens should be stored in session
    token_resp = client.get("/auth/token")
    assert token_resp.status_code == 200
    assert token_resp.json()["auth_method"] == "oauth"


def test_callback_exchange_failure_redirects_with_error(client):
    with patch(
        "app.routes.callback.exchange_code_for_tokens",
        new_callable=AsyncMock,
        side_effect=RuntimeError("Exchange failed"),
    ):
        resp = client.get(
            "/auth/callback",
            params={"code": "bad-code"},
            follow_redirects=False,
        )

    assert resp.status_code == 307
    assert "/login" in resp.headers["location"]
    assert "error" in resp.headers["location"]


def test_callback_does_not_require_csrf(client):
    """OAuth callback is a GET redirect — no CSRF header needed."""
    resp = client.get("/auth/callback", params={"code": "test"}, follow_redirects=False)
    # Should not be 403
    assert resp.status_code != 403


def test_callback_stores_refresh_token_server_side(
    client, valid_id_token, valid_access_token
):
    """Refresh token from OAuth should be stored but never returned."""
    mock_tokens = {
        "access_token": valid_access_token,
        "id_token": valid_id_token,
        "refresh_token": "secret-refresh-token",
    }

    with patch(
        "app.routes.callback.exchange_code_for_tokens",
        new_callable=AsyncMock,
        return_value=mock_tokens,
    ):
        client.get(
            "/auth/callback",
            params={"code": "auth-code", "state": "s"},
            follow_redirects=False,
        )

    # GET /auth/token should NOT include refresh_token
    token_resp = client.get("/auth/token")
    assert "refresh_token" not in token_resp.json()
