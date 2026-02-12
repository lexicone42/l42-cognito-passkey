"""Tests for POST /auth/refresh."""

from unittest.mock import AsyncMock, patch

import pytest


def test_refresh_unauthenticated(client, csrf_headers):
    resp = client.post("/auth/refresh", headers=csrf_headers)
    assert resp.status_code == 401


def test_refresh_no_refresh_token(
    client, valid_id_token, valid_access_token, jwks_response, csrf_headers
):
    """Session without refresh token should return 401."""
    with patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response):
        client.post(
            "/auth/session",
            json={
                "access_token": valid_access_token,
                "id_token": valid_id_token,
                "refresh_token": None,  # No refresh token
            },
            headers=csrf_headers,
        )

    resp = client.post("/auth/refresh", headers=csrf_headers)
    assert resp.status_code == 401
    assert resp.json()["error"] == "No refresh token"


def test_refresh_success(auth_session, make_jwt, make_access_token, csrf_headers):
    """Successful refresh returns new tokens."""
    new_id = make_jwt(sub="user-123", groups=["admin"])
    new_access = make_access_token(sub="user-123")

    mock_result = {
        "AuthenticationResult": {
            "AccessToken": new_access,
            "IdToken": new_id,
        }
    }

    with patch("app.routes.refresh.cognito_request", new_callable=AsyncMock, return_value=mock_result):
        resp = auth_session.post("/auth/refresh", headers=csrf_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"] == new_access
    assert data["id_token"] == new_id
    assert "refresh_token" not in data


def test_refresh_failure_destroys_session(auth_session, csrf_headers):
    """Failed refresh should destroy the session."""
    with patch(
        "app.routes.refresh.cognito_request",
        new_callable=AsyncMock,
        side_effect=RuntimeError("Token revoked"),
    ):
        resp = auth_session.post("/auth/refresh", headers=csrf_headers)

    assert resp.status_code == 401
    assert "Refresh failed" in resp.json()["error"]

    # Session should be destroyed — subsequent token request should fail
    resp = auth_session.get("/auth/token")
    assert resp.status_code == 401


def test_refresh_preserves_refresh_token_if_not_rotated(
    auth_session, make_jwt, make_access_token, csrf_headers
):
    """If Cognito doesn't return a new refresh token, keep the old one."""
    new_id = make_jwt(sub="user-123")
    new_access = make_access_token()

    mock_result = {
        "AuthenticationResult": {
            "AccessToken": new_access,
            "IdToken": new_id,
            # No RefreshToken — Cognito didn't rotate it
        }
    }

    with patch("app.routes.refresh.cognito_request", new_callable=AsyncMock, return_value=mock_result):
        resp = auth_session.post("/auth/refresh", headers=csrf_headers)

    assert resp.status_code == 200

    # Should still be able to refresh again (old refresh token preserved)
    with patch("app.routes.refresh.cognito_request", new_callable=AsyncMock, return_value=mock_result):
        resp = auth_session.post("/auth/refresh", headers=csrf_headers)
    assert resp.status_code == 200
