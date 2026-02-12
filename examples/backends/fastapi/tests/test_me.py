"""Tests for GET /auth/me."""

import pytest


def test_me_unauthenticated(client):
    resp = client.get("/auth/me")
    assert resp.status_code == 401


def test_me_returns_user_info(auth_session):
    resp = auth_session.get("/auth/me")
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "test@example.com"
    assert data["sub"] == "user-123"
    assert data["groups"] == ["admin"]


def test_me_returns_empty_groups_when_none(
    client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    """User with no groups should get empty list."""
    from unittest.mock import AsyncMock, patch

    id_token = make_jwt(groups=None)
    access_token = make_access_token()

    with patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response):
        client.post(
            "/auth/session",
            json={
                "access_token": access_token,
                "id_token": id_token,
                "refresh_token": "r",
            },
            headers=csrf_headers,
        )

    resp = client.get("/auth/me")
    assert resp.status_code == 200
    assert resp.json()["groups"] == []
