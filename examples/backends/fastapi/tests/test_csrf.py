"""Tests for CSRF enforcement across all POST endpoints."""

import pytest


POST_ENDPOINTS = [
    ("/auth/session", {"access_token": "x", "id_token": "x"}),
    ("/auth/refresh", None),
    ("/auth/logout", None),
    ("/auth/authorize", {"action": "read:content"}),
]


@pytest.mark.parametrize("endpoint,body", POST_ENDPOINTS)
def test_post_without_csrf_returns_403(client, endpoint, body):
    """All POST endpoints must reject requests without X-L42-CSRF header."""
    if body:
        resp = client.post(endpoint, json=body)
    else:
        resp = client.post(endpoint)
    assert resp.status_code == 403
    data = resp.json()
    assert data["detail"]["error"] == "CSRF validation failed"


@pytest.mark.parametrize("endpoint,body", POST_ENDPOINTS)
def test_post_with_wrong_csrf_returns_403(client, endpoint, body):
    """CSRF header with wrong value should be rejected."""
    if body:
        resp = client.post(endpoint, json=body, headers={"X-L42-CSRF": "wrong"})
    else:
        resp = client.post(endpoint, headers={"X-L42-CSRF": "wrong"})
    assert resp.status_code == 403


def test_callback_does_not_require_csrf(client):
    """GET /auth/callback is exempt from CSRF (uses OAuth state)."""
    resp = client.get("/auth/callback")
    # Should not be 403 — it redirects or gives an error about missing code
    assert resp.status_code != 403
