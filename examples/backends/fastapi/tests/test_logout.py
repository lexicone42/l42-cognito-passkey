"""Tests for POST /auth/logout."""

import pytest


def test_logout_destroys_session(auth_session, csrf_headers):
    # Verify authenticated
    resp = auth_session.get("/auth/token")
    assert resp.status_code == 200

    # Logout
    resp = auth_session.post("/auth/logout", headers=csrf_headers)
    assert resp.status_code == 200
    assert resp.json() == {"success": True}

    # Should no longer be authenticated
    resp = auth_session.get("/auth/token")
    assert resp.status_code == 401


def test_logout_without_session(client, csrf_headers):
    """Logging out without a session should still succeed."""
    resp = client.post("/auth/logout", headers=csrf_headers)
    assert resp.status_code == 200


def test_logout_clears_session_cookie(auth_session, csrf_headers):
    resp = auth_session.post("/auth/logout", headers=csrf_headers)
    cookie_header = resp.headers.get("set-cookie", "")
    assert "Max-Age=0" in cookie_header


def test_logout_requires_csrf(client):
    resp = client.post("/auth/logout")
    assert resp.status_code == 403
