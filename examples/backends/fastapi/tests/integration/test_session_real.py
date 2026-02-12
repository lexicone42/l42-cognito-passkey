"""Integration test: POST /auth/session with real Cognito tokens.

Requires a test user and real tokens. This is a placeholder — you need
to provide valid tokens (e.g., from a Cognito-authenticated test user)
via environment variables or a helper script.

Env vars for this test:
    TEST_ACCESS_TOKEN   — valid Cognito access token
    TEST_ID_TOKEN       — valid Cognito ID token
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from app.cognito import reset_jwks_cache
from app.main import create_app
from app.session import InMemoryBackend

pytestmark = pytest.mark.integration


@pytest.fixture
def real_tokens():
    """Real Cognito tokens from environment."""
    access = os.environ.get("TEST_ACCESS_TOKEN")
    id_token = os.environ.get("TEST_ID_TOKEN")
    if not access or not id_token:
        pytest.skip("TEST_ACCESS_TOKEN and TEST_ID_TOKEN required")
    return {"access_token": access, "id_token": id_token}


@pytest.fixture
def real_client(real_settings):
    """TestClient configured with real Cognito settings."""
    reset_jwks_cache()
    app = create_app(session_backend=InMemoryBackend(), skip_cedar=True)
    return TestClient(app, cookies={})


def test_session_with_real_tokens(real_client, real_tokens):
    """POST /auth/session should verify real tokens via JWKS."""
    resp = real_client.post(
        "/auth/session",
        json=real_tokens,
        headers={"X-L42-CSRF": "1"},
    )
    assert resp.status_code == 200
    assert resp.json()["success"] is True

    # Verify session was created
    resp = real_client.get("/auth/token")
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"] == real_tokens["access_token"]


def test_me_with_real_tokens(real_client, real_tokens):
    """GET /auth/me should return real user info."""
    real_client.post(
        "/auth/session",
        json=real_tokens,
        headers={"X-L42-CSRF": "1"},
    )
    resp = real_client.get("/auth/me")
    assert resp.status_code == 200
    body = resp.json()
    assert "sub" in body
    assert "email" in body
