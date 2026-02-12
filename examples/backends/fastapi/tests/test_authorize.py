"""Tests for POST /auth/authorize (Cedar policy authorization).

Uses real Cedar schema and policies from the shared cedar/ directory.
This is the largest test file — covers admin, roles, ownership, fail-closed.
"""

import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app import cedar_engine
from app.cedar_engine import init_cedar_engine, reset_for_testing
from app.cognito import reset_jwks_cache
from app.config import Settings, override_settings
from app.main import create_app
from app.session import InMemoryBackend
from fastapi.testclient import TestClient

CEDAR_DIR = Path(__file__).parent.parent / "cedar"
SCHEMA_PATH = str(CEDAR_DIR / "schema.cedarschema.json")
POLICY_DIR = str(CEDAR_DIR / "policies")


@pytest.fixture(autouse=True)
def reset_cedar():
    reset_for_testing()
    yield
    reset_for_testing()


@pytest.fixture
def cedar_app(test_settings):
    """App with Cedar initialized."""
    override_settings(test_settings)
    reset_jwks_cache()
    init_cedar_engine(schema_path=SCHEMA_PATH, policy_dir=POLICY_DIR)
    return create_app(skip_cedar=True)


@pytest.fixture
def cedar_client(cedar_app) -> TestClient:
    return TestClient(cedar_app, cookies={})


def _authenticate(client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=None, sub="user-123"):
    """Helper: create an authenticated session with specific groups."""
    id_token = make_jwt(sub=sub, groups=groups or [])
    access_token = make_access_token(sub=sub, groups=groups or [])

    with patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response):
        resp = client.post(
            "/auth/session",
            json={
                "access_token": access_token,
                "id_token": id_token,
                "refresh_token": "r",
                "auth_method": "direct",
            },
            headers=csrf_headers,
        )
        assert resp.status_code == 200
    return client


# ── Fail-Closed ───────────────────────────────────────────────────────────

def test_authorize_cedar_unavailable_returns_503(auth_session, csrf_headers):
    """When Cedar is not initialized, return 503."""
    resp = auth_session.post(
        "/auth/authorize",
        json={"action": "read:content"},
        headers=csrf_headers,
    )
    assert resp.status_code == 503
    data = resp.json()
    assert data["authorized"] is False
    assert "not available" in data["error"]


def test_authorize_unauthenticated(client, csrf_headers):
    resp = client.post(
        "/auth/authorize",
        json={"action": "read:content"},
        headers=csrf_headers,
    )
    assert resp.status_code == 401


# ── Admin Permits All ─────────────────────────────────────────────────────

def test_admin_can_read_content(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["admin"])
    resp = cedar_client.post(
        "/auth/authorize",
        json={"action": "read:content"},
        headers=csrf_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True


def test_admin_can_delete_user(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["admin"])
    resp = cedar_client.post(
        "/auth/authorize",
        json={"action": "admin:delete-user"},
        headers=csrf_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True


def test_admin_alias_admins_works(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["admins"])  # Alias
    resp = cedar_client.post(
        "/auth/authorize",
        json={"action": "admin:manage"},
        headers=csrf_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True


# ── Role-Based Access ─────────────────────────────────────────────────────

def test_readonly_can_read_content(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["readonly"])
    resp = cedar_client.post(
        "/auth/authorize",
        json={"action": "read:content"},
        headers=csrf_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True


def test_readonly_cannot_write_content(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["readonly"])
    resp = cedar_client.post(
        "/auth/authorize",
        json={"action": "write:content"},
        headers=csrf_headers,
    )
    assert resp.status_code == 403
    assert resp.json()["authorized"] is False


def test_editors_can_write_content(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["editors"])
    resp = cedar_client.post(
        "/auth/authorize",
        json={"action": "write:content"},
        headers=csrf_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True


def test_editors_cannot_admin(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["editors"])
    resp = cedar_client.post(
        "/auth/authorize",
        json={"action": "admin:delete-user"},
        headers=csrf_headers,
    )
    assert resp.status_code == 403


def test_unauthenticated_group_denied(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    """User with no groups should be denied everything."""
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=[])
    resp = cedar_client.post(
        "/auth/authorize",
        json={"action": "read:content"},
        headers=csrf_headers,
    )
    assert resp.status_code == 403


# ── Ownership Enforcement ─────────────────────────────────────────────────

def test_owner_can_write_own(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    """User who owns a resource can write:own."""
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["users"], sub="owner-sub")
    resp = cedar_client.post(
        "/auth/authorize",
        json={
            "action": "write:own",
            "resource": {"id": "doc-1", "type": "document", "owner": "owner-sub"},
        },
        headers=csrf_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True


def test_non_owner_denied_write_own(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    """User who doesn't own a resource is denied write:own."""
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["users"], sub="other-user")
    resp = cedar_client.post(
        "/auth/authorize",
        json={
            "action": "write:own",
            "resource": {"id": "doc-1", "type": "document", "owner": "owner-sub"},
        },
        headers=csrf_headers,
    )
    assert resp.status_code == 403
    assert resp.json()["authorized"] is False


def test_non_owner_denied_delete_own(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    """Non-owner is denied delete:own."""
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["users"], sub="other-user")
    resp = cedar_client.post(
        "/auth/authorize",
        json={
            "action": "delete:own",
            "resource": {"id": "doc-1", "type": "document", "owner": "the-owner"},
        },
        headers=csrf_headers,
    )
    assert resp.status_code == 403


def test_admin_overrides_ownership(
    cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
):
    """Admin can write to resources they don't own (admin permit overrides)."""
    _authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                  groups=["admin"], sub="admin-user")
    resp = cedar_client.post(
        "/auth/authorize",
        json={
            "action": "write:all",
            "resource": {"id": "doc-1", "type": "document", "owner": "someone-else"},
        },
        headers=csrf_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["authorized"] is True


# ── Edge Cases ────────────────────────────────────────────────────────────

def test_missing_action_returns_400(auth_session, csrf_headers):
    """No Cedar init needed — action validation happens first... wait, auth check happens first.
    Actually, the require_auth dependency fires first, then Cedar check."""
    # We need Cedar initialized for this to hit the action validation
    init_cedar_engine(schema_path=SCHEMA_PATH, policy_dir=POLICY_DIR)

    resp = auth_session.post(
        "/auth/authorize",
        json={"action": ""},
        headers=csrf_headers,
    )
    assert resp.status_code == 400


def test_authorize_requires_csrf(auth_session):
    resp = auth_session.post(
        "/auth/authorize",
        json={"action": "read:content"},
    )
    assert resp.status_code == 403
