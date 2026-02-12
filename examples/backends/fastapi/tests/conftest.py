"""Shared fixtures for the FastAPI Token Handler test suite."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Generator
from unittest.mock import AsyncMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from jwt import algorithms as jwt_algorithms
import jwt

from app.config import Settings, override_settings
from app.cognito import reset_jwks_cache
from app.main import create_app
from app.session import InMemoryBackend


# ── RSA Key Pair (generated once per test session) ────────────────────────

@pytest.fixture(scope="session")
def rsa_private_key():
    """Generate a test RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_public_key(rsa_private_key):
    return rsa_private_key.public_key()


@pytest.fixture(scope="session")
def jwk_dict(rsa_public_key) -> dict[str, Any]:
    """Build a JWK dict from the test RSA public key."""
    public_numbers = rsa_public_key.public_numbers()

    def _int_to_b64(n: int, length: int) -> str:
        return base64.urlsafe_b64encode(
            n.to_bytes(length, byteorder="big")
        ).decode().rstrip("=")

    return {
        "kty": "RSA",
        "kid": "test-key-1",
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_b64(public_numbers.n, 256),
        "e": _int_to_b64(public_numbers.e, 3),
    }


@pytest.fixture(scope="session")
def jwks_response(jwk_dict) -> dict[str, Any]:
    """JWKS response with the test key."""
    return {"keys": [jwk_dict]}


# ── JWT Factory ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def rsa_private_key_pem(rsa_private_key) -> bytes:
    return rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def make_jwt(rsa_private_key_pem):
    """Factory for creating signed JWTs for testing."""

    def _make(
        sub: str = "user-123",
        email: str = "test@example.com",
        groups: list[str] | None = None,
        exp: int | None = None,
        iss: str = "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test123",
        aud: str = "test-client-id",
        token_use: str = "id",
        extra_claims: dict | None = None,
    ) -> str:
        now = int(time.time())
        payload = {
            "sub": sub,
            "email": email,
            "iss": iss,
            "aud": aud,
            "iat": now,
            "exp": exp or (now + 3600),
            "token_use": token_use,
        }
        if groups is not None:
            payload["cognito:groups"] = groups
        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(
            payload,
            rsa_private_key_pem,
            algorithm="RS256",
            headers={"kid": "test-key-1"},
        )

    return _make


@pytest.fixture
def make_access_token(make_jwt):
    """Factory for access tokens (no aud claim for Cognito access tokens)."""

    def _make(sub: str = "user-123", groups: list[str] | None = None, **kwargs):
        return make_jwt(sub=sub, groups=groups, token_use="access", aud="test-client-id", **kwargs)

    return _make


@pytest.fixture
def valid_id_token(make_jwt) -> str:
    """A valid, signed ID token for the default test user."""
    return make_jwt(groups=["admin"])


@pytest.fixture
def valid_access_token(make_access_token) -> str:
    return make_access_token(groups=["admin"])


@pytest.fixture
def expired_id_token(make_jwt) -> str:
    return make_jwt(exp=int(time.time()) - 100)


@pytest.fixture
def expired_access_token(make_access_token) -> str:
    return make_access_token(exp=int(time.time()) - 100)


# ── Test Settings ─────────────────────────────────────────────────────────

@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        cognito_client_id="test-client-id",
        cognito_user_pool_id="us-west-2_test123",
        cognito_domain="test.auth.us-west-2.amazoncognito.com",
        cognito_region="us-west-2",
        session_secret="test-secret-key-for-sessions",
        frontend_url="http://localhost:3000",
    )


# ── App & Client ──────────────────────────────────────────────────────────

@pytest.fixture
def session_backend() -> InMemoryBackend:
    return InMemoryBackend()


@pytest.fixture
def app(test_settings, session_backend):
    override_settings(test_settings)
    reset_jwks_cache()
    return create_app(session_backend=session_backend, skip_cedar=True)


@pytest.fixture
def client(app) -> TestClient:
    """TestClient with cookie persistence."""
    return TestClient(app, cookies={})


# ── Helper: Authenticated Client ──────────────────────────────────────────

@pytest.fixture
def auth_session(client, valid_id_token, valid_access_token, jwks_response):
    """Set up an authenticated session and return the client.

    POSTs to /auth/session with valid tokens, mock-verified via JWKS.
    """
    with patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response):
        resp = client.post(
            "/auth/session",
            json={
                "access_token": valid_access_token,
                "id_token": valid_id_token,
                "refresh_token": "test-refresh-token",
                "auth_method": "direct",
            },
            headers={"X-L42-CSRF": "1"},
        )
        assert resp.status_code == 200
    return client


@pytest.fixture
def csrf_headers() -> dict[str, str]:
    """Standard CSRF headers for POST requests."""
    return {"X-L42-CSRF": "1"}
