"""Tests for POST /auth/session (token storage with JWKS verification)."""

import time
from unittest.mock import AsyncMock, patch

import pytest


def test_create_session_success(
    client, valid_id_token, valid_access_token, jwks_response, csrf_headers
):
    with patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response):
        resp = client.post(
            "/auth/session",
            json={
                "access_token": valid_access_token,
                "id_token": valid_id_token,
                "refresh_token": "refresh-abc",
                "auth_method": "passkey",
            },
            headers=csrf_headers,
        )
    assert resp.status_code == 200
    assert resp.json() == {"success": True}

    # Verify tokens are stored
    token_resp = client.get("/auth/token")
    assert token_resp.status_code == 200
    assert token_resp.json()["auth_method"] == "passkey"


def test_create_session_missing_tokens(client, csrf_headers):
    resp = client.post(
        "/auth/session",
        json={"access_token": "", "id_token": ""},
        headers=csrf_headers,
    )
    # Pydantic may accept empty strings, but the endpoint checks
    assert resp.status_code in (400, 422)


def test_create_session_bad_signature_returns_403(
    client, make_jwt, csrf_headers
):
    """Tokens with bad signature should be rejected."""
    # Create a token signed with a different key (won't match JWKS)
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    from cryptography.hazmat.primitives import serialization
    wrong_key = rsa_mod.generate_private_key(65537, 2048)
    wrong_pem = wrong_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    import jwt as pyjwt
    bad_token = pyjwt.encode(
        {"sub": "user-123", "email": "x@x.com", "iss": "wrong", "aud": "wrong",
         "exp": int(time.time()) + 3600},
        wrong_pem,
        algorithm="RS256",
        headers={"kid": "wrong-key"},
    )

    # Mock JWKS that doesn't have the wrong key
    with patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value={"keys": []}):
        resp = client.post(
            "/auth/session",
            json={
                "access_token": bad_token,
                "id_token": bad_token,
                "refresh_token": None,
            },
            headers=csrf_headers,
        )
    assert resp.status_code == 403
    assert resp.json()["error"] == "Token verification failed"


def test_create_session_verifies_issuer(
    client, rsa_private_key_pem, jwks_response, csrf_headers
):
    """Token with wrong issuer should be rejected."""
    import jwt as pyjwt
    bad_token = pyjwt.encode(
        {
            "sub": "user-123", "email": "x@x.com",
            "iss": "https://wrong-issuer.com",
            "aud": "test-client-id",
            "exp": int(time.time()) + 3600,
        },
        rsa_private_key_pem,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )

    with patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response):
        resp = client.post(
            "/auth/session",
            json={
                "access_token": bad_token,
                "id_token": bad_token,
                "refresh_token": None,
            },
            headers=csrf_headers,
        )
    assert resp.status_code == 403


def test_create_session_verifies_audience(
    client, rsa_private_key_pem, jwks_response, csrf_headers
):
    """Token with wrong audience should be rejected."""
    import jwt as pyjwt
    bad_token = pyjwt.encode(
        {
            "sub": "user-123", "email": "x@x.com",
            "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test123",
            "aud": "wrong-client-id",
            "exp": int(time.time()) + 3600,
        },
        rsa_private_key_pem,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )

    with patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response):
        resp = client.post(
            "/auth/session",
            json={
                "access_token": bad_token,
                "id_token": bad_token,
                "refresh_token": None,
            },
            headers=csrf_headers,
        )
    assert resp.status_code == 403


def test_create_session_no_csrf_returns_403(client, valid_id_token, valid_access_token):
    resp = client.post(
        "/auth/session",
        json={
            "access_token": valid_access_token,
            "id_token": valid_id_token,
        },
    )
    assert resp.status_code == 403


def test_create_session_defaults_auth_method_to_direct(
    client, valid_id_token, valid_access_token, jwks_response, csrf_headers
):
    with patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response):
        client.post(
            "/auth/session",
            json={
                "access_token": valid_access_token,
                "id_token": valid_id_token,
            },
            headers=csrf_headers,
        )

    resp = client.get("/auth/token")
    assert resp.status_code == 200
    assert resp.json()["auth_method"] == "direct"
