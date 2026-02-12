"""Integration test: real JWKS fetch from Cognito.

Verifies that the JWKS endpoint returns valid RSA keys,
caching works, and the response format matches expectations.
"""

from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_jwks_fetch(jwks_url):
    """Fetch JWKS from real Cognito and validate key structure."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(jwks_url)

    assert resp.status_code == 200
    jwks = resp.json()
    assert "keys" in jwks
    assert len(jwks["keys"]) > 0

    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert "kid" in key
    assert "n" in key
    assert "e" in key


@pytest.mark.asyncio
async def test_jwks_caching(cognito_env, jwks_url):
    """Verify JWKS module-level caching works with real endpoint."""
    from app.cognito import _fetch_jwks, reset_jwks_cache

    reset_jwks_cache()

    # First fetch — hits network
    jwks1 = await _fetch_jwks()
    assert "keys" in jwks1

    # Second fetch — should return cached (same object)
    jwks2 = await _fetch_jwks()
    assert jwks1 is jwks2

    reset_jwks_cache()


@pytest.mark.asyncio
async def test_jwks_keys_are_usable(jwks_url):
    """Verify fetched JWK can be loaded by PyJWT."""
    from jwt import algorithms as jwt_algorithms

    async with httpx.AsyncClient() as client:
        resp = await client.get(jwks_url)

    jwks = resp.json()
    for key_data in jwks["keys"]:
        if key_data.get("use") == "sig":
            # Should not raise
            public_key = jwt_algorithms.RSAAlgorithm.from_jwk(key_data)
            assert public_key is not None
