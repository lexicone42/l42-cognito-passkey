"""Shared fixtures for integration tests against a real Cognito user pool.

All integration tests are skipped unless the required environment variables
are set. This allows the test suite to run in CI without credentials while
supporting local testing against a real pool.

Required env vars:
    COGNITO_CLIENT_ID       — Cognito app client ID
    COGNITO_USER_POOL_ID    — e.g., us-west-2_abc123
    COGNITO_DOMAIN          — e.g., myapp.auth.us-west-2.amazoncognito.com

Optional env vars:
    COGNITO_REGION          — defaults to us-west-2
    COGNITO_CLIENT_SECRET   — for confidential clients
"""

from __future__ import annotations

import os

import pytest

from app.config import Settings, override_settings


def _get_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _has_cognito_env() -> bool:
    return all(
        os.environ.get(k)
        for k in ("COGNITO_CLIENT_ID", "COGNITO_USER_POOL_ID", "COGNITO_DOMAIN")
    )


# Skip all integration tests if credentials are missing
pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def cognito_env():
    """Return Cognito env vars or skip."""
    if not _has_cognito_env():
        pytest.skip("Integration tests require COGNITO_CLIENT_ID, COGNITO_USER_POOL_ID, COGNITO_DOMAIN")
    return {
        "client_id": _get_env("COGNITO_CLIENT_ID"),
        "user_pool_id": _get_env("COGNITO_USER_POOL_ID"),
        "domain": _get_env("COGNITO_DOMAIN"),
        "region": _get_env("COGNITO_REGION", "us-west-2"),
        "client_secret": _get_env("COGNITO_CLIENT_SECRET", ""),
    }


@pytest.fixture(scope="session")
def real_settings(cognito_env):
    """Settings configured from real Cognito env vars."""
    s = Settings(
        cognito_client_id=cognito_env["client_id"],
        cognito_user_pool_id=cognito_env["user_pool_id"],
        cognito_domain=cognito_env["domain"],
        cognito_region=cognito_env["region"],
        cognito_client_secret=cognito_env["client_secret"],
        session_secret="integration-test-secret",
    )
    override_settings(s)
    return s


@pytest.fixture(scope="session")
def jwks_url(cognito_env):
    """JWKS URL for the real Cognito pool."""
    region = cognito_env["region"]
    pool_id = cognito_env["user_pool_id"]
    return f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json"
