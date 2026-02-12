"""End-to-end flow tests — exercise full session lifecycles.

Unlike unit tests that mock internal functions like _fetch_jwks or
cognito_request individually, these tests only mock at the external HTTP
boundary (httpx calls to Cognito). Cedar uses real schema + policies.

This catches integration bugs in middleware chains, session handling,
CSRF validation, and Cedar evaluation that unit tests would miss.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from app import cedar_engine
from app.cognito import reset_jwks_cache
from app.config import Settings, override_settings
from app.main import create_app
from app.session import InMemoryBackend


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def _rsa_keypair():
    """RSA keypair generated once per module (expensive)."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private, public, pem


@pytest.fixture(scope="module")
def _jwk_dict(_rsa_keypair):
    """JWK dict from the test RSA public key."""
    _, public, _ = _rsa_keypair
    nums = public.public_numbers()

    def _int_to_b64(n: int, length: int) -> str:
        return base64.urlsafe_b64encode(
            n.to_bytes(length, byteorder="big")
        ).decode().rstrip("=")

    return {
        "kty": "RSA",
        "kid": "test-key-1",
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_b64(nums.n, 256),
        "e": _int_to_b64(nums.e, 3),
    }


@pytest.fixture
def jwks_json(_jwk_dict):
    """JWKS JSON bytes as Cognito would return."""
    return json.dumps({"keys": [_jwk_dict]}).encode()


@pytest.fixture
def make_token(_rsa_keypair):
    """Factory: create a signed JWT with given claims."""
    _, _, pem = _rsa_keypair

    def _make(
        sub: str = "user-123",
        email: str = "test@example.com",
        groups: list[str] | None = None,
        exp: int | None = None,
        token_use: str = "id",
    ) -> str:
        now = int(time.time())
        payload = {
            "sub": sub,
            "email": email,
            "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test123",
            "aud": "test-client-id",
            "iat": now,
            "exp": exp or (now + 3600),
            "token_use": token_use,
        }
        if groups is not None:
            payload["cognito:groups"] = groups
        return pyjwt.encode(payload, pem, algorithm="RS256", headers={"kid": "test-key-1"})

    return _make


@pytest.fixture
def settings():
    s = Settings(
        cognito_client_id="test-client-id",
        cognito_user_pool_id="us-west-2_test123",
        cognito_domain="test.auth.us-west-2.amazoncognito.com",
        cognito_region="us-west-2",
        session_secret="test-secret-for-e2e",
        frontend_url="http://localhost:3000",
    )
    override_settings(s)
    return s


@pytest.fixture
def backend():
    return InMemoryBackend()


@pytest.fixture
def cedar_app(settings, backend):
    """App with Cedar initialized from real schema + policies.

    Uses yield to ensure Cedar global state is cleaned up after the test,
    preventing interference with other tests (e.g., test_health.py).
    """
    reset_jwks_cache()
    cedar_engine.reset_for_testing()
    cedar_dir = Path(__file__).resolve().parent.parent / "cedar"
    if not cedar_dir.exists():
        pytest.skip("Cedar directory not found (symlink missing?)")
    app = create_app(session_backend=backend, skip_cedar=True)
    cedar_engine.init_cedar_engine(
        schema_path=str(cedar_dir / "schema.cedarschema.json"),
        policy_dir=str(cedar_dir / "policies"),
    )
    yield app
    cedar_engine.reset_for_testing()


@pytest.fixture
def app(settings, backend):
    """App without Cedar (for non-authorization flows)."""
    reset_jwks_cache()
    cedar_engine.reset_for_testing()
    return create_app(session_backend=backend, skip_cedar=True)


def _mock_httpx_for_jwks(jwks_json: bytes):
    """Create a mock that intercepts httpx.AsyncClient for JWKS fetches.

    Returns a context manager that patches httpx.AsyncClient so that
    GET requests to the JWKS URL return the test JWKS, while POST
    requests (e.g., Cognito token exchange) can be configured separately.
    """
    original_init = httpx.AsyncClient.__init__

    class FakeResponse:
        def __init__(self, status_code: int, content: bytes):
            self.status_code = status_code
            self._content = content
            self.is_success = 200 <= status_code < 300
            self.text = content.decode()

        def json(self):
            return json.loads(self._content)

        def raise_for_status(self):
            if not self.is_success:
                raise httpx.HTTPStatusError(
                    "error", request=MagicMock(), response=self,
                )

    class MockClient:
        """Replaces httpx.AsyncClient as a context manager."""

        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url, **kwargs):
            if "jwks.json" in url:
                return FakeResponse(200, jwks_json)
            return FakeResponse(404, b'{"error": "not found"}')

        async def post(self, url, **kwargs):
            # Default: fail. Tests that need POST mocking override this.
            return FakeResponse(500, b'{"error": "not mocked"}')

    return patch("app.cognito.httpx.AsyncClient", MockClient)


def _mock_httpx_for_cognito(jwks_json: bytes, post_responses: dict | None = None):
    """Mock httpx.AsyncClient for both JWKS GET and Cognito POST calls.

    post_responses: dict mapping URL substring → (status_code, response_dict)
    """
    post_responses = post_responses or {}

    class FakeResponse:
        def __init__(self, status_code: int, body: dict | bytes):
            self.status_code = status_code
            if isinstance(body, bytes):
                self._content = body
            else:
                self._content = json.dumps(body).encode()
            self.is_success = 200 <= status_code < 300
            self.text = self._content.decode()

        def json(self):
            return json.loads(self._content)

        def raise_for_status(self):
            if not self.is_success:
                raise httpx.HTTPStatusError(
                    "error", request=MagicMock(), response=self,
                )

    class MockClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, url, **kwargs):
            if "jwks.json" in url:
                return FakeResponse(200, json.loads(jwks_json))
            return FakeResponse(404, {"error": "not found"})

        async def post(self, url, **kwargs):
            for url_substr, (status, body) in post_responses.items():
                if url_substr in url:
                    return FakeResponse(status, body)
            return FakeResponse(500, {"error": "not mocked"})

    return patch("app.cognito.httpx.AsyncClient", MockClient)


CSRF = {"X-L42-CSRF": "1"}


# ── E2E Flow Tests ────────────────────────────────────────────────────────


class TestPasskeyLoginFlow:
    """Full passkey/password login lifecycle:
    session → token → authorize → me → logout → verify 401
    """

    def test_full_lifecycle(self, cedar_app, make_token, jwks_json):
        client = TestClient(cedar_app, cookies={})
        id_token = make_token(groups=["admin"])
        access_token = make_token(groups=["admin"], token_use="access")

        with _mock_httpx_for_jwks(jwks_json):
            # 1. POST /auth/session — store tokens
            resp = client.post(
                "/auth/session",
                json={
                    "access_token": access_token,
                    "id_token": id_token,
                    "refresh_token": "rt-123",
                    "auth_method": "passkey",
                },
                headers=CSRF,
            )
            assert resp.status_code == 200
            assert resp.json()["success"] is True

        # 2. GET /auth/token — retrieve tokens (no JWKS needed, reads session)
        resp = client.get("/auth/token")
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"] == access_token
        assert body["id_token"] == id_token
        assert "refresh_token" not in body  # Never exposed
        assert body["auth_method"] == "passkey"

        # 3. POST /auth/authorize — Cedar check (admin can read:content)
        resp = client.post(
            "/auth/authorize",
            json={"action": "read:content"},
            headers=CSRF,
        )
        assert resp.status_code == 200
        assert resp.json()["authorized"] is True

        # 4. GET /auth/me — user info
        resp = client.get("/auth/me")
        assert resp.status_code == 200
        me = resp.json()
        assert me["sub"] == "user-123"
        assert me["email"] == "test@example.com"
        assert "admin" in me["groups"]

        # 5. POST /auth/logout — destroy session
        resp = client.post("/auth/logout", headers=CSRF)
        assert resp.status_code == 200

        # 6. GET /auth/token — should be 401 now
        resp = client.get("/auth/token")
        assert resp.status_code == 401


class TestOAuthCallbackFlow:
    """OAuth callback flow:
    callback (mock code exchange) → token → authorize → logout
    """

    def test_oauth_callback_to_logout(self, cedar_app, make_token, jwks_json):
        client = TestClient(cedar_app, cookies={}, follow_redirects=False)
        id_token = make_token(groups=["editors"])
        access_token = make_token(groups=["editors"], token_use="access")

        post_responses = {
            "oauth2/token": (200, {
                "access_token": access_token,
                "id_token": id_token,
                "refresh_token": "rt-oauth",
            }),
        }

        with _mock_httpx_for_cognito(jwks_json, post_responses):
            # 1. GET /auth/callback — exchange code for tokens
            resp = client.get("/auth/callback?code=test-auth-code&state=page1")
            assert resp.status_code == 307
            assert "/auth/success" in resp.headers["location"]
            assert "state=page1" in resp.headers["location"]

        # 2. GET /auth/token — tokens should be in session
        resp = client.get("/auth/token")
        assert resp.status_code == 200
        body = resp.json()
        assert body["auth_method"] == "oauth"

        # 3. POST /auth/authorize — editors can read
        resp = client.post(
            "/auth/authorize",
            json={"action": "read:content"},
            headers=CSRF,
        )
        assert resp.status_code == 200
        assert resp.json()["authorized"] is True

        # 4. Logout
        resp = client.post("/auth/logout", headers=CSRF)
        assert resp.status_code == 200

        # Verify logged out
        resp = client.get("/auth/token")
        assert resp.status_code == 401


class TestTokenRefreshFlow:
    """Token refresh:
    session → mock Cognito refresh → verify new tokens in session
    """

    def test_refresh_updates_session(self, app, make_token, jwks_json):
        client = TestClient(app, cookies={})
        id_token = make_token(groups=["admin"])
        access_token = make_token(groups=["admin"], token_use="access")

        # Create session
        with _mock_httpx_for_jwks(jwks_json):
            resp = client.post(
                "/auth/session",
                json={
                    "access_token": access_token,
                    "id_token": id_token,
                    "refresh_token": "rt-original",
                },
                headers=CSRF,
            )
            assert resp.status_code == 200

        # New tokens from refresh
        new_id = make_token(sub="user-123", groups=["admin"])
        new_access = make_token(sub="user-123", groups=["admin"], token_use="access")

        cognito_refresh_response = {
            "AuthenticationResult": {
                "AccessToken": new_access,
                "IdToken": new_id,
            }
        }

        post_responses = {
            "cognito-idp": (200, cognito_refresh_response),
        }
        with _mock_httpx_for_cognito(jwks_json, post_responses):
            resp = client.post("/auth/refresh", headers=CSRF)
            assert resp.status_code == 200
            body = resp.json()
            assert body["access_token"] == new_access
            assert body["id_token"] == new_id

        # Verify session was updated
        resp = client.get("/auth/token")
        assert resp.status_code == 200
        assert resp.json()["access_token"] == new_access


class TestRefreshFailureDestroysSession:
    """Refresh failure must destroy the session (security invariant #6)."""

    def test_refresh_error_clears_session(self, app, make_token, jwks_json):
        client = TestClient(app, cookies={})
        id_token = make_token(groups=["admin"])
        access_token = make_token(groups=["admin"], token_use="access")

        with _mock_httpx_for_jwks(jwks_json):
            resp = client.post(
                "/auth/session",
                json={
                    "access_token": access_token,
                    "id_token": id_token,
                    "refresh_token": "rt-will-fail",
                },
                headers=CSRF,
            )
            assert resp.status_code == 200

        # Cognito returns error
        post_responses = {
            "cognito-idp": (400, {
                "__type": "NotAuthorizedException",
                "message": "Refresh Token has been revoked",
            }),
        }
        with _mock_httpx_for_cognito(jwks_json, post_responses):
            resp = client.post("/auth/refresh", headers=CSRF)
            assert resp.status_code == 401

        # Session should be destroyed
        resp = client.get("/auth/token")
        assert resp.status_code == 401


class TestSessionIsolation:
    """Two clients with different sessions should not interfere."""

    def test_separate_sessions(self, app, make_token, jwks_json):
        client_a = TestClient(app, cookies={})
        client_b = TestClient(app, cookies={})

        admin_id = make_token(sub="admin-user", groups=["admin"], email="admin@test.com")
        admin_access = make_token(sub="admin-user", groups=["admin"], token_use="access")
        editor_id = make_token(sub="editor-user", groups=["editors"], email="editor@test.com")
        editor_access = make_token(sub="editor-user", groups=["editors"], token_use="access")

        with _mock_httpx_for_jwks(jwks_json):
            # Client A: admin
            resp = client_a.post(
                "/auth/session",
                json={"access_token": admin_access, "id_token": admin_id, "refresh_token": "rt-a"},
                headers=CSRF,
            )
            assert resp.status_code == 200

            # Client B: editor
            resp = client_b.post(
                "/auth/session",
                json={"access_token": editor_access, "id_token": editor_id, "refresh_token": "rt-b"},
                headers=CSRF,
            )
            assert resp.status_code == 200

        # Verify they see their own data
        me_a = client_a.get("/auth/me").json()
        assert me_a["sub"] == "admin-user"
        assert me_a["email"] == "admin@test.com"

        me_b = client_b.get("/auth/me").json()
        assert me_b["sub"] == "editor-user"
        assert me_b["email"] == "editor@test.com"

        # Logout A should not affect B
        client_a.post("/auth/logout", headers=CSRF)
        assert client_a.get("/auth/token").status_code == 401
        assert client_b.get("/auth/token").status_code == 200


class TestExpiredTokenRejection:
    """Session with expired tokens should return 401 from /auth/token."""

    def test_expired_token_returns_401(self, app, make_token, jwks_json):
        client = TestClient(app, cookies={})

        # Create tokens that are already expired — but bypass JWKS verify
        # since verify_id_token checks exp too. We create a "valid at creation"
        # token, store it, then test with expired tokens afterward.
        # Strategy: create session with valid tokens, then replace session
        # tokens with expired ones via a second /auth/session call.
        #
        # Actually, verify_id_token will reject expired tokens at session creation.
        # So instead, create a token that expires in 2 seconds, wait, then check.
        # But that's fragile. Better: create a valid session, then manually
        # manipulate. BUT we want to test at the HTTP boundary.
        #
        # Simplest approach: The /auth/token endpoint checks is_token_expired
        # independently. So create a session with tokens that have exp=now+1,
        # and verify_id_token will accept them (they're not expired yet), but
        # by the time we call /auth/token the exp check might pass.
        # Let's use a generous window approach: create with exp=now-1 but
        # with leeway in JWT verification... actually PyJWT has default leeway of 0.
        #
        # Best approach: create session normally, then test /auth/token
        # with time mocked forward.
        valid_id = make_token(groups=["admin"])
        valid_access = make_token(groups=["admin"], token_use="access")

        with _mock_httpx_for_jwks(jwks_json):
            resp = client.post(
                "/auth/session",
                json={"access_token": valid_access, "id_token": valid_id, "refresh_token": "rt"},
                headers=CSRF,
            )
            assert resp.status_code == 200

        # Now mock time.time() to be in the future so tokens appear expired
        future_time = time.time() + 7200  # 2 hours later (tokens expire in 1 hour)
        with patch("app.cognito.time.time", return_value=future_time):
            resp = client.get("/auth/token")
            assert resp.status_code == 401
            assert resp.json()["error"] == "Token expired"


class TestCedarOwnershipEnforcement:
    """Cedar ownership policies:
    - User writes own resource (write:own) → allowed
    - User writes other's resource (write:own) → denied by forbid policy
    - Admin writes via write:all → allowed (forbid only fires on write:own)

    The forbid policy in owner-only.cedar fires on write:own and delete:own,
    and Cedar's forbid-overrides-permit means even admin can't bypass it for
    those specific actions. Admin uses write:all instead, which has no forbid.
    """

    def test_ownership_enforcement(self, cedar_app, make_token, jwks_json):
        # Standard user client (in "users" group, which has write:own)
        user_client = TestClient(cedar_app, cookies={})
        user_id = make_token(sub="user-sub", groups=["users"], email="user@test.com")
        user_access = make_token(sub="user-sub", groups=["users"], token_use="access")

        # Admin client
        admin_client = TestClient(cedar_app, cookies={})
        admin_id = make_token(sub="admin-sub", groups=["admin"], email="admin@test.com")
        admin_access = make_token(sub="admin-sub", groups=["admin"], token_use="access")

        with _mock_httpx_for_jwks(jwks_json):
            # Create user session
            resp = user_client.post(
                "/auth/session",
                json={"access_token": user_access, "id_token": user_id},
                headers=CSRF,
            )
            assert resp.status_code == 200

            # Create admin session
            resp = admin_client.post(
                "/auth/session",
                json={"access_token": admin_access, "id_token": admin_id},
                headers=CSRF,
            )
            assert resp.status_code == 200

        # User writes own resource → allowed (permit from users + no forbid)
        resp = user_client.post(
            "/auth/authorize",
            json={
                "action": "write:own",
                "resource": {"id": "doc-1", "type": "document", "owner": "user-sub"},
            },
            headers=CSRF,
        )
        assert resp.status_code == 200
        assert resp.json()["authorized"] is True

        # User writes someone else's resource → denied (forbid fires)
        resp = user_client.post(
            "/auth/authorize",
            json={
                "action": "write:own",
                "resource": {"id": "doc-2", "type": "document", "owner": "other-user"},
            },
            headers=CSRF,
        )
        assert resp.status_code == 403
        assert resp.json()["authorized"] is False

        # Admin writes to another user's resource via write:all → allowed
        # (admin permit-all covers write:all; the forbid only fires on write:own)
        resp = admin_client.post(
            "/auth/authorize",
            json={
                "action": "write:all",
                "resource": {"id": "doc-2", "type": "document", "owner": "other-user"},
            },
            headers=CSRF,
        )
        assert resp.status_code == 200
        assert resp.json()["authorized"] is True
