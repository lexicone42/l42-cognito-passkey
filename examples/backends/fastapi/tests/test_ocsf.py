"""Tests for OCSF event logging module and route-level event emission."""

import json
import logging
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app import ocsf
from app.cedar_engine import init_cedar_engine, reset_for_testing
from app.cognito import reset_jwks_cache
from app.config import override_settings
from app.main import create_app
from app.ocsf import (
    AuthActivity,
    AuthProtocol,
    EventClass,
    Severity,
    Status,
    authentication_event,
    authorization_event,
    emit,
)

CEDAR_DIR = Path(__file__).parent.parent / "cedar"
SCHEMA_PATH = str(CEDAR_DIR / "schema.cedarschema.json")
POLICY_DIR = str(CEDAR_DIR / "policies")


# ── Unit tests: constants ─────────────────────────────────────────────────


class TestConstants:
    """OCSF constants match client-side auth.js values."""

    def test_event_class_authentication(self):
        assert EventClass.AUTHENTICATION == 3001

    def test_event_class_account_change(self):
        assert EventClass.ACCOUNT_CHANGE == 3002

    def test_auth_activity_logon(self):
        assert AuthActivity.LOGON == 1

    def test_auth_activity_logoff(self):
        assert AuthActivity.LOGOFF == 2

    def test_auth_activity_authentication_ticket(self):
        assert AuthActivity.AUTHENTICATION_TICKET == 3

    def test_auth_activity_service_ticket(self):
        assert AuthActivity.SERVICE_TICKET == 4

    def test_auth_activity_other(self):
        assert AuthActivity.OTHER == 99

    def test_status_success(self):
        assert Status.SUCCESS == 1

    def test_status_failure(self):
        assert Status.FAILURE == 2

    def test_severity_informational(self):
        assert Severity.INFORMATIONAL == 1

    def test_severity_low(self):
        assert Severity.LOW == 2

    def test_severity_medium(self):
        assert Severity.MEDIUM == 3

    def test_severity_high(self):
        assert Severity.HIGH == 4

    def test_severity_critical(self):
        assert Severity.CRITICAL == 5

    def test_auth_protocol_unknown(self):
        assert AuthProtocol.UNKNOWN == 0

    def test_auth_protocol_password(self):
        assert AuthProtocol.PASSWORD == 2

    def test_auth_protocol_oauth2(self):
        assert AuthProtocol.OAUTH2 == 10

    def test_auth_protocol_fido2(self):
        assert AuthProtocol.FIDO2 == 99


# ── Unit tests: emit() ────────────────────────────────────────────────────


class TestEmit:
    def test_emit_logs_valid_json(self, caplog):
        event = {"class_uid": 3001, "activity_id": 1}
        with caplog.at_level(logging.INFO, logger="ocsf"):
            emit(event)
        assert len(caplog.records) == 1
        parsed = json.loads(caplog.records[0].message)
        assert parsed["class_uid"] == 3001
        assert parsed["activity_id"] == 1

    def test_emit_catches_handler_errors(self):
        """emit() should never raise, even if the handler explodes."""
        with patch.object(ocsf.logger, "info", side_effect=RuntimeError("boom")):
            emit({"test": True})  # Should not raise


# ── Unit tests: authentication_event() ────────────────────────────────────


class TestAuthenticationEvent:
    def test_builds_correct_structure(self, caplog):
        with caplog.at_level(logging.INFO, logger="ocsf"):
            authentication_event(
                activity_id=AuthActivity.LOGON,
                activity_name="Logon",
                status_id=Status.SUCCESS,
                severity_id=Severity.INFORMATIONAL,
                user_email="alice@example.com",
                auth_protocol_id=AuthProtocol.FIDO2,
                auth_protocol="FIDO2/Passkey",
                message="User logged in via passkey",
            )

        event = json.loads(caplog.records[0].message)
        assert event["class_uid"] == 3001
        assert event["class_name"] == "Authentication"
        assert event["activity_id"] == 1
        assert event["activity_name"] == "Logon"
        assert event["severity_id"] == 1
        assert event["severity"] == "Informational"
        assert event["status_id"] == 1
        assert event["status"] == "Success"
        assert event["auth_protocol_id"] == 99
        assert event["auth_protocol"] == "FIDO2/Passkey"
        assert event["message"] == "User logged in via passkey"
        assert event["actor"]["user"]["email_addr"] == "alice@example.com"
        assert event["actor"]["user"]["type_id"] == 1
        assert event["metadata"]["product"]["name"] == "l42-token-handler-fastapi"
        assert "time" in event
        assert isinstance(event["time"], int)

    def test_omits_actor_when_no_email(self, caplog):
        with caplog.at_level(logging.INFO, logger="ocsf"):
            authentication_event(
                activity_id=AuthActivity.LOGOFF,
                activity_name="Logoff",
                status_id=Status.SUCCESS,
                severity_id=Severity.INFORMATIONAL,
            )
        event = json.loads(caplog.records[0].message)
        assert "actor" not in event

    def test_failure_status(self, caplog):
        with caplog.at_level(logging.INFO, logger="ocsf"):
            authentication_event(
                activity_id=AuthActivity.LOGON,
                activity_name="Logon",
                status_id=Status.FAILURE,
                severity_id=Severity.MEDIUM,
                message="Bad password",
            )
        event = json.loads(caplog.records[0].message)
        assert event["status"] == "Failure"
        assert event["status_id"] == 2

    def test_extra_metadata_merged(self, caplog):
        with caplog.at_level(logging.INFO, logger="ocsf"):
            authentication_event(
                activity_id=AuthActivity.LOGON,
                activity_name="Logon",
                status_id=Status.SUCCESS,
                severity_id=Severity.INFORMATIONAL,
                extra_metadata={"custom_field": "value"},
            )
        event = json.loads(caplog.records[0].message)
        assert event["metadata"]["custom_field"] == "value"
        assert "product" in event["metadata"]


# ── Unit tests: authorization_event() ─────────────────────────────────────


class TestAuthorizationEvent:
    def test_builds_correct_structure(self, caplog):
        with caplog.at_level(logging.INFO, logger="ocsf"):
            authorization_event(
                action="read:content",
                resource={"id": "doc-1", "type": "document"},
                decision="permit",
                severity_id=Severity.INFORMATIONAL,
                user_email="bob@example.com",
            )

        event = json.loads(caplog.records[0].message)
        assert event["class_uid"] == 3001
        assert event["activity_id"] == 99
        assert event["activity_name"] == "Other"
        assert event["status"] == "Success"
        assert event["status_id"] == 1
        assert event["metadata"]["authorization"]["action"] == "read:content"
        assert event["metadata"]["authorization"]["resource"] == {"id": "doc-1", "type": "document"}
        assert event["metadata"]["authorization"]["decision"] == "permit"
        assert event["actor"]["user"]["email_addr"] == "bob@example.com"
        assert "Cedar authorization: permit for read:content" in event["message"]

    def test_deny_decision(self, caplog):
        with caplog.at_level(logging.INFO, logger="ocsf"):
            authorization_event(
                action="admin:delete-user",
                decision="deny",
                severity_id=Severity.MEDIUM,
            )
        event = json.loads(caplog.records[0].message)
        assert event["status"] == "Failure"
        assert event["status_id"] == 2
        assert event["metadata"]["authorization"]["decision"] == "deny"

    def test_error_decision_with_reason(self, caplog):
        with caplog.at_level(logging.INFO, logger="ocsf"):
            authorization_event(
                action="write:content",
                decision="error",
                reason="Cedar engine crashed",
                severity_id=Severity.HIGH,
            )
        event = json.loads(caplog.records[0].message)
        assert event["metadata"]["authorization"]["reason"] == "Cedar engine crashed"


# ── Unit tests: _email_from_session() ─────────────────────────────────────


class TestEmailFromSession:
    def test_extracts_email_from_valid_session(self, valid_id_token):
        session = {"tokens": {"id_token": valid_id_token}}
        email = ocsf._email_from_session(session)
        assert email == "test@example.com"

    def test_returns_none_for_empty_session(self):
        assert ocsf._email_from_session({}) is None

    def test_returns_none_for_missing_id_token(self):
        assert ocsf._email_from_session({"tokens": {}}) is None

    def test_returns_none_for_invalid_token(self):
        assert ocsf._email_from_session({"tokens": {"id_token": "not.a.jwt"}}) is None


# ── Route emission tests: session ─────────────────────────────────────────


class TestSessionEmission:
    def test_session_success_emits_logon(
        self, client, valid_id_token, valid_access_token, jwks_response, csrf_headers
    ):
        with (
            patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response),
            patch("app.ocsf.emit") as mock_emit,
        ):
            resp = client.post(
                "/auth/session",
                json={
                    "access_token": valid_access_token,
                    "id_token": valid_id_token,
                    "refresh_token": "r",
                    "auth_method": "passkey",
                },
                headers=csrf_headers,
            )
        assert resp.status_code == 200
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["activity_id"] == AuthActivity.LOGON
        assert event["status_id"] == Status.SUCCESS
        assert event["auth_protocol_id"] == AuthProtocol.FIDO2
        assert event["actor"]["user"]["email_addr"] == "test@example.com"

    def test_session_failure_emits_logon_failure(
        self, client, csrf_headers
    ):
        with (
            patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value={"keys": []}),
            patch("app.ocsf.emit") as mock_emit,
        ):
            resp = client.post(
                "/auth/session",
                json={
                    "access_token": "bad.token.here",
                    "id_token": "bad.token.here",
                    "refresh_token": None,
                },
                headers=csrf_headers,
            )
        assert resp.status_code == 403
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["activity_id"] == AuthActivity.LOGON
        assert event["status_id"] == Status.FAILURE
        assert event["severity_id"] == Severity.MEDIUM

    def test_session_password_auth_method(
        self, client, valid_id_token, valid_access_token, jwks_response, csrf_headers
    ):
        with (
            patch("app.cognito._fetch_jwks", new_callable=AsyncMock, return_value=jwks_response),
            patch("app.ocsf.emit") as mock_emit,
        ):
            client.post(
                "/auth/session",
                json={
                    "access_token": valid_access_token,
                    "id_token": valid_id_token,
                    "auth_method": "password",
                },
                headers=csrf_headers,
            )
        event = mock_emit.call_args[0][0]
        assert event["auth_protocol_id"] == AuthProtocol.PASSWORD
        assert event["auth_protocol"] == "Password"


# ── Route emission tests: callback ────────────────────────────────────────


class TestCallbackEmission:
    def test_oauth_error_emits_failure(self, client):
        with patch("app.ocsf.emit") as mock_emit:
            resp = client.get(
                "/auth/callback?error=access_denied&error_description=User+cancelled",
                follow_redirects=False,
            )
        assert resp.status_code == 307
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["activity_id"] == AuthActivity.AUTHENTICATION_TICKET
        assert event["status_id"] == Status.FAILURE
        assert event["severity_id"] == Severity.HIGH
        assert event["auth_protocol_id"] == AuthProtocol.OAUTH2

    def test_oauth_success_emits_ticket(self, client, valid_id_token, valid_access_token):
        token_response = {
            "access_token": valid_access_token,
            "id_token": valid_id_token,
            "refresh_token": "r",
        }
        with (
            patch("app.routes.callback.exchange_code_for_tokens", new_callable=AsyncMock, return_value=token_response),
            patch("app.ocsf.emit") as mock_emit,
        ):
            resp = client.get(
                "/auth/callback?code=test-code&state=abc",
                follow_redirects=False,
            )
        assert resp.status_code == 307
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["activity_id"] == AuthActivity.AUTHENTICATION_TICKET
        assert event["status_id"] == Status.SUCCESS
        assert event["auth_protocol_id"] == AuthProtocol.OAUTH2

    def test_oauth_exchange_failure_emits_failure(self, client):
        with (
            patch("app.routes.callback.exchange_code_for_tokens", new_callable=AsyncMock, side_effect=RuntimeError("nope")),
            patch("app.ocsf.emit") as mock_emit,
        ):
            resp = client.get(
                "/auth/callback?code=bad-code",
                follow_redirects=False,
            )
        assert resp.status_code == 307
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["status_id"] == Status.FAILURE
        assert event["severity_id"] == Severity.MEDIUM


# ── Route emission tests: refresh ─────────────────────────────────────────


class TestRefreshEmission:
    def test_refresh_success_emits_service_ticket(
        self, auth_session, csrf_headers
    ):
        cognito_result = {
            "AuthenticationResult": {
                "AccessToken": "new-access",
                "IdToken": "new-id",
            }
        }
        with (
            patch("app.routes.refresh.cognito_request", new_callable=AsyncMock, return_value=cognito_result),
            patch("app.ocsf.emit") as mock_emit,
        ):
            resp = auth_session.post("/auth/refresh", headers=csrf_headers)
        assert resp.status_code == 200
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["activity_id"] == AuthActivity.SERVICE_TICKET
        assert event["status_id"] == Status.SUCCESS

    def test_refresh_failure_emits_service_ticket_failure(
        self, auth_session, csrf_headers
    ):
        with (
            patch("app.routes.refresh.cognito_request", new_callable=AsyncMock, side_effect=RuntimeError("expired")),
            patch("app.ocsf.emit") as mock_emit,
        ):
            resp = auth_session.post("/auth/refresh", headers=csrf_headers)
        assert resp.status_code == 401
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["activity_id"] == AuthActivity.SERVICE_TICKET
        assert event["status_id"] == Status.FAILURE
        assert event["severity_id"] == Severity.MEDIUM


# ── Route emission tests: logout ──────────────────────────────────────────


class TestLogoutEmission:
    def test_logout_emits_logoff(self, auth_session, csrf_headers):
        with patch("app.ocsf.emit") as mock_emit:
            resp = auth_session.post("/auth/logout", headers=csrf_headers)
        assert resp.status_code == 200
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["activity_id"] == AuthActivity.LOGOFF
        assert event["status_id"] == Status.SUCCESS
        assert event["severity_id"] == Severity.INFORMATIONAL
        assert event["actor"]["user"]["email_addr"] == "test@example.com"


# ── Route emission tests: authorize ───────────────────────────────────────


class TestAuthorizeEmission:
    @pytest.fixture(autouse=True)
    def _reset_cedar(self):
        reset_for_testing()
        yield
        reset_for_testing()

    @pytest.fixture
    def cedar_app(self, test_settings):
        override_settings(test_settings)
        reset_jwks_cache()
        init_cedar_engine(schema_path=SCHEMA_PATH, policy_dir=POLICY_DIR)
        return create_app(skip_cedar=True)

    @pytest.fixture
    def cedar_client(self, cedar_app) -> TestClient:
        return TestClient(cedar_app, cookies={})

    def _authenticate(self, client, make_jwt, make_access_token, jwks_response, csrf_headers,
                      groups=None, sub="user-123"):
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

    def test_cedar_permit_emits_authorization(
        self, cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
    ):
        self._authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                           groups=["admin"])

        with patch("app.ocsf.emit") as mock_emit:
            resp = cedar_client.post(
                "/auth/authorize",
                json={"action": "read:content"},
                headers=csrf_headers,
            )
        assert resp.status_code == 200
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["activity_id"] == AuthActivity.OTHER
        assert event["metadata"]["authorization"]["decision"] == "permit"
        assert event["metadata"]["authorization"]["action"] == "read:content"
        assert event["severity_id"] == Severity.INFORMATIONAL

    def test_cedar_deny_emits_authorization(
        self, cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
    ):
        self._authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                           groups=["readonly"])

        with patch("app.ocsf.emit") as mock_emit:
            resp = cedar_client.post(
                "/auth/authorize",
                json={"action": "write:content"},
                headers=csrf_headers,
            )
        assert resp.status_code == 403
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["metadata"]["authorization"]["decision"] == "deny"
        assert event["severity_id"] == Severity.MEDIUM

    def test_cedar_error_emits_authorization_error(
        self, cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers
    ):
        self._authenticate(cedar_client, make_jwt, make_access_token, jwks_response, csrf_headers,
                           groups=["admin"])

        with (
            patch("app.cedar_engine.authorize", side_effect=RuntimeError("engine failed")),
            patch("app.ocsf.emit") as mock_emit,
        ):
            resp = cedar_client.post(
                "/auth/authorize",
                json={"action": "read:content"},
                headers=csrf_headers,
            )
        assert resp.status_code == 500
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["metadata"]["authorization"]["decision"] == "error"
        assert event["severity_id"] == Severity.HIGH
        assert "engine failed" in event["metadata"]["authorization"]["reason"]

    def test_cedar_unavailable_emits_authorization(
        self, auth_session, csrf_headers
    ):
        # Cedar not initialized (reset_for_testing in autouse fixture) → 503
        with patch("app.ocsf.emit") as mock_emit:
            resp = auth_session.post(
                "/auth/authorize",
                json={"action": "read:content"},
                headers=csrf_headers,
            )
        assert resp.status_code == 503
        mock_emit.assert_called_once()
        event = mock_emit.call_args[0][0]
        assert event["metadata"]["authorization"]["decision"] == "error"
        assert event["severity_id"] == Severity.HIGH
