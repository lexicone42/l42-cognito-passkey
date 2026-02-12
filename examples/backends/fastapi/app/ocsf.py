"""OCSF (Open Cybersecurity Schema Framework) event logging.

Emits structured security events matching the client-side auth.js OCSF schema.
Events are logged to the ``ocsf`` logger as JSON — consumers attach their own
handlers (CloudWatch JSON formatter, Firehose, structlog, etc.).

Usage in route handlers::

    from . import ocsf
    ocsf.authentication_event(
        activity_id=ocsf.AuthActivity.LOGON,
        activity_name="Logon",
        status_id=ocsf.Status.SUCCESS,
        severity_id=ocsf.Severity.INFORMATIONAL,
        user_email="user@example.com",
        auth_protocol_id=ocsf.AuthProtocol.FIDO2,
        auth_protocol="FIDO2/Passkey",
        message="User logged in via passkey",
    )
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger("ocsf")

# ── OCSF Constants (mirror auth.js lines 249-306) ─────────────────────────


class EventClass:
    AUTHENTICATION = 3001
    ACCOUNT_CHANGE = 3002


class AuthActivity:
    LOGON = 1
    LOGOFF = 2
    AUTHENTICATION_TICKET = 3  # OAuth token exchange
    SERVICE_TICKET = 4  # Token refresh
    OTHER = 99  # Authorization decisions


class Status:
    SUCCESS = 1
    FAILURE = 2


class Severity:
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class AuthProtocol:
    UNKNOWN = 0
    PASSWORD = 2
    OAUTH2 = 10
    FIDO2 = 99


_SEVERITY_NAMES = {
    Severity.INFORMATIONAL: "Informational",
    Severity.LOW: "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH: "High",
    Severity.CRITICAL: "Critical",
}

_PRODUCT = {
    "name": "l42-token-handler-fastapi",
    "version": "0.8.0",
    "vendor_name": "L42",
}


# ── Core emit ──────────────────────────────────────────────────────────────


def emit(event: dict[str, Any]) -> None:
    """Log an OCSF event as JSON.  Never raises — errors are silently caught."""
    try:
        logger.info(json.dumps(event, default=str))
    except Exception:
        pass


# ── Event builders ─────────────────────────────────────────────────────────


def authentication_event(
    *,
    activity_id: int,
    activity_name: str,
    status_id: int,
    severity_id: int,
    user_email: str | None = None,
    auth_protocol_id: int = AuthProtocol.UNKNOWN,
    auth_protocol: str = "Unknown",
    message: str = "",
    extra_metadata: dict[str, Any] | None = None,
) -> None:
    """Emit an OCSF Authentication (3001) event."""
    event: dict[str, Any] = {
        "class_uid": EventClass.AUTHENTICATION,
        "class_name": "Authentication",
        "activity_id": activity_id,
        "activity_name": activity_name,
        "severity_id": severity_id,
        "severity": _SEVERITY_NAMES.get(severity_id, "Unknown"),
        "status_id": status_id,
        "status": "Success" if status_id == Status.SUCCESS else "Failure",
        "time": int(time.time() * 1000),
        "metadata": {
            "product": _PRODUCT,
            **(extra_metadata or {}),
        },
        "auth_protocol_id": auth_protocol_id,
        "auth_protocol": auth_protocol,
        "message": message,
    }
    if user_email:
        event["actor"] = {
            "user": {
                "email_addr": user_email,
                "type_id": 1,
                "type": "User",
            }
        }
    emit(event)


def authorization_event(
    *,
    action: str,
    resource: dict[str, Any] | None = None,
    decision: str,
    reason: str = "",
    severity_id: int,
    user_email: str | None = None,
) -> None:
    """Emit an OCSF Authorization event (class 3001, activity 99/Other)."""
    event: dict[str, Any] = {
        "class_uid": EventClass.AUTHENTICATION,
        "class_name": "Authentication",
        "activity_id": AuthActivity.OTHER,
        "activity_name": "Other",
        "severity_id": severity_id,
        "severity": _SEVERITY_NAMES.get(severity_id, "Unknown"),
        "status_id": Status.SUCCESS if decision == "permit" else Status.FAILURE,
        "status": "Success" if decision == "permit" else "Failure",
        "time": int(time.time() * 1000),
        "metadata": {
            "product": _PRODUCT,
            "authorization": {
                "action": action,
                "resource": resource or {},
                "decision": decision,
                "reason": reason,
            },
        },
        "message": f"Cedar authorization: {decision} for {action}",
    }
    if user_email:
        event["actor"] = {
            "user": {
                "email_addr": user_email,
                "type_id": 1,
                "type": "User",
            }
        }
    emit(event)


def _email_from_session(session: dict[str, Any]) -> str | None:
    """Extract user email from session ID token (best-effort)."""
    from .cognito import decode_jwt_payload

    try:
        tokens = session.get("tokens", {})
        id_token = tokens.get("id_token", "")
        if not id_token:
            return None
        claims = decode_jwt_payload(id_token)
        return claims.get("email")
    except Exception:
        return None
