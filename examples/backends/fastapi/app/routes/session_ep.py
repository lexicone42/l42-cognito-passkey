"""POST /auth/session — Store tokens from direct login (passkey/password)."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .. import ocsf
from ..cognito import verify_id_token
from ..dependencies import require_csrf

logger = logging.getLogger(__name__)

router = APIRouter()


class SessionRequest(BaseModel):
    access_token: str
    id_token: str
    refresh_token: str | None = None
    auth_method: str = "direct"


@router.post("/auth/session")
async def create_session(
    body: SessionRequest,
    request: Request,
    _csrf: None = Depends(require_csrf),
):
    if not body.access_token or not body.id_token:
        return JSONResponse(
            {"error": "Missing access_token or id_token"}, status_code=400
        )

    # Determine auth protocol from auth_method
    proto_id, proto_name = {
        "passkey": (ocsf.AuthProtocol.FIDO2, "FIDO2/Passkey"),
        "password": (ocsf.AuthProtocol.PASSWORD, "Password"),
    }.get(body.auth_method, (ocsf.AuthProtocol.UNKNOWN, "Unknown"))

    # Verify id_token signature via JWKS before storing
    try:
        await verify_id_token(body.id_token)
    except Exception as e:
        logger.error("Token verification failed: %s", e)
        ocsf.authentication_event(
            activity_id=ocsf.AuthActivity.LOGON,
            activity_name="Logon",
            status_id=ocsf.Status.FAILURE,
            severity_id=ocsf.Severity.MEDIUM,
            auth_protocol_id=proto_id,
            auth_protocol=proto_name,
            message=f"Session creation failed: token verification error",
        )
        return JSONResponse({"error": "Token verification failed"}, status_code=403)

    request.state.session["tokens"] = {
        "access_token": body.access_token,
        "id_token": body.id_token,
        "refresh_token": body.refresh_token,
        "auth_method": body.auth_method,
    }

    email = ocsf._email_from_session(request.state.session)
    ocsf.authentication_event(
        activity_id=ocsf.AuthActivity.LOGON,
        activity_name="Logon",
        status_id=ocsf.Status.SUCCESS,
        severity_id=ocsf.Severity.INFORMATIONAL,
        user_email=email,
        auth_protocol_id=proto_id,
        auth_protocol=proto_name,
        message="Session created via direct login",
    )

    return {"success": True}
