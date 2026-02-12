"""POST /auth/refresh — Refresh tokens via Cognito."""

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from .. import ocsf
from ..cognito import cognito_request
from ..config import get_settings
from ..dependencies import destroy_session, require_auth, require_csrf

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/auth/refresh")
async def refresh_tokens(
    request: Request,
    _csrf: None = Depends(require_csrf),
    tokens: dict = Depends(require_auth),
):
    if not tokens.get("refresh_token"):
        return JSONResponse({"error": "No refresh token"}, status_code=401)

    s = get_settings()

    try:
        result = await cognito_request(
            "InitiateAuth",
            {
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "ClientId": s.cognito_client_id,
                "AuthParameters": {
                    "REFRESH_TOKEN": tokens["refresh_token"],
                },
            },
        )
    except Exception as e:
        logger.error("Token refresh error: %s", e)
        email = ocsf._email_from_session(request.state.session)
        ocsf.authentication_event(
            activity_id=ocsf.AuthActivity.SERVICE_TICKET,
            activity_name="Service Ticket",
            status_id=ocsf.Status.FAILURE,
            severity_id=ocsf.Severity.MEDIUM,
            user_email=email,
            message=f"Token refresh failed: {e}",
        )
        destroy_session(request)
        return JSONResponse(
            {"error": "Refresh failed", "message": str(e)}, status_code=401
        )

    auth_result = result.get("AuthenticationResult")
    if not auth_result:
        return JSONResponse({"error": "Refresh failed"}, status_code=500)

    # Update session with new tokens
    request.state.session["tokens"] = {
        "access_token": auth_result["AccessToken"],
        "id_token": auth_result["IdToken"],
        "refresh_token": auth_result.get("RefreshToken", tokens["refresh_token"]),
        "auth_method": tokens.get("auth_method"),
    }

    email = ocsf._email_from_session(request.state.session)
    ocsf.authentication_event(
        activity_id=ocsf.AuthActivity.SERVICE_TICKET,
        activity_name="Service Ticket",
        status_id=ocsf.Status.SUCCESS,
        severity_id=ocsf.Severity.INFORMATIONAL,
        user_email=email,
        message="Token refresh succeeded",
    )

    return {
        "access_token": auth_result["AccessToken"],
        "id_token": auth_result["IdToken"],
        "auth_method": tokens.get("auth_method", "handler"),
    }
