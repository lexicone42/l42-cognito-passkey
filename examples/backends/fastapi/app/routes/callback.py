"""GET /auth/callback — OAuth callback from Cognito Hosted UI."""

import logging
from urllib.parse import quote_plus

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from .. import ocsf
from ..cognito import exchange_code_for_tokens
from ..config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/auth/callback")
async def oauth_callback(request: Request):
    s = get_settings()
    code = request.query_params.get("code")
    state = request.query_params.get("state", "")
    error = request.query_params.get("error")
    error_description = request.query_params.get("error_description")

    if error:
        logger.error("OAuth error: %s %s", error, error_description)
        ocsf.authentication_event(
            activity_id=ocsf.AuthActivity.AUTHENTICATION_TICKET,
            activity_name="Authentication Ticket",
            status_id=ocsf.Status.FAILURE,
            severity_id=ocsf.Severity.HIGH,
            auth_protocol_id=ocsf.AuthProtocol.OAUTH2,
            auth_protocol="OAuth 2.0/OIDC",
            message=f"OAuth error: {error}",
        )
        msg = error_description or error
        return RedirectResponse(
            f"{s.frontend_url}/login?error={quote_plus(msg)}"
        )

    if not code:
        return RedirectResponse(
            f"{s.frontend_url}/login?error=Missing+authorization+code"
        )

    try:
        redirect_uri = str(request.url_for("oauth_callback"))
        token_response = await exchange_code_for_tokens(code, redirect_uri)

        request.state.session["tokens"] = {
            "access_token": token_response["access_token"],
            "id_token": token_response["id_token"],
            "refresh_token": token_response.get("refresh_token"),
            "auth_method": "oauth",
        }

        email = ocsf._email_from_session(request.state.session)
        ocsf.authentication_event(
            activity_id=ocsf.AuthActivity.AUTHENTICATION_TICKET,
            activity_name="Authentication Ticket",
            status_id=ocsf.Status.SUCCESS,
            severity_id=ocsf.Severity.INFORMATIONAL,
            user_email=email,
            auth_protocol_id=ocsf.AuthProtocol.OAUTH2,
            auth_protocol="OAuth 2.0/OIDC",
            message="OAuth token exchange succeeded",
        )

        return RedirectResponse(f"{s.frontend_url}/auth/success?state={state}")

    except Exception as e:
        logger.error("Token exchange error: %s", e)
        ocsf.authentication_event(
            activity_id=ocsf.AuthActivity.AUTHENTICATION_TICKET,
            activity_name="Authentication Ticket",
            status_id=ocsf.Status.FAILURE,
            severity_id=ocsf.Severity.MEDIUM,
            auth_protocol_id=ocsf.AuthProtocol.OAUTH2,
            auth_protocol="OAuth 2.0/OIDC",
            message=f"OAuth token exchange failed: {e}",
        )
        return RedirectResponse(
            f"{s.frontend_url}/login?error=Authentication+failed"
        )
