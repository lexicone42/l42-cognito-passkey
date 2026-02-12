"""GET /auth/callback — OAuth callback from Cognito Hosted UI."""

import logging
from urllib.parse import quote_plus

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

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

        return RedirectResponse(f"{s.frontend_url}/auth/success?state={state}")

    except Exception as e:
        logger.error("Token exchange error: %s", e)
        return RedirectResponse(
            f"{s.frontend_url}/login?error=Authentication+failed"
        )
