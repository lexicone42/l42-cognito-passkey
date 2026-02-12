"""GET /auth/me — Return user info from ID token claims."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..cognito import decode_jwt_payload
from ..dependencies import require_auth

router = APIRouter()


@router.get("/auth/me")
async def get_me(request: Request, tokens: dict = Depends(require_auth)):
    try:
        claims = decode_jwt_payload(tokens["id_token"])
        return {
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "groups": claims.get("cognito:groups", []),
        }
    except Exception:
        return JSONResponse({"error": "Failed to decode token"}, status_code=500)
