"""POST /auth/authorize — Cedar authorization endpoint."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .. import cedar_engine, ocsf
from ..cognito import is_token_expired
from ..dependencies import require_auth, require_csrf

logger = logging.getLogger(__name__)

router = APIRouter()


class ResourceModel(BaseModel):
    id: str | None = None
    type: str | None = None
    owner: str | None = None


class AuthorizeRequest(BaseModel):
    action: str
    resource: ResourceModel | None = None
    context: dict[str, Any] | None = None


@router.post("/auth/authorize")
async def authorize(
    body: AuthorizeRequest,
    request: Request,
    _csrf: None = Depends(require_csrf),
    tokens: dict = Depends(require_auth),
):
    if is_token_expired(tokens["id_token"]):
        return JSONResponse({"error": "Token expired"}, status_code=401)

    if not cedar_engine.is_initialized():
        email = ocsf._email_from_session(request.state.session)
        ocsf.authorization_event(
            action=body.action,
            decision="error",
            reason="Cedar engine not initialized",
            severity_id=ocsf.Severity.HIGH,
            user_email=email,
        )
        return JSONResponse(
            {"error": "Authorization engine not available", "authorized": False},
            status_code=503,
        )

    if not body.action:
        return JSONResponse(
            {"error": "Missing or invalid action"}, status_code=400
        )

    email = ocsf._email_from_session(request.state.session)
    resource = body.resource.model_dump(exclude_none=True) if body.resource else {}

    try:
        result = cedar_engine.authorize(
            session=request.state.session,
            action=body.action,
            resource=resource,
            context=body.context or {},
        )

        decision = "permit" if result["authorized"] else "deny"
        ocsf.authorization_event(
            action=body.action,
            resource=resource,
            decision=decision,
            severity_id=ocsf.Severity.INFORMATIONAL if result["authorized"] else ocsf.Severity.MEDIUM,
            user_email=email,
        )

        status = 200 if result["authorized"] else 403
        return JSONResponse(result, status_code=status)

    except Exception as e:
        logger.error("Authorization error: %s", e)
        ocsf.authorization_event(
            action=body.action,
            resource=resource,
            decision="error",
            reason=str(e),
            severity_id=ocsf.Severity.HIGH,
            user_email=email,
        )
        return JSONResponse(
            {"authorized": False, "error": "Authorization evaluation failed"},
            status_code=500,
        )
