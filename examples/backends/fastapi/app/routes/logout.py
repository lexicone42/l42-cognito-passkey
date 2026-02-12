"""POST /auth/logout — Destroy session."""

from fastapi import APIRouter, Depends, Request

from .. import ocsf
from ..dependencies import destroy_session, require_csrf

router = APIRouter()


@router.post("/auth/logout")
async def logout(
    request: Request,
    _csrf: None = Depends(require_csrf),
):
    email = ocsf._email_from_session(request.state.session)
    destroy_session(request)
    ocsf.authentication_event(
        activity_id=ocsf.AuthActivity.LOGOFF,
        activity_name="Logoff",
        status_id=ocsf.Status.SUCCESS,
        severity_id=ocsf.Severity.INFORMATIONAL,
        user_email=email,
        message="User logged out",
    )
    return {"success": True}
