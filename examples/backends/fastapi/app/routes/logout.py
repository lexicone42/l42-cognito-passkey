"""POST /auth/logout — Destroy session."""

from fastapi import APIRouter, Depends, Request

from ..dependencies import destroy_session, require_csrf

router = APIRouter()


@router.post("/auth/logout")
async def logout(
    request: Request,
    _csrf: None = Depends(require_csrf),
):
    destroy_session(request)
    return {"success": True}
