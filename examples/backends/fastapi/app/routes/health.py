"""GET /health — Liveness check."""

from fastapi import APIRouter

from .. import cedar_engine

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "mode": "token-handler",
        "cedar": "ready" if cedar_engine.is_initialized() else "unavailable",
    }
