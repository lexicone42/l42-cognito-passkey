"""FastAPI dependency injection: session access, CSRF, auth."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request


def get_session(request: Request) -> dict[str, Any]:
    """Get the session dict from request state."""
    return request.state.session


def require_csrf(request: Request) -> None:
    """Require X-L42-CSRF: 1 header on state-changing requests."""
    if request.headers.get("x-l42-csrf") != "1":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "CSRF validation failed",
                "message": "Missing X-L42-CSRF header",
            },
        )


def require_auth(request: Request) -> dict[str, Any]:
    """Require an authenticated session with tokens."""
    session = request.state.session
    tokens = session.get("tokens")
    if not tokens or not tokens.get("access_token") or not tokens.get("id_token"):
        raise HTTPException(status_code=401, detail={"error": "Not authenticated"})
    return tokens


def destroy_session(request: Request) -> None:
    """Mark the session for destruction."""
    request.state.session_destroyed = True
    request.state.session.clear()
