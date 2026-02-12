"""FastAPI Token Handler backend for l42-cognito-passkey.

Implements the Token Handler protocol (docs/token-handler-spec.md) with
Cedar authorization via cedarpy.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import cedar_engine
from .config import get_settings
from .routes import authorize, callback, health, logout, me, refresh, session_ep, token
from .session import InMemoryBackend, SessionMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialize Cedar engine (non-blocking)."""
    cedar_dir = Path(__file__).parent.parent / "cedar"
    try:
        cedar_engine.init_cedar_engine(
            schema_path=str(cedar_dir / "schema.cedarschema.json"),
            policy_dir=str(cedar_dir / "policies"),
        )
        logger.info("Cedar: initialized (policies validated)")
    except Exception as e:
        logger.error("Cedar: FAILED — %s", e)
        logger.error("Authorization endpoint will return 503")
    yield


def create_app(
    *,
    session_backend=None,
    skip_cedar: bool = False,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        session_backend: Custom session backend (default: InMemoryBackend).
        skip_cedar: Skip Cedar initialization (for testing).
    """
    app_lifespan = None if skip_cedar else lifespan
    app = FastAPI(title="L42 Token Handler", lifespan=app_lifespan)
    s = get_settings()

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[s.frontend_url],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Server-side sessions
    backend = session_backend or InMemoryBackend()
    app.add_middleware(
        SessionMiddleware,
        secret=s.session_secret,
        backend=backend,
        https_only=s.session_https_only,
    )

    # Routes
    app.include_router(token.router)
    app.include_router(session_ep.router)
    app.include_router(refresh.router)
    app.include_router(logout.router)
    app.include_router(callback.router)
    app.include_router(authorize.router)
    app.include_router(me.router)
    app.include_router(health.router)

    return app
