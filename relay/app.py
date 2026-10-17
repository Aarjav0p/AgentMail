"""agentmail relay — the single FastAPI application (§3.2).

Three surfaces on one instance:
* ``POST /mcp``          — remote MCP server (stateless streamable HTTP, Bearer)
* ``/v1/*``              — REST (register, whois, reissue, health, admin)
* ``GET /register``      — browser key-generation page (static HTML + vendored libs)
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from slowapi.errors import RateLimitExceeded
from slowapi.extension import _rate_limit_exceeded_handler
from starlette.staticfiles import StaticFiles

from relay.api import admin, agents, health, reissue, whois
from relay.crypto.vault import vault
from relay.mcp.auth import MCPAuthMiddleware
from relay.mcp.server import mcp_server
from relay.ratelimit import limiter

logger = logging.getLogger("agentmail")

_STATIC_DIR = Path(__file__).parent / "static"

# The MCP streamable-HTTP ASGI app, wrapped with Bearer auth.  Built once
# at import so ``mcp_server.session_manager`` exists for the lifespan.
mcp_http_app = MCPAuthMiddleware(mcp_server.streamable_http_app())


async def _vault_sweeper() -> None:
    """Periodically purge idle vault entries (belt and braces — the vault
    also expires entries lazily on access)."""
    while True:
        await asyncio.sleep(60)
        try:
            await vault.purge_expired()
        except Exception:  # noqa: BLE001
            logger.exception("vault sweeper iteration failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Mounted Starlette apps don't get their lifespan run by Starlette's
    # router, so the streamable-HTTP session manager is started explicitly.
    async with mcp_server.session_manager.run():
        sweeper = asyncio.create_task(_vault_sweeper())
        try:
            yield
        finally:
            sweeper.cancel()


app = FastAPI(title="agentmail", version="0.1.0", lifespan=lifespan)

# REST rate limiting (§8.1) — decorators live on the routes; the handler
# turns breaches into clean 429s across the app.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(health.router)
app.include_router(agents.router)
app.include_router(whois.router)
app.include_router(reissue.router)
app.include_router(admin.router)


@app.get("/register", include_in_schema=False)
async def register_page() -> FileResponse:
    """The browser registration / recovery / export page (§4.2)."""
    return FileResponse(_STATIC_DIR / "register.html")


app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

# Mounted last: the MCP app owns everything else (its streamable-HTTP
# route is ``/mcp``), so REST/documentation routes above always win.
app.mount("/", mcp_http_app)
