"""Bearer auth middleware wrapping the mounted MCP ASGI app (§3.2, §7.1).

Every ``POST /mcp`` request is authenticated independently — stateless
by design.  On success the resolved agent + a fresh DB session are bound
to a ContextVar that tool wrappers read; on failure a JSON 401 is
returned without ever reaching the MCP machinery.
"""

from __future__ import annotations

from sqlalchemy import select
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from relay import db as db_module
from relay.crypto.envelope import hash_api_key
from relay.mcp.context import (
    MCPRequestContext,
    reset_request_context,
    set_request_context,
)
from relay.models.schema import Agent


async def _unauthorized(scope: Scope, send: Send, message: str) -> None:
    response = JSONResponse(
        status_code=401,
        content={"error": {"code": "UNAUTHORIZED", "message": message, "retry_after": None}},
        headers={"WWW-Authenticate": "Bearer"},
    )
    await response(scope, receive=None, send=send)  # type: ignore[arg-type]


class MCPAuthMiddleware:
    """ASGI middleware: ``Authorization: Bearer am_live_…`` → agent context."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        auth_header = request.headers.get("authorization", "")
        token_value = (
            auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
        )
        if not token_value:
            await _unauthorized(scope, send, "Missing or malformed Authorization header.")
            return
        if not token_value.startswith("am_live_"):
            await _unauthorized(
                scope,
                send,
                "Invalid API key format. Agent API keys must start with 'am_live_'.",
            )
            return

        async with db_module.async_session() as session:
            result = await session.execute(
                select(Agent).where(
                    Agent.api_key_hash == hash_api_key(token_value),
                    Agent.deleted_at.is_(None),
                )
            )
            agent = result.scalar_one_or_none()
            if agent is None:
                await _unauthorized(scope, send, "Invalid API key.")
                return

            context = MCPRequestContext(
                agent=agent,
                db=session,
                passphrase=request.headers.get("x-agentmail-passphrase") or None,
            )
            ctx_token = set_request_context(context)
            try:
                await self.app(scope, receive, send)
            finally:
                reset_request_context(ctx_token)
