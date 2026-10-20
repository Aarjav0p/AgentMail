"""Bearer auth middleware wrapping the mounted MCP ASGI app (§3.2, §7.1).

Every ``POST /mcp`` request is authenticated independently — stateless
by design.  On success the resolved agent + a fresh DB session are bound
to a ContextVar that tool wrappers read; on failure a JSON 401 is
returned without ever reaching the MCP machinery.

Tokens may be presented three ways (see :func:`_extract_token`):
``Authorization: Bearer am_live_…`` (canonical), a bare
``Authorization: am_live_…``, or ``X-API-Key: am_live_…``.
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


def _extract_token(auth_header: str, api_key_header: str) -> str:
    """Extract the raw ``am_live_…`` token from a request's auth headers.

    Accepted presentations (in priority order):

    1. ``Authorization: Bearer <key>`` — the canonical, MCP-spec form
       (scheme matched case-insensitively per RFC 7235).
    2. ``Authorization: <key>`` — a bare key with no auth scheme, for
       minimal clients that pass the key through verbatim.
    3. ``X-API-Key: <key>`` — for clients whose dedicated API-key field
       sends that header (the pattern used by Anthropic's and Azure's
       APIs).

    Query-string parameters are deliberately NOT accepted: keys in URLs
    leak into server logs, proxies, and browser history.
    """
    token = ""
    if auth_header:
        scheme, _, value = auth_header.partition(" ")
        if scheme.lower() == "bearer":
            token = value.strip()
        elif auth_header.startswith("am_live_"):
            token = auth_header.strip()
    if not token:
        token = api_key_header.strip()
    return token


class MCPAuthMiddleware:
    """ASGI middleware: ``Authorization: Bearer am_live_…`` → agent context."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        token_value = _extract_token(
            request.headers.get("authorization", ""),
            request.headers.get("x-api-key", ""),
        )
        if not token_value:
            await _unauthorized(
                scope,
                send,
                "Missing or malformed Authorization header. Send "
                "'Authorization: Bearer am_live_…' (a bare am_live_… value "
                "or an X-API-Key header is also accepted).",
            )
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

            context = MCPRequestContext(agent=agent, db=session)
            ctx_token = set_request_context(context)
            try:
                await self.app(scope, receive, send)
            finally:
                reset_request_context(ctx_token)
