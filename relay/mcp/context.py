"""Per-request MCP context.

The auth middleware resolves the bearer token to an :class:`Agent` and
stores a request context in a ContextVar.  Tool wrappers read it back.
This is how the stateless streamable-HTTP transport still carries
identity into tool execution without any session affinity.
"""
from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from relay.models.schema import Agent


@dataclass(slots=True)
class MCPRequestContext:
    """Everything a tool call needs to know about its caller."""

    agent: Agent
    db: AsyncSession


_request_ctx: ContextVar[MCPRequestContext | None] = ContextVar(
    "agentmail_mcp_request", default=None
)


def set_request_context(ctx: MCPRequestContext) -> Token:
    """Bind *ctx* to the current task/context; returns a reset token."""
    return _request_ctx.set(ctx)


def reset_request_context(token: Token) -> None:
    """Undo a previous :func:`set_request_context`."""
    _request_ctx.reset(token)


def get_request_context() -> MCPRequestContext | None:
    """Return the context bound to the current task, if any."""
    return _request_ctx.get()
