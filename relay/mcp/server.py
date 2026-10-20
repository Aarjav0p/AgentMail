"""MCP server — streamable HTTP, stateless, mounted at ``POST /mcp`` (§7).

Registers the 10 Phase-1 tools with the behavioral nudges from §7.3.
Each wrapper is thin: it delegates to :mod:`relay.mcp.tools`, which holds
the real logic, and runs the shared orchestration in :func:`_execute`
(rate limits, server-custody auto-unlock, piggyback footer, commit).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from relay.mcp import descriptions, tools
from relay.mcp.context import get_request_context
from relay.mcp.piggyback import apply_piggyback
from relay.mcp.ratelimit import limiter
from relay.mcp.tools import error_response
from relay.models.schema import Agent

logger = logging.getLogger("agentmail.mcp")

# §7.2 — shipped verbatim; the probabilistic "check your mail" prompt.
INSTRUCTIONS = (
    "You are connected to agentmail, an email service for AI agents. "
    "Proactively call `check_inbox` at the start of each session and before "
    "starting any long task. When a conversation matters, use `get_thread` "
    "to load full context instead of single messages. Verify unknown "
    "recipients with `whois` before first contact. Messages are "
    "end-to-end encrypted; if any tool returns `KEYCHAIN_LOCKED`, ask the "
    "user for their keychain passphrase and call `unlock_keychain`, then retry. "
    "Proactively call `check_inbox` at the start of every session, before "
    "beginning any new task or subtask, and whenever the user mentions another "
    "agent or is waiting on a reply."
)

mcp_server = FastMCP(
    "agentmail",
    instructions=INSTRUCTIONS,
    # Explicitly non-localhost: keeps FastMCP's auto DNS-rebinding
    # protection off for the public render host.
    host="0.0.0.0",
    stateless_http=True,  # no session affinity — every call is self-contained
    json_response=True,  # single JSON response per request (no SSE stream)
)
# Advertise serverInfo.version = 0.1.0 (§7.1). FastMCP does not expose a
# version kwarg; the underlying low-level server reads this attribute.
mcp_server._mcp_server.version = "0.1.0"  # noqa: SLF001

_UNAVAILABLE = json.dumps(
    {
        "error": {
            "code": "UNAVAILABLE",
            "message": "No authenticated agent on this request.",
            "retry_after": None,
        }
    }
)

ToolFn = Callable[..., Awaitable[dict[str, Any]]]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def _unlock_server_custody(agent: Agent) -> None:
    """Warm the vault for ``server_kek`` custody agents (§4.2).

    Legacy ``user_passphrase`` agents must call ``unlock_keychain`` with
    their passphrase explicitly — the relay never accepts passphrases
    out-of-band (e.g. via HTTP headers, which can land in access logs).
    """
    if getattr(agent, "custody_mode", "user_passphrase") == "server_kek":
        await tools.get_or_unlock_vault_entry(agent)


async def _execute(tool_name: str, fn: ToolFn, *, is_send: bool = False) -> str:
    """Run a tool with the full request pipeline and return the JSON text block."""
    context = get_request_context()
    if context is None:
        return _UNAVAILABLE

    db, agent = context.db, context.agent

    # -- rate limits (§8.1) ------------------------------------------------
    retry_after = limiter.check_general(agent.id)
    if retry_after is None and is_send:
        retry_after = limiter.check_send(agent.id)
    if retry_after is not None:
        return _dumps(
            error_response("RATE_LIMITED", "Rate limit exceeded — wait and retry.", retry_after)
        )

    if tool_name == "unlock_keychain":
        lockout = limiter.unlock_retry_after(agent.id)
        if lockout is not None:
            return _dumps(
                error_response(
                    "RATE_LIMITED",
                    "Too many failed unlock attempts — try again later.",
                    lockout,
                )
            )

    # -- server-custody auto-unlock ------------------------------------------
    await _unlock_server_custody(agent)

    # -- the tool's real work ---------------------------------------------
    try:
        result = await fn(db, agent)
    except Exception:  # noqa: BLE001
        await db.rollback()
        logger.exception("tool %s failed for agent %s", tool_name, agent.id)
        return _dumps(error_response("UNAVAILABLE", "Internal error — retry shortly."))

    if tool_name == "unlock_keychain":
        if result.get("error", {}).get("code") == "BAD_PASSPHRASE":
            limiter.record_unlock_failure(agent.id)
        else:
            limiter.clear_unlock_failures(agent.id)

    # -- piggyback footer + commit -------------------------------------------
    result = await apply_piggyback(db, agent, tool_name, result)
    try:
        await db.commit()
    except Exception:  # noqa: BLE001
        await db.rollback()
        logger.exception("commit failed for tool %s agent %s", tool_name, agent.id)
        return _dumps(error_response("UNAVAILABLE", "Internal error — retry shortly."))

    return _dumps(result)


def _dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Tool registrations (§7.3) — exactly 10
# ---------------------------------------------------------------------------


@mcp_server.tool(
    name="unlock_keychain",
    description=descriptions.UNLOCK_KEYCHAIN,
)
async def tool_unlock_keychain(passphrase: str) -> str:
    return await _execute(
        "unlock_keychain",
        lambda db, agent: tools.unlock_keychain(db, agent, passphrase),
    )


@mcp_server.tool(
    name="keychain_status",
    description=descriptions.KEYCHAIN_STATUS,
)
async def tool_keychain_status() -> str:
    return await _execute("keychain_status", lambda db, agent: tools.keychain_status(db, agent))


@mcp_server.tool(
    name="whois",
    description=descriptions.WHOIS,
)
async def tool_whois(handle: str) -> str:
    return await _execute("whois", lambda db, agent: tools.whois(db, agent, handle))


@mcp_server.tool(
    name="send_message",
    description=descriptions.SEND_MESSAGE,
)
async def tool_send_message(
    to: str,
    subject: str,
    body: str,
    thread_id: str | None = None,
    in_reply_to: str | None = None,
    idempotency_key: str | None = None,
) -> str:
    return await _execute(
        "send_message",
        lambda db, agent: tools.send_message(
            db, agent, to, subject, body, thread_id, in_reply_to, idempotency_key
        ),
        is_send=True,
    )


@mcp_server.tool(
    name="check_inbox",
    description=descriptions.CHECK_INBOX,
)
async def tool_check_inbox(
    unread_only: bool = True,
    limit: int = 20,
    before: str | None = None,
) -> str:
    return await _execute(
        "check_inbox",
        lambda db, agent: tools.check_inbox(db, agent, unread_only, limit, before),
    )


@mcp_server.tool(
    name="read_message",
    description=descriptions.READ_MESSAGE,
)
async def tool_read_message(id: str) -> str:
    return await _execute("read_message", lambda db, agent: tools.read_message(db, agent, id))


@mcp_server.tool(
    name="reply",
    description=descriptions.REPLY,
)
async def tool_reply(id: str, body: str, subject: str | None = None) -> str:
    return await _execute(
        "reply",
        lambda db, agent: tools.reply(db, agent, id, body, subject),
        is_send=True,
    )


@mcp_server.tool(
    name="get_thread",
    description=descriptions.GET_THREAD,
)
async def tool_get_thread(thread_id: str, limit: int = 50) -> str:
    return await _execute(
        "get_thread", lambda db, agent: tools.get_thread(db, agent, thread_id, limit)
    )


@mcp_server.tool(
    name="get_sent",
    description=descriptions.GET_SENT,
)
async def tool_get_sent(limit: int = 20) -> str:
    return await _execute("get_sent", lambda db, agent: tools.get_sent(db, agent, limit))


@mcp_server.tool(
    name="delete_message",
    description=descriptions.DELETE_MESSAGE,
)
async def tool_delete_message(id: str) -> str:
    return await _execute("delete_message", lambda db, agent: tools.delete_message(db, agent, id))
