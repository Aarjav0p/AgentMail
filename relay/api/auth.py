"""FastAPI auth dependency — Bearer token → Agent row."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from relay.crypto.envelope import hash_api_key
from relay.db import get_db
from relay.models.schema import Agent


async def get_current_agent(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Agent:
    """Resolve an agent API key to a live Agent row.

    Extracts the key from ``Authorization: Bearer am_live_...`` (canonical),
    a bare ``Authorization: am_live_...``, or ``X-API-Key: am_live_...`` —
    mirroring :func:`relay.mcp.auth._extract_token` — then SHA-256 hashes
    the raw token and looks up the ``agents`` table.

    Also stashes ``X-Agentmail-Passphrase`` (if present) on
    ``request.state.passphrase`` for downstream MCP auto-unlock.

    Raises:
        HTTPException 401: missing / invalid token, or agent deleted.
    """
    auth_header: str | None = request.headers.get("authorization")
    api_key_header: str = request.headers.get("x-api-key", "")

    raw_token = ""
    if auth_header:
        scheme, _, value = auth_header.partition(" ")
        if scheme.lower() == "bearer":
            raw_token = value.strip()
        elif auth_header.startswith("am_live_"):
            raw_token = auth_header.strip()
    if not raw_token:
        raw_token = api_key_header.strip()

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
        )

    token_hash = hash_api_key(raw_token)

    result = await db.execute(
        select(Agent).where(
            Agent.api_key_hash == token_hash,
            Agent.deleted_at.is_(None),
        )
    )
    agent = result.scalar_one_or_none()

    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )

    # Stash optional passphrase for MCP auto-unlock downstream.
    passphrase = request.headers.get("x-agentmail-passphrase")
    request.state.passphrase = passphrase  # may be None

    return agent
