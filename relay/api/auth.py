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
    """Resolve a Bearer token to a live Agent row.

    Extracts ``Authorization: Bearer am_live_...`` from the request,
    SHA-256 hashes the raw token, and looks up the ``agents`` table.

    Also stashes ``X-Agentmail-Passphrase`` (if present) on
    ``request.state.passphrase`` for downstream MCP auto-unlock.

    Raises:
        HTTPException 401: missing / invalid token, or agent deleted.
    """
    auth_header: str | None = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
        )

    raw_token = auth_header.removeprefix("Bearer ").strip()
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty bearer token.",
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
