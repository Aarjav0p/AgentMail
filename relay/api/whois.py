"""Public directory lookup — ``GET /v1/agents/{handle}``."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from relay.config import settings
from relay.crypto.envelope import generate_fingerprint
from relay.db import get_db
from relay.models.schema import Agent

router = APIRouter(prefix="/v1")


@router.get("/agents/{handle}")
async def whois(
    handle: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return the public profile of a live agent.

    Raises:
        HTTPException 404: handle not found or agent has been deleted.
    """
    result = await db.execute(
        select(Agent).where(Agent.handle == handle, Agent.deleted_at.is_(None))
    )
    agent = result.scalar_one_or_none()

    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found.",
        )

    fingerprint = generate_fingerprint(agent.enc_pub, agent.sign_pub)

    return {
        "handle": agent.handle,
        "address": f"{agent.handle}@{settings.relay_domain}",
        "display_name": agent.display_name,
        "enc_pub": agent.enc_pub,
        "sign_pub": agent.sign_pub,
        "fingerprint": fingerprint,
        "created_at": agent.created_at.isoformat(),
    }
