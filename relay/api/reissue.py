"""API-key reissue via Ed25519 challenge-response — §6.5."""
from __future__ import annotations

import base64
import os
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from nacl.signing import VerifyKey
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from relay.config import settings
from relay.crypto.envelope import generate_api_key, hash_api_key
from relay.db import get_db
from relay.models.schema import Agent, AuditLog
from relay.ratelimit import limiter

router = APIRouter(prefix="/v1")

# ── In-memory challenge store with 5-minute TTL ────────────────────────────

_CHALLENGE_TTL_SECONDS = 300  # 5 minutes

_pending_challenges: dict[str, tuple[bytes, float]] = {}
"""handle → (challenge_bytes, created_epoch)"""


def _prune_expired() -> None:
    """Remove stale challenges — called before every read/write."""
    cutoff = time.monotonic() - _CHALLENGE_TTL_SECONDS
    expired = [h for h, (_, t) in _pending_challenges.items() if t < cutoff]
    for h in expired:
        del _pending_challenges[h]


# ── Helpers ─────────────────────────────────────────────────────────────────


async def _get_live_agent(handle: str, db: AsyncSession) -> Agent:
    """Look up a live agent by handle, or raise 404."""
    result = await db.execute(
        select(Agent).where(Agent.handle == handle, Agent.deleted_at.is_(None))
    )
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found.",
        )
    return agent


# ── Request schemas ─────────────────────────────────────────────────────────


class ReissueRequest(BaseModel):
    """Body for ``POST /v1/agents/{handle}/reissue``."""

    challenge_response: str  # base64-encoded Ed25519 signature over challenge


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.post("/agents/{handle}/reissue/challenge")
@limiter.limit("5/hour")
async def reissue_challenge(
    handle: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate a random 32-byte challenge for API key reissue.

    The challenge is held in-memory with a 5-minute TTL.  The client
    must sign it with their Ed25519 private key and present the
    signature at ``POST /v1/agents/{handle}/reissue``.
    """
    agent = await _get_live_agent(handle, db)

    challenge_bytes = os.urandom(32)
    _prune_expired()
    _pending_challenges[handle] = (challenge_bytes, time.monotonic())

    # Audit.
    db.add(
        AuditLog(
            agent_id=agent.id,
            event="reissue_challenge",
            ip=request.client.host if request.client else None,
        )
    )

    return {
        "challenge": base64.b64encode(challenge_bytes).decode(),
        "key_blob": agent.key_blob,
        "kdf_params": agent.kdf_params,
    }


@router.post("/agents/{handle}/reissue")
async def reissue(
    handle: str,
    body: ReissueRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Verify the challenge signature and issue a fresh API key.

    Raises:
        HTTPException 400: no pending challenge or signature invalid.
    """
    _prune_expired()
    pending = _pending_challenges.get(handle)
    if pending is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending challenge for this handle (expired or not requested).",
        )

    challenge_bytes, _ = pending
    agent = await _get_live_agent(handle, db)

    # Verify Ed25519 signature.
    try:
        sig_bytes = base64.b64decode(body.challenge_response)
        verify_key = VerifyKey(bytes.fromhex(agent.sign_pub))
        verify_key.verify(challenge_bytes, sig_bytes)
    except Exception as exc:  # bad base64, bad hex, or bad signature
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge verification failed.",
        ) from exc

    # Rotate API key.
    raw_api_key = generate_api_key()
    agent.api_key_hash = hash_api_key(raw_api_key)

    # Clear challenge.
    _pending_challenges.pop(handle, None)

    # Audit.
    db.add(
        AuditLog(
            agent_id=agent.id,
            event="reissue",
            ip=request.client.host if request.client else None,
        )
    )

    return {
        "api_key": raw_api_key,
        "address": f"{agent.handle}@{settings.relay_domain}",
    }
