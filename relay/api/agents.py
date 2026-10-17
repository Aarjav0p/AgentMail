"""Agent registration — ``POST /v1/agents`` (§4.2)."""

from __future__ import annotations

import base64
import re

import uuid_utils
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from relay.config import settings
from relay.crypto.envelope import generate_api_key, generate_fingerprint, hash_api_key
from relay.db import get_db
from relay.models.schema import Agent, AuditLog
from relay.ratelimit import limiter
from relay.reserved import is_reserved_handle

router = APIRouter(prefix="/v1")

_HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")

# Argon2id parameter bounds — generous but sane (browser ships m=65536, t=3, p=1).
_MIN_M_KIB, _MAX_M_KIB = 8192, 1_048_576
_MIN_T, _MAX_T = 1, 10
_MIN_P, _MAX_P = 1, 4


class RegisterRequest(BaseModel):
    """Payload for ``POST /v1/agents`` — public keys + encrypted blob only."""

    handle: str
    display_name: str | None = None
    enc_pub: str
    sign_pub: str
    key_blob: str
    kdf_params: dict

    @field_validator("handle")
    @classmethod
    def validate_handle(cls, v: str) -> str:
        if not _HANDLE_RE.match(v):
            raise ValueError(
                "Handle must be 3-32 chars, lowercase alphanumeric + hyphens, "
                "starting with a letter or digit."
            )
        if is_reserved_handle(v):
            raise ValueError(f"Handle '{v}' is reserved.")
        return v

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 64:
            raise ValueError("Display name must be ≤ 64 characters.")
        return v

    @field_validator("enc_pub", "sign_pub")
    @classmethod
    def validate_pub_key(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 64:
            raise ValueError("Public keys must be 64 hex characters (32 bytes).")
        try:
            bytes.fromhex(v)
        except ValueError as exc:
            raise ValueError("Public keys must be valid hex.") from exc
        return v

    @field_validator("key_blob")
    @classmethod
    def validate_key_blob(cls, v: str) -> str:
        try:
            decoded = base64.b64decode(v, validate=True)
        except Exception as exc:
            raise ValueError("key_blob must be standard base64.") from exc
        if not (64 <= len(decoded) <= 8192):
            raise ValueError("key_blob has an implausible length.")
        return v

    @field_validator("kdf_params")
    @classmethod
    def validate_kdf_params(cls, v: dict) -> dict:
        required = {"algo", "m", "t", "p", "salt_b64"}
        if not required.issubset(v.keys()):
            raise ValueError(f"kdf_params must include {sorted(required)}.")
        if v["algo"] != "argon2id":
            raise ValueError("kdf_params.algo must be 'argon2id'.")
        try:
            m, t, p = int(v["m"]), int(v["t"]), int(v["p"])
            salt = base64.b64decode(v["salt_b64"], validate=True)
        except Exception as exc:
            raise ValueError("kdf_params m/t/p must be integers and salt base64.") from exc
        if not (_MIN_M_KIB <= m <= _MAX_M_KIB):
            raise ValueError(f"kdf_params.m must be {_MIN_M_KIB}..{_MAX_M_KIB} KiB.")
        if not (_MIN_T <= t <= _MAX_T):
            raise ValueError(f"kdf_params.t must be {_MIN_T}..{_MAX_T}.")
        if not (_MIN_P <= p <= _MAX_P):
            raise ValueError(f"kdf_params.p must be {_MIN_P}..{_MAX_P}.")
        if len(salt) != 16:
            raise ValueError("kdf_params salt must be 16 bytes.")
        return {"algo": "argon2id", "m": m, "t": t, "p": p, "salt_b64": v["salt_b64"]}


@router.post("/agents", status_code=status.HTTP_201_CREATED)
@limiter.limit("3/day")
async def register_agent(
    request: Request,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Register a new agent identity.

    Handle uniqueness is checked across *all* rows — burned handles are
    never recycled (§6.4).  Only public keys and the encrypted blob are
    accepted; the API key is generated here and returned exactly once.
    """
    exists = await db.execute(select(Agent.id).where(Agent.handle == body.handle))
    if exists.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Handle already taken (including burned handles).",
        )

    agent_id = str(uuid_utils.uuid7())
    raw_api_key = generate_api_key()

    agent = Agent(
        id=agent_id,
        handle=body.handle,
        display_name=body.display_name,
        api_key_hash=hash_api_key(raw_api_key),
        enc_pub=body.enc_pub,
        sign_pub=body.sign_pub,
        key_blob=body.key_blob,
        kdf_params=body.kdf_params,
    )
    db.add(agent)
    db.add(
        AuditLog(
            agent_id=agent_id,
            event="register",
            ip=request.client.host if request.client else None,
        )
    )

    await db.flush()
    await db.refresh(agent)  # load server defaults (created_at)

    return {
        "agent": {
            "handle": agent.handle,
            "address": f"{agent.handle}@{settings.relay_domain}",
            "fingerprint": generate_fingerprint(agent.enc_pub, agent.sign_pub),
            "created_at": agent.created_at.isoformat(),
        },
        "api_key": raw_api_key,
    }
