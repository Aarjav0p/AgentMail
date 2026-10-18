"""Dashboard account endpoints — ``/v1/account/*`` (DASH-01).

Manages account-owned agents, API key reveal/rotate, handle availability,
and the contact-alias address book.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
from typing import Any

import jwt
import uuid_utils
from fastapi import APIRouter, Depends, Request, Response, status
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from pydantic import BaseModel
from slowapi.util import get_remote_address
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from relay.api.jwks import ASYM_ALGS, get_verification_key
from relay.config import settings
from relay.crypto.envelope import (
    decrypt_server_kek,
    encrypt_server_kek,
    generate_api_key,
    generate_fingerprint,
    hash_api_key,
)
from relay.db import get_db
from relay.models.schema import Agent, AuditLog, UserContact
from relay.ratelimit import limiter
from relay.reserved import is_reserved_handle

router = APIRouter(prefix="/v1/account")

logger = logging.getLogger(__name__)

_HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")
_ALIAS_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
_TARGET_HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")


class AccountError(Exception):
    """Domain error returned in uniform {error: {code, message}} shape."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(message)


def get_account_user_id(request: Request) -> str:
    """Extract authenticated user sub from request state or JWT for rate limiting."""
    if hasattr(request.state, "user_id"):
        return str(request.state.user_id)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            sub = unverified.get("sub")
            if sub:
                return str(sub)
        except Exception:
            pass
    return get_remote_address(request)


def verify_dashboard_token(raw: str) -> dict[str, Any]:
    """Verify a Supabase access token (§5.2).

    Two branches, chosen from the token's unverified ``alg`` header:

    * ``HS256`` — legacy shared-secret path (SUPABASE_JWT_SECRET).
    * ``ES256`` / ``RS256`` / ``EdDSA`` — asymmetric signing keys, verified
      against the project JWKS at ``{SUPABASE_URL}/auth/v1/.well-known/jwks.json``
      (new Supabase projects issue ES256 tokens by default).
    """
    if raw.startswith("am_live_"):
        raise AccountError(
            status.HTTP_401_UNAUTHORIZED,
            "UNAUTHORIZED",
            "API keys cannot be used to authenticate account endpoints. Supabase JWT required.",
        )
    issuer = f"{settings.supabase_url.rstrip('/')}/auth/v1"
    try:
        header = jwt.get_unverified_header(raw)
    except Exception as exc:
        raise AccountError(
            status.HTTP_401_UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid or expired authentication token.",
        ) from exc

    alg = header.get("alg") or ""

    if alg == "HS256":
        if not settings.supabase_jwt_secret:
            raise AccountError(
                status.HTTP_401_UNAUTHORIZED,
                "UNAUTHORIZED",
                "Supabase JWT secret is not configured.",
            )
        try:
            return jwt.decode(
                raw,
                key=settings.supabase_jwt_secret,
                algorithms=["HS256"],
                issuer=issuer,
                options={"require": ["exp", "sub", "iss"]},
            )
        except Exception as exc:
            raise AccountError(
                status.HTTP_401_UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid or expired authentication token.",
            ) from exc

    if alg in ASYM_ALGS:
        kid = header.get("kid") or ""
        try:
            key = get_verification_key(alg, kid)
            return jwt.decode(
                raw,
                key=key,
                algorithms=[alg],
                issuer=issuer,
                options={"require": ["exp", "sub", "iss"]},
            )
        except Exception as exc:
            logger.warning(
                "Asymmetric token verification failed (alg=%s kid=%r): %s",
                alg,
                kid,
                exc,
            )
            raise AccountError(
                status.HTTP_401_UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid or expired authentication token.",
            ) from exc

    raise AccountError(
        status.HTTP_401_UNAUTHORIZED,
        "UNAUTHORIZED",
        f"Unsupported token algorithm {alg!r}.",
    )


async def get_current_user_sub(request: Request) -> str:
    """FastAPI route-guard dependency extracting and verifying the JWT subject (§5.2)."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise AccountError(
            status.HTTP_401_UNAUTHORIZED,
            "UNAUTHORIZED",
            "Missing or malformed Authorization header.",
        )
    raw_token = auth_header.removeprefix("Bearer ").strip()
    if not raw_token:
        raise AccountError(
            status.HTTP_401_UNAUTHORIZED,
            "UNAUTHORIZED",
            "Missing or malformed Authorization header.",
        )
    claims = verify_dashboard_token(raw_token)
    sub = claims.get("sub")
    if not sub:
        raise AccountError(
            status.HTTP_401_UNAUTHORIZED,
            "UNAUTHORIZED",
            "Token missing sub claim.",
        )
    request.state.user_id = str(sub)
    return str(sub)


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------


class ProvisionAgentRequest(BaseModel):
    handle: str


class CreateContactRequest(BaseModel):
    alias: str
    target_handle: str
    note: str | None = None


class PatchContactRequest(BaseModel):
    alias: str | None = None
    target_handle: str | None = None
    note: str | None = None


# ---------------------------------------------------------------------------
# 1. Handle Availability (§6.1)
# ---------------------------------------------------------------------------


@router.get("/handle-available")
@limiter.limit("60/minute", key_func=get_account_user_id)
async def handle_available(
    request: Request,
    handle: str,
    sub: str = Depends(get_current_user_sub),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Live handle availability check — 200 with reason on unavailability."""
    if not _HANDLE_RE.match(handle):
        return {"handle": handle, "available": False, "reason": "invalid"}
    if is_reserved_handle(handle):
        return {"handle": handle, "available": False, "reason": "reserved"}

    # Live or burned handles count as taken
    res = await db.execute(select(Agent.id).where(Agent.handle == handle))
    if res.scalar_one_or_none() is not None:
        return {"handle": handle, "available": False, "reason": "taken"}

    return {"handle": handle, "available": True}


# ---------------------------------------------------------------------------
# 2. Provision Agent (§6.2, §4)
# ---------------------------------------------------------------------------


@router.post("/agents")
@limiter.limit("5/hour", key_func=get_account_user_id)
async def provision_agent(
    request: Request,
    body: ProvisionAgentRequest,
    sub: str = Depends(get_current_user_sub),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Idempotently provision a server-custody agent with a chosen bare handle."""
    # 1. Idempotency: return existing agent if one already belongs to this account
    existing_res = await db.execute(
        select(Agent).where(Agent.owner_user_id == sub, Agent.deleted_at.is_(None))
    )
    existing_agent = existing_res.scalar_one_or_none()
    if existing_agent is not None:
        decrypted_key = (
            decrypt_server_kek(existing_agent.api_key_enc) if existing_agent.api_key_enc else ""
        )
        return {
            "agent": {
                "id": str(existing_agent.id),
                "handle": existing_agent.handle,
                "address": f"{existing_agent.handle}@{settings.relay_domain}",
                "fingerprint": generate_fingerprint(
                    existing_agent.enc_pub, existing_agent.sign_pub
                ),
                "custody_mode": existing_agent.custody_mode,
                "created_at": existing_agent.created_at.isoformat(),
                **(
                    {"display_name": existing_agent.display_name}
                    if existing_agent.display_name
                    else {}
                ),
            },
            "api_key": decrypted_key,
            "existing": True,
        }

    # 2. Handle validation
    raw_handle = body.handle
    if "@" in raw_handle:
        raise AccountError(
            status.HTTP_400_BAD_REQUEST,
            "VALIDATION_ERROR",
            "Handle must be a bare local part without '@'.",
        )
    handle = raw_handle.strip()
    if not _HANDLE_RE.match(handle):
        raise AccountError(
            status.HTTP_400_BAD_REQUEST,
            "VALIDATION_ERROR",
            "Handle must be 3-32 chars, lowercase alphanumeric + hyphens, starting with a letter or digit.",
        )
    if is_reserved_handle(handle):
        raise AccountError(
            status.HTTP_400_BAD_REQUEST,
            "VALIDATION_ERROR",
            f"Handle '{handle}' is reserved.",
        )

    # 3. All-time uniqueness
    taken_res = await db.execute(select(Agent.id).where(Agent.handle == handle))
    if taken_res.scalar_one_or_none() is not None:
        raise AccountError(
            status.HTTP_409_CONFLICT,
            "HANDLE_TAKEN",
            "That agent ID is already in use.",
        )

    # 4. Generate keypairs
    priv_enc = PrivateKey.generate()
    signing_key = SigningKey.generate()
    enc_sk = bytes(priv_enc)
    sign_sk = bytes(signing_key)
    enc_pub = priv_enc.public_key.encode().hex()
    sign_pub = signing_key.verify_key.encode().hex()

    # 5. Generate API key & encrypt
    raw_api_key = generate_api_key()
    api_key_hash = hash_api_key(raw_api_key)
    api_key_enc = encrypt_server_kek(raw_api_key)

    # 6. Build server-custody blob
    blob_json = json.dumps(
        {"epochs": [{"epoch": 1, "enc_sk": enc_sk.hex(), "sign_sk": sign_sk.hex()}]}
    )
    key_blob = encrypt_server_kek(blob_json)

    # 7. Insert agent
    agent_id = str(uuid_utils.uuid7())
    agent = Agent(
        id=agent_id,
        handle=handle,
        owner_user_id=sub,
        custody_mode="server_kek",
        api_key_hash=api_key_hash,
        api_key_enc=api_key_enc,
        enc_pub=enc_pub,
        sign_pub=sign_pub,
        key_blob=key_blob,
        key_epoch=1,
        kdf_params={"algo": "server_kek"},
    )
    db.add(agent)
    db.add(
        AuditLog(
            agent_id=agent_id,
            event="account_agent_provisioned",
            ip=request.client.host if request.client else None,
        )
    )

    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        # Check if raced user already got one
        recheck = await db.execute(
            select(Agent).where(Agent.owner_user_id == sub, Agent.deleted_at.is_(None))
        )
        raced_agent = recheck.scalar_one_or_none()
        if raced_agent is not None:
            decrypted = (
                decrypt_server_kek(raced_agent.api_key_enc) if raced_agent.api_key_enc else ""
            )
            return {
                "agent": {
                    "id": str(raced_agent.id),
                    "handle": raced_agent.handle,
                    "address": f"{raced_agent.handle}@{settings.relay_domain}",
                    "fingerprint": generate_fingerprint(raced_agent.enc_pub, raced_agent.sign_pub),
                    "custody_mode": raced_agent.custody_mode,
                    "created_at": raced_agent.created_at.isoformat(),
                },
                "api_key": decrypted,
                "existing": True,
            }
        raise AccountError(
            status.HTTP_409_CONFLICT,
            "HANDLE_TAKEN",
            "That agent ID is already in use.",
        ) from exc

    await db.refresh(agent)
    return {
        "agent": {
            "id": str(agent.id),
            "handle": agent.handle,
            "address": f"{agent.handle}@{settings.relay_domain}",
            "fingerprint": generate_fingerprint(agent.enc_pub, agent.sign_pub),
            "custody_mode": agent.custody_mode,
            "created_at": agent.created_at.isoformat(),
        },
        "api_key": raw_api_key,
        "existing": False,
    }


# ---------------------------------------------------------------------------
# 3. List Agents (§6.3)
# ---------------------------------------------------------------------------


@router.get("/agents")
@limiter.limit("60/minute", key_func=get_account_user_id)
async def list_agents(
    request: Request,
    sub: str = Depends(get_current_user_sub),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """List all agents belonging to the authenticated account."""
    result = await db.execute(
        select(Agent)
        .where(Agent.owner_user_id == sub, Agent.deleted_at.is_(None))
        .order_by(Agent.created_at.asc())
    )
    agents = result.scalars().all()
    return {
        "agents": [
            {
                "id": str(a.id),
                "handle": a.handle,
                "address": f"{a.handle}@{settings.relay_domain}",
                "fingerprint": generate_fingerprint(a.enc_pub, a.sign_pub),
                "custody_mode": a.custody_mode,
                "created_at": a.created_at.isoformat(),
                **({"display_name": a.display_name} if a.display_name else {}),
            }
            for a in agents
        ]
    }


# ---------------------------------------------------------------------------
# 4. Reveal API Key (§6.4)
# ---------------------------------------------------------------------------


@router.get("/agents/{agent_id}/api-key")
@limiter.limit("10/hour", key_func=get_account_user_id)
async def reveal_api_key(
    request: Request,
    agent_id: str,
    sub: str = Depends(get_current_user_sub),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Audited reveal of the encrypted API key."""
    result = await db.execute(
        select(Agent).where(
            Agent.id == agent_id,
            Agent.owner_user_id == sub,
            Agent.deleted_at.is_(None),
        )
    )
    agent = result.scalar_one_or_none()
    if agent is None or not agent.api_key_enc:
        raise AccountError(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Agent not found.")

    try:
        raw_key = decrypt_server_kek(agent.api_key_enc)
    except Exception as exc:
        raise AccountError(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "CRYPTO_ERROR",
            "Failed to decrypt API key.",
        ) from exc

    db.add(
        AuditLog(
            agent_id=agent.id,
            event="api_key_revealed",
            ip=request.client.host if request.client else None,
        )
    )
    await db.commit()

    return {"api_key": raw_key}


# ---------------------------------------------------------------------------
# 5. Rotate API Key (§6.5)
# ---------------------------------------------------------------------------


@router.post("/agents/{agent_id}/api-key/rotate")
@limiter.limit("5/hour", key_func=get_account_user_id)
async def rotate_api_key(
    request: Request,
    agent_id: str,
    sub: str = Depends(get_current_user_sub),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate and store a new API key for the agent, invalidating the old one."""
    result = await db.execute(
        select(Agent).where(
            Agent.id == agent_id,
            Agent.owner_user_id == sub,
            Agent.deleted_at.is_(None),
        )
    )
    agent = result.scalar_one_or_none()
    if agent is None:
        raise AccountError(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Agent not found.")

    new_key = generate_api_key()
    agent.api_key_hash = hash_api_key(new_key)
    agent.api_key_enc = encrypt_server_kek(new_key)

    db.add(
        AuditLog(
            agent_id=agent.id,
            event="api_key_rotated",
            ip=request.client.host if request.client else None,
        )
    )
    await db.commit()

    return {"api_key": new_key}


# ---------------------------------------------------------------------------
# 6. Contacts CRUD (§6.7)
# ---------------------------------------------------------------------------


@router.get("/contacts")
@limiter.limit("60/minute", key_func=get_account_user_id)
async def list_contacts(
    request: Request,
    sub: str = Depends(get_current_user_sub),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """List all contact aliases owned by the calling user."""
    result = await db.execute(
        select(UserContact)
        .where(UserContact.owner_user_id == sub)
        .order_by(UserContact.alias.asc())
        .limit(100)
    )
    contacts = result.scalars().all()
    return {
        "contacts": [
            {
                "id": str(c.id),
                "alias": c.alias,
                "target_handle": c.target_handle,
                "address": f"{c.target_handle}@{settings.relay_domain}",
                "note": c.note,
                "created_at": c.created_at.isoformat(),
                "updated_at": c.updated_at.isoformat(),
            }
            for c in contacts
        ]
    }


@router.post("/contacts", status_code=status.HTTP_201_CREATED)
@limiter.limit("60/minute", key_func=get_account_user_id)
async def create_contact(
    request: Request,
    body: CreateContactRequest,
    sub: str = Depends(get_current_user_sub),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Create a new contact alias."""
    # Cap check: 100 contacts per account
    count_res = await db.execute(
        select(func.count()).select_from(UserContact).where(UserContact.owner_user_id == sub)
    )
    if count_res.scalar_one() >= 100:
        raise AccountError(
            status.HTTP_400_BAD_REQUEST,
            "VALIDATION_ERROR",
            "Contact list is at maximum capacity (100 contacts).",
        )

    # Check '@'
    if "@" in body.alias or "@" in body.target_handle:
        raise AccountError(
            status.HTTP_400_BAD_REQUEST,
            "VALIDATION_ERROR",
            "Alias and target handle must be bare local parts without '@'.",
        )

    # Validate alias
    alias = body.alias.strip()
    if not _ALIAS_RE.match(alias):
        raise AccountError(
            status.HTTP_400_BAD_REQUEST,
            "VALIDATION_ERROR",
            "Alias must be 2-32 chars (lowercase letters, digits, hyphen, underscore, starting alphanumeric).",
        )

    # Validate target handle
    target_handle = body.target_handle.strip()
    if not _TARGET_HANDLE_RE.match(target_handle):
        raise AccountError(
            status.HTTP_400_BAD_REQUEST,
            "VALIDATION_ERROR",
            "Target handle must be 3-32 chars (lowercase letters, digits, hyphen, starting alphanumeric).",
        )
    if is_reserved_handle(target_handle):
        raise AccountError(
            status.HTTP_400_BAD_REQUEST,
            "VALIDATION_ERROR",
            f"Target handle '{target_handle}' is reserved.",
        )

    # Validate note
    note = body.note.strip() if body.note else None
    if note is not None:
        if len(note) > 200:
            raise AccountError(
                status.HTTP_400_BAD_REQUEST,
                "VALIDATION_ERROR",
                "Note must be ≤ 200 characters.",
            )
        if note == "":
            note = None

    # Duplicate alias check for this user
    exists = await db.execute(
        select(UserContact.id).where(UserContact.owner_user_id == sub, UserContact.alias == alias)
    )
    if exists.scalar_one_or_none() is not None:
        raise AccountError(
            status.HTTP_409_CONFLICT,
            "ALIAS_EXISTS",
            f"You already have a contact named '{alias}'.",
        )

    now = datetime.datetime.now(datetime.UTC)
    contact = UserContact(
        id=str(uuid_utils.uuid7()),
        owner_user_id=sub,
        alias=alias,
        target_handle=target_handle,
        note=note,
        created_at=now,
        updated_at=now,
    )
    db.add(contact)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise AccountError(
            status.HTTP_409_CONFLICT,
            "ALIAS_EXISTS",
            f"You already have a contact named '{alias}'.",
        ) from exc

    await db.refresh(contact)
    return {
        "contact": {
            "id": str(contact.id),
            "alias": contact.alias,
            "target_handle": contact.target_handle,
            "address": f"{contact.target_handle}@{settings.relay_domain}",
            "note": contact.note,
            "created_at": contact.created_at.isoformat(),
            "updated_at": contact.updated_at.isoformat(),
        }
    }


@router.patch("/contacts/{contact_id}")
@limiter.limit("60/minute", key_func=get_account_user_id)
async def update_contact(
    request: Request,
    contact_id: str,
    body: PatchContactRequest,
    sub: str = Depends(get_current_user_sub),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Partially update an existing contact alias."""
    result = await db.execute(
        select(UserContact).where(UserContact.id == contact_id, UserContact.owner_user_id == sub)
    )
    contact = result.scalar_one_or_none()
    if contact is None:
        raise AccountError(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Contact not found.")

    payload_dict = body.model_dump(exclude_unset=True)

    if "alias" in payload_dict and body.alias is not None:
        if "@" in body.alias:
            raise AccountError(
                status.HTTP_400_BAD_REQUEST,
                "VALIDATION_ERROR",
                "Alias must not contain '@'.",
            )
        alias = body.alias.strip()
        if not _ALIAS_RE.match(alias):
            raise AccountError(
                status.HTTP_400_BAD_REQUEST,
                "VALIDATION_ERROR",
                "Alias must be 2-32 chars (lowercase letters, digits, hyphen, underscore, starting alphanumeric).",
            )
        if alias != contact.alias:
            exists = await db.execute(
                select(UserContact.id).where(
                    UserContact.owner_user_id == sub,
                    UserContact.alias == alias,
                    UserContact.id != contact_id,
                )
            )
            if exists.scalar_one_or_none() is not None:
                raise AccountError(
                    status.HTTP_409_CONFLICT,
                    "ALIAS_EXISTS",
                    f"You already have a contact named '{alias}'.",
                )
            contact.alias = alias

    if "target_handle" in payload_dict and body.target_handle is not None:
        if "@" in body.target_handle:
            raise AccountError(
                status.HTTP_400_BAD_REQUEST,
                "VALIDATION_ERROR",
                "Target handle must not contain '@'.",
            )
        target_handle = body.target_handle.strip()
        if not _TARGET_HANDLE_RE.match(target_handle):
            raise AccountError(
                status.HTTP_400_BAD_REQUEST,
                "VALIDATION_ERROR",
                "Target handle must be 3-32 chars (lowercase letters, digits, hyphen, starting alphanumeric).",
            )
        if is_reserved_handle(target_handle):
            raise AccountError(
                status.HTTP_400_BAD_REQUEST,
                "VALIDATION_ERROR",
                f"Target handle '{target_handle}' is reserved.",
            )
        contact.target_handle = target_handle

    if "note" in payload_dict:
        if body.note is not None:
            note = body.note.strip()
            if len(note) > 200:
                raise AccountError(
                    status.HTTP_400_BAD_REQUEST,
                    "VALIDATION_ERROR",
                    "Note must be ≤ 200 characters.",
                )
            contact.note = note if note != "" else None
        else:
            contact.note = None

    contact.updated_at = datetime.datetime.now(datetime.UTC)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise AccountError(
            status.HTTP_409_CONFLICT,
            "ALIAS_EXISTS",
            "A contact with that alias already exists.",
        ) from exc

    await db.refresh(contact)
    return {
        "contact": {
            "id": str(contact.id),
            "alias": contact.alias,
            "target_handle": contact.target_handle,
            "address": f"{contact.target_handle}@{settings.relay_domain}",
            "note": contact.note,
            "created_at": contact.created_at.isoformat(),
            "updated_at": contact.updated_at.isoformat(),
        }
    }


@router.delete("/contacts/{contact_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("60/minute", key_func=get_account_user_id)
async def delete_contact(
    request: Request,
    contact_id: str,
    sub: str = Depends(get_current_user_sub),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a contact alias."""
    result = await db.execute(
        select(UserContact).where(UserContact.id == contact_id, UserContact.owner_user_id == sub)
    )
    contact = result.scalar_one_or_none()
    if contact is None:
        raise AccountError(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Contact not found.")

    await db.delete(contact)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
