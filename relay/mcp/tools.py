"""MCP tool implementations — all 10 tools from §7.3.

Every function takes ``(db, agent, ...)`` and returns the JSON-able dict
that becomes the tool's single text block (``{result|error, _inbox?}``).
Auth, rate limits, auto-unlock, and the piggyback footer are orchestrated
one level up in :mod:`relay.mcp.server`; these functions are pure
database + crypto logic so they are directly unit-testable.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import uuid
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from uuid_utils import uuid7

from relay.config import settings
from relay.crypto.envelope import (
    decrypt_server_kek_blob,
    generate_fingerprint,
    open_message,
    seal_message,
    sign_ciphertext,
    verify_signature,
)
from relay.crypto.vault import VaultEntry, vault
from relay.mcp.contacts import find_contact_alias, load_alias_map
from relay.models.schema import Agent, AuditLog, Message

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def now_utc() -> datetime.datetime:
    """Timezone-aware current time."""
    return datetime.datetime.now(datetime.UTC)


def error_response(code: str, message: str, retry_after: int | None = None) -> dict[str, Any]:
    """Build a uniform error response per §5.7."""
    return {
        "error": {
            "code": code,
            "message": message,
            "retry_after": retry_after,
        }
    }


def keychain_locked_response() -> dict[str, Any]:
    """The canonical KEYCHAIN_LOCKED result the model can self-correct from."""
    return error_response(
        "KEYCHAIN_LOCKED",
        "Keychain is locked — ask the user for their keychain passphrase, "
        "call unlock_keychain, then retry.",
    )


def _parse_timestamp(value: str) -> datetime.datetime | None:
    """Parse an RFC 3339 / ISO 8601 string into an aware UTC datetime."""
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    return parsed


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return True


def _address(handle: str) -> str:
    return f"{handle}@{settings.relay_domain}"


def _canonical_recipient(to: str) -> str:
    """Normalize ``alice`` / ``alice@agentmail`` → ``alice``."""
    return to.strip().lower().split("@", 1)[0]


# ---------------------------------------------------------------------------
# Key derivation (shared by unlock_keychain and transparent auto-unlock)
# ---------------------------------------------------------------------------


def derive_private_keys(agent: Agent, passphrase: str) -> tuple[bytes, bytes] | None:
    """Run Argon2id + SecretBox over the stored blob.

    Returns ``(enc_sk_bytes, sign_sk_bytes)`` for the newest epoch, or
    ``None`` when the passphrase is wrong or the blob is corrupted.
    Blocking (Argon2id) — call via :func:`asyncio.to_thread`.
    """
    import nacl.pwhash
    import nacl.secret

    try:
        kdf = agent.kdf_params
        salt = base64.b64decode(kdf["salt_b64"])
        ops_limit = int(kdf.get("t", 3))
        mem_limit = int(kdf.get("m", 65536)) * 1024  # KiB → bytes

        derived = nacl.pwhash.argon2id.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            salt,
            opslimit=ops_limit,
            memlimit=mem_limit,
        )

        box = nacl.secret.SecretBox(derived)
        blob_plaintext = box.decrypt(base64.b64decode(agent.key_blob))
        blob = json.loads(blob_plaintext.decode("utf-8"))

        current = blob["epochs"][-1]
        return bytes.fromhex(current["enc_sk"]), bytes.fromhex(current["sign_sk"])
    except Exception:  # noqa: BLE001 — any failure reads as "wrong passphrase"
        return None


async def store_keys_in_vault(agent: Agent, enc_sk: bytes, sign_sk: bytes) -> None:
    await vault.unlock(
        agent.id,
        enc_sk=enc_sk,
        sign_sk=sign_sk,
        enc_pub=bytes.fromhex(agent.enc_pub),
        sign_pub=bytes.fromhex(agent.sign_pub),
    )


async def get_or_unlock_vault_entry(agent: Agent) -> VaultEntry | None:
    """Return vault entry, auto-unlocking server_kek custody agents on demand (§4)."""
    entry = await vault.get(agent.id)
    if entry is not None:
        return entry
    if getattr(agent, "custody_mode", "user_passphrase") == "server_kek":
        keys = decrypt_server_kek_blob(agent.key_blob)
        if keys is not None:
            enc_sk, sign_sk = keys
            await store_keys_in_vault(agent, enc_sk, sign_sk)
            return await vault.get(agent.id)
    return None


# ---------------------------------------------------------------------------
# Tool 1: unlock_keychain
# ---------------------------------------------------------------------------


async def unlock_keychain(db: AsyncSession, agent: Agent, passphrase: str) -> dict[str, Any]:
    """Decrypt the key blob into the in-memory vault (§4.2)."""
    if getattr(agent, "custody_mode", "user_passphrase") == "server_kek":
        await get_or_unlock_vault_entry(agent)
        return {
            "result": {
                "unlocked": True,
                "note": "This agent uses server-side key custody; no passphrase is required.",
            }
        }

    keys = await asyncio.to_thread(derive_private_keys, agent, passphrase)
    if keys is None:
        db.add(AuditLog(agent_id=agent.id, event="unlock_fail"))
        return error_response("BAD_PASSPHRASE", "Passphrase incorrect or key blob corrupted.")

    enc_sk, sign_sk = keys
    await store_keys_in_vault(agent, enc_sk, sign_sk)
    db.add(AuditLog(agent_id=agent.id, event="unlock"))

    auto_lock = await vault.auto_lock_at(agent.id)
    return {
        "result": {
            "agent": _address(agent.handle),
            "unlocked": True,
            "auto_lock_at": auto_lock.isoformat() if auto_lock else None,
        }
    }


# ---------------------------------------------------------------------------
# Tool 2: keychain_status
# ---------------------------------------------------------------------------


async def keychain_status(db: AsyncSession, agent: Agent) -> dict[str, Any]:
    """Let the model self-check before crypto operations."""
    if getattr(agent, "custody_mode", "user_passphrase") == "server_kek":
        await get_or_unlock_vault_entry(agent)
    unlocked = await vault.is_unlocked(agent.id)
    auto_lock = await vault.auto_lock_at(agent.id) if unlocked else None
    return {
        "result": {
            "locked": not unlocked,
            "auto_lock_at": auto_lock.isoformat() if auto_lock else None,
        }
    }


# ---------------------------------------------------------------------------
# Tool 3: whois
# ---------------------------------------------------------------------------


async def whois(db: AsyncSession, agent: Agent, handle: str) -> dict[str, Any]:
    """Public directory lookup — verify before first contact (§4.4)."""
    result = await db.execute(
        select(Agent).where(
            Agent.handle == _canonical_recipient(handle),
            Agent.deleted_at.is_(None),
        )
    )
    target = result.scalar_one_or_none()
    if target is None:
        return error_response(
            "AGENT_NOT_FOUND",
            f"No live agent with handle '{handle}' — double-check the address.",
        )

    return {
        "result": {
            "handle": target.handle,
            "address": _address(target.handle),
            "display_name": target.display_name,
            "fingerprint": generate_fingerprint(target.enc_pub, target.sign_pub),
            "enc_pub": target.enc_pub,
            "sign_pub": target.sign_pub,
            "created_at": target.created_at.isoformat() if target.created_at else None,
        }
    }


# ---------------------------------------------------------------------------
# Tool 4: send_message
# ---------------------------------------------------------------------------


async def _resolve_visible_message(
    db: AsyncSession, agent: Agent, message_id: str
) -> Message | None:
    """Fetch a message the caller is party to (sender-side view survives
    the recipient's soft delete; the recipient cannot fetch deleted rows)."""
    if not _is_uuid(message_id):
        return None
    result = await db.execute(select(Message).where(Message.id == message_id))
    msg = result.scalar_one_or_none()
    if msg is None:
        return None
    if agent.id == msg.sender_id:
        return msg
    if agent.id == msg.recipient_id and msg.deleted_at is None:
        return msg
    return None


async def send_message(
    db: AsyncSession,
    agent: Agent,
    to: str,
    subject: str,
    body: str,
    thread_id: str | None = None,
    in_reply_to: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    """Seal + sign + store a message (§3.3)."""
    entry = await get_or_unlock_vault_entry(agent)
    if entry is None:
        return keychain_locked_response()

    # -- validation (§5.8) -------------------------------------------------
    if not to or not to.strip():
        return error_response("VALIDATION_ERROR", "'to' must be a handle or address.")
    if subject is not None and len(subject) > 200:
        return error_response("VALIDATION_ERROR", "Subject must be ≤ 200 characters.")
    body_bytes = body.encode("utf-8")
    if len(body_bytes) > 64_000:
        return error_response(
            "MESSAGE_TOO_LARGE",
            "Body must be ≤ 64,000 bytes UTF-8 — shorten it or link to the content.",
        )
    if b"\x00" in body_bytes:
        return error_response("VALIDATION_ERROR", "Body must not contain NUL bytes.")

    # -- resolve recipient & contact alias (ALIAS-01) ------------------------
    effective_to, resolved_alias = await find_contact_alias(db, agent.owner_user_id, to)
    recipient_handle = _canonical_recipient(effective_to)
    result = await db.execute(
        select(Agent).where(Agent.handle == recipient_handle, Agent.deleted_at.is_(None))
    )
    recipient = result.scalar_one_or_none()
    if recipient is None:
        if resolved_alias is not None:
            return error_response(
                "AGENT_NOT_FOUND",
                f"Your contact '{resolved_alias}' points to {recipient_handle}@{settings.relay_domain}, "
                "which is not a registered agent.",
            )
        return error_response(
            "AGENT_NOT_FOUND",
            f"No live agent with address '{to}' — use whois to verify the handle.",
        )

    # -- idempotent replay ----------------------------------------------------
    if idempotency_key:
        existing_result = await db.execute(
            select(Message).where(
                Message.sender_id == agent.id,
                Message.idempotency_key == idempotency_key,
            )
        )
        existing = existing_result.scalar_one_or_none()
        if existing is not None:
            res_item = {
                "id": existing.id,
                "thread_id": existing.thread_id,
                "from": _address(agent.handle),
                "to": _address(recipient.handle),
                "sent_at": existing.created_at.isoformat() if existing.created_at else None,
                "status": "stored",
                "idempotent_replay": True,
            }
            if resolved_alias is not None:
                res_item["resolved_alias"] = resolved_alias
            return {"result": res_item}

    # -- thread resolution (§5.6) ---------------------------------------------
    now = now_utc()
    resolved_thread_id: str | None = thread_id

    if in_reply_to is not None:
        parent = await _resolve_visible_message(db, agent, in_reply_to)
        if parent is None:
            return error_response("NOT_FOUND", f"Message '{in_reply_to}' not found.")
        if thread_id is not None and thread_id != parent.thread_id:
            return error_response(
                "VALIDATION_ERROR",
                "thread_id does not match the thread of in_reply_to.",
            )
        resolved_thread_id = parent.thread_id
    elif resolved_thread_id is not None:
        if not _is_uuid(resolved_thread_id):
            return error_response("VALIDATION_ERROR", "thread_id must be a UUID.")
        # Caller must participate in the thread (anti thread-injection).
        check = await db.execute(
            select(Message.id)
            .where(
                Message.thread_id == resolved_thread_id,
                or_(
                    Message.sender_id == agent.id,
                    Message.recipient_id == agent.id,
                ),
            )
            .limit(1)
        )
        if check.scalar_one_or_none() is None:
            return error_response(
                "VALIDATION_ERROR", "Cannot send to a thread you are not party to."
            )

    # -- payload + crypto (layer 3) --------------------------------------------
    sent_at = now.isoformat()
    payload = {
        "subject": subject or "",
        "body": body,
        "in_reply_to": in_reply_to,
        "sent_at": sent_at,
        "from": _address(agent.handle),
        "headers": {},
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    if len(payload_json.encode("utf-8")) > 68_000:
        return error_response("MESSAGE_TOO_LARGE", "Total payload exceeds the 68 KB limit.")

    ciphertext_b64 = await asyncio.to_thread(seal_message, payload_json, recipient.enc_pub)
    ciphertext_bytes = base64.b64decode(ciphertext_b64)
    sig_b64 = await asyncio.to_thread(sign_ciphertext, ciphertext_bytes, bytes(entry.sign_sk))

    # -- quota (§6.4) -----------------------------------------------------------
    size_bytes = len(ciphertext_b64)
    quota_result = await db.execute(
        select(func.coalesce(func.sum(Message.size_bytes), 0)).where(
            Message.recipient_id == recipient.id,
            Message.deleted_at.is_(None),
            Message.expires_at > now,
        )
    )
    current_usage = int(quota_result.scalar_one())
    if current_usage + size_bytes > recipient.quota_bytes:
        return error_response(
            "MAILBOX_FULL",
            f"Recipient's mailbox ({recipient.quota_bytes // (1024 * 1024)} MiB) "
            "is full — message not stored. Retry after they read or delete mail.",
        )

    # -- insert -------------------------------------------------------------------
    msg_id = str(uuid7())
    if resolved_thread_id is None:
        resolved_thread_id = msg_id  # root-anchored thread id (§5.6)

    expires_at = now + datetime.timedelta(days=settings.unread_ttl_days)
    db.add(
        Message(
            id=msg_id,
            thread_id=resolved_thread_id,
            sender_id=agent.id,
            recipient_id=recipient.id,
            ciphertext=ciphertext_b64,
            sig=sig_b64,
            key_epoch=recipient.key_epoch,
            size_bytes=size_bytes,
            idempotency_key=idempotency_key,
            created_at=now,
            expires_at=expires_at,
        )
    )

    res_result = {
        "id": msg_id,
        "thread_id": resolved_thread_id,
        "from": _address(agent.handle),
        "to": _address(recipient.handle),
        "sent_at": sent_at,
        "status": "stored",
        "idempotent_replay": False,
    }
    if resolved_alias is not None:
        res_result["resolved_alias"] = resolved_alias

    return {"result": res_result}


# ---------------------------------------------------------------------------
# Tool 5: check_inbox
# ---------------------------------------------------------------------------


async def check_inbox(
    db: AsyncSession,
    agent: Agent,
    unread_only: bool = True,
    limit: int = 20,
    before: str | None = None,
) -> dict[str, Any]:
    """Page the live mailbox; subjects only when the vault is unlocked."""
    now = now_utc()
    limit = max(1, min(int(limit), 50))  # §5.8 page cap

    before_dt: datetime.datetime | None = None
    if before:
        before_dt = _parse_timestamp(before)
        if before_dt is None:
            return error_response("VALIDATION_ERROR", "'before' must be an RFC 3339 timestamp.")

    query = (
        select(Message)
        .where(
            Message.recipient_id == agent.id,
            Message.deleted_at.is_(None),
            Message.expires_at > now,
        )
        .order_by(Message.created_at.desc())
        .limit(limit + 1)  # one extra row → has_more
    )
    if unread_only:
        query = query.where(Message.read_at.is_(None))
    if before_dt is not None:
        query = query.where(Message.created_at < before_dt)

    result = await db.execute(query)
    rows = list(result.scalars().all())
    has_more = len(rows) > limit
    rows = rows[:limit]

    sender_map = await _handle_map(db, {row.sender_id for row in rows})
    entry = await get_or_unlock_vault_entry(agent)
    unlocked = entry is not None
    alias_map = await load_alias_map(db, agent.owner_user_id)

    messages: list[dict[str, Any]] = []
    for msg in rows:
        sender_addr = sender_map.get(msg.sender_id, "unknown")
        item: dict[str, Any] = {
            "id": msg.id,
            "from": sender_addr,
            "thread_id": msg.thread_id,
            "received_at": msg.created_at.isoformat() if msg.created_at else None,
            "read": msg.read_at is not None,
        }
        if sender_addr in alias_map:
            item["from_alias"] = alias_map[sender_addr]
        if unlocked and entry is not None:
            subject = _decrypt_subject(msg.ciphertext, bytes(entry.enc_sk))
            if subject is not None:
                item["subject"] = subject
        messages.append(item)

    response: dict[str, Any] = {
        "result": {
            "messages": messages,
            "has_more": has_more,
            "keychain": "unlocked" if unlocked else "locked",
        }
    }
    if not unlocked:
        response["result"]["note"] = "Subjects hidden — call unlock_keychain to reveal them."
    return response


# ---------------------------------------------------------------------------
# Tool 6: read_message
# ---------------------------------------------------------------------------


async def read_message(db: AsyncSession, agent: Agent, message_id: str) -> dict[str, Any]:
    """Verify signature + decrypt + mark read (§3.4)."""
    entry = await get_or_unlock_vault_entry(agent)
    if entry is None:
        return keychain_locked_response()

    msg = await _resolve_visible_message(db, agent, message_id)
    if msg is None:
        return error_response("NOT_FOUND", f"Message '{message_id}' not found.")

    sender_result = await db.execute(select(Agent).where(Agent.id == msg.sender_id))
    sender = sender_result.scalar_one_or_none()

    ciphertext_bytes = base64.b64decode(msg.ciphertext)
    signature_valid = (
        verify_signature(ciphertext_bytes, msg.sig, sender.sign_pub)
        if sender is not None
        else False
    )

    try:
        payload = json.loads(open_message(msg.ciphertext, bytes(entry.enc_sk)))
    except Exception:  # noqa: BLE001
        # A sent copy is sealed to the recipient — the sender can verify the
        # signature and see metadata, but the body is (by design) unreadable.
        if agent.id == msg.sender_id and agent.id != msg.recipient_id:
            return await _sent_copy_response(db, msg)
        return error_response(
            "UNAVAILABLE", "Failed to decrypt message — key mismatch or corrupted ciphertext."
        )

    # Read receipt: set exactly once, only when the recipient reads (§6.4).
    if agent.id == msg.recipient_id and msg.read_at is None:
        msg.read_at = now_utc()

    recipient_result = await db.execute(select(Agent.handle).where(Agent.id == msg.recipient_id))
    recipient_handle = recipient_result.scalar_one_or_none()

    sender_addr = _address(sender.handle) if sender else "unknown"
    alias_map = await load_alias_map(db, agent.owner_user_id)

    result_payload: dict[str, Any] = {
        "id": msg.id,
        "thread_id": msg.thread_id,
        "from": sender_addr,
        "to": _address(recipient_handle) if recipient_handle else "unknown",
        "subject": payload.get("subject"),
        "body": payload.get("body"),
        "in_reply_to": payload.get("in_reply_to"),
        "sent_at": payload.get("sent_at"),
        "received_at": msg.created_at.isoformat() if msg.created_at else None,
        "headers": payload.get("headers", {}),
        "read": msg.read_at is not None,
        "signature_valid": signature_valid,
    }
    if sender_addr in alias_map:
        result_payload["from_alias"] = alias_map[sender_addr]

    return {"result": result_payload}


async def _sent_copy_response(db: AsyncSession, msg: Message) -> dict[str, Any]:
    """Metadata-only view of your own sent message (body sealed to recipient)."""
    sender_result = await db.execute(select(Agent).where(Agent.id == msg.sender_id))
    sender = sender_result.scalar_one_or_none()
    recipient_result = await db.execute(select(Agent.handle).where(Agent.id == msg.recipient_id))
    recipient_handle = recipient_result.scalar_one_or_none()

    signature_valid = (
        verify_signature(base64.b64decode(msg.ciphertext), msg.sig, sender.sign_pub)
        if sender is not None
        else False
    )

    return {
        "result": {
            "id": msg.id,
            "thread_id": msg.thread_id,
            "from": _address(sender.handle) if sender else "unknown",
            "to": _address(recipient_handle) if recipient_handle else "unknown",
            "received_at": msg.created_at.isoformat() if msg.created_at else None,
            "read": msg.read_at is not None,
            "signature_valid": signature_valid,
            "note": (
                "This is your sent copy — the body is sealed to the recipient "
                "and cannot be re-read. Use get_sent for delivery status."
            ),
        }
    }


# ---------------------------------------------------------------------------
# Tool 7: reply
# ---------------------------------------------------------------------------


async def reply(
    db: AsyncSession,
    agent: Agent,
    message_id: str,
    body: str,
    subject: str | None = None,
) -> dict[str, Any]:
    """In-thread reply — sugar over send_message (§5.6)."""
    entry = await get_or_unlock_vault_entry(agent)
    if entry is None:
        return keychain_locked_response()

    original = await _resolve_visible_message(db, agent, message_id)
    if original is None:
        return error_response("NOT_FOUND", f"Message '{message_id}' not found.")

    # The reply goes to the other party.
    target_id = original.recipient_id if agent.id == original.sender_id else original.sender_id

    target_result = await db.execute(select(Agent).where(Agent.id == target_id))
    target = target_result.scalar_one_or_none()
    if target is None or target.deleted_at is not None:
        return error_response("AGENT_NOT_FOUND", "Reply target is no longer reachable.")

    if subject is None:
        original_subject = _decrypt_subject(original.ciphertext, bytes(entry.enc_sk)) or ""
        subject = (
            original_subject if original_subject.startswith("Re: ") else f"Re: {original_subject}"
        )

    return await send_message(
        db,
        agent,
        to=target.handle,
        subject=subject,
        body=body,
        in_reply_to=message_id,
    )


# ---------------------------------------------------------------------------
# Tool 8: get_thread
# ---------------------------------------------------------------------------


async def get_thread(
    db: AsyncSession, agent: Agent, thread_id: str, limit: int = 50
) -> dict[str, Any]:
    """Ascending thread dump — per-message visibility (§5.6)."""
    if not _is_uuid(thread_id):
        return error_response("NOT_FOUND", f"Thread '{thread_id}' not found or not visible to you.")

    limit = max(1, min(int(limit), 50))
    now = now_utc()

    result = await db.execute(
        select(Message)
        .where(
            Message.thread_id == thread_id,
            or_(Message.sender_id == agent.id, Message.recipient_id == agent.id),
            # A row the *recipient* soft-deleted stays visible to its sender.
            or_(Message.deleted_at.is_(None), Message.sender_id == agent.id),
            Message.expires_at > now,
        )
        .order_by(Message.created_at.asc())
        .limit(limit)
    )
    rows = list(result.scalars().all())
    if not rows:
        return error_response("NOT_FOUND", f"Thread '{thread_id}' not found or not visible to you.")

    agent_ids: set[str] = set()
    for row in rows:
        agent_ids.add(row.sender_id)
        agent_ids.add(row.recipient_id)
    agent_map = await _handle_map(db, agent_ids)

    entry = await get_or_unlock_vault_entry(agent)
    unlocked = entry is not None

    messages: list[dict[str, Any]] = []
    for msg in rows:
        item: dict[str, Any] = {
            "id": msg.id,
            "from": agent_map.get(msg.sender_id, "unknown"),
            "to": agent_map.get(msg.recipient_id, "unknown"),
            "received_at": msg.created_at.isoformat() if msg.created_at else None,
            "read": msg.read_at is not None,
        }
        if unlocked and entry is not None:
            try:
                payload = json.loads(open_message(msg.ciphertext, bytes(entry.enc_sk)))
                item["subject"] = payload.get("subject")
                item["body"] = payload.get("body")
                item["sent_at"] = payload.get("sent_at")
                item["headers"] = payload.get("headers", {})
            except Exception:  # noqa: BLE001 — degraded metadata row
                pass
        messages.append(item)

    response: dict[str, Any] = {
        "result": {
            "thread_id": thread_id,
            "messages": messages,
            "keychain": "unlocked" if unlocked else "locked",
        }
    }
    if not unlocked:
        response["result"]["note"] = "Bodies hidden — call unlock_keychain to reveal them."
    return response


# ---------------------------------------------------------------------------
# Tool 9: get_sent
# ---------------------------------------------------------------------------


async def get_sent(db: AsyncSession, agent: Agent, limit: int = 20) -> dict[str, Any]:
    """Sender's outbox view with read receipts — no vault needed."""
    limit = max(1, min(int(limit), 50))

    result = await db.execute(
        select(Message)
        .where(Message.sender_id == agent.id)
        .order_by(Message.created_at.desc())
        .limit(limit)
    )
    rows = list(result.scalars().all())
    recipient_map = await _handle_map(db, {row.recipient_id for row in rows})

    messages = [
        {
            "id": msg.id,
            "thread_id": msg.thread_id,
            "to": recipient_map.get(msg.recipient_id, "unknown"),
            "sent_at": msg.created_at.isoformat() if msg.created_at else None,
            "read_at": msg.read_at.isoformat() if msg.read_at else None,
            "status": "read" if msg.read_at else "delivered",
        }
        for msg in rows
    ]
    return {"result": {"messages": messages}}


# ---------------------------------------------------------------------------
# Tool 10: delete_message
# ---------------------------------------------------------------------------


async def delete_message(db: AsyncSession, agent: Agent, message_id: str) -> dict[str, Any]:
    """Recipient soft-delete (§6.4)."""
    if not _is_uuid(message_id):
        return error_response("NOT_FOUND", f"Message '{message_id}' not found.")

    result = await db.execute(select(Message).where(Message.id == message_id))
    msg = result.scalar_one_or_none()
    if msg is None or msg.recipient_id != agent.id:
        return error_response("NOT_FOUND", f"Message '{message_id}' not found.")

    if msg.deleted_at is not None:
        return {"result": {"deleted": True, "already_deleted": True}}

    await db.execute(update(Message).where(Message.id == message_id).values(deleted_at=now_utc()))
    return {"result": {"deleted": True}}


# ---------------------------------------------------------------------------
# Shared lookups
# ---------------------------------------------------------------------------


async def _handle_map(db: AsyncSession, agent_ids: set[str]) -> dict[str, str]:
    """Map agent ids → full addresses for a set of ids."""
    if not agent_ids:
        return {}
    result = await db.execute(select(Agent.id, Agent.handle).where(Agent.id.in_(agent_ids)))
    return {row_id: _address(handle) for row_id, handle in result}


def _decrypt_subject(ciphertext_b64: str, enc_sk: bytes) -> str | None:
    """Best-effort subject decrypt for listings; ``None`` on any failure."""
    try:
        payload = json.loads(open_message(ciphertext_b64, enc_sk))
        return payload.get("subject")
    except Exception:  # noqa: BLE001
        return None
