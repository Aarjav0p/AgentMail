"""The ``_inbox`` piggyback footer — §5.5.

Every tool response passes through :func:`apply_piggyback`.  When the
emission rules hold, a small unread-mail badge is attached in-band:

1. ``feature_flags.inbox_piggyback`` is enabled for the agent
   (absent row = enabled — the Phase 1 default).
2. The invoked tool is not ``check_inbox`` (a footer there is noise).
3. ``unread > 0``.
4. Sticky dedupe: state changed since the last footer emitted to this
   agent (``unread != agents.footer_unread`` OR ``latest.id != agents.footer_latest``).
5. Count + one summary line + fixed hint only — never bodies.
"""
from __future__ import annotations

import datetime
import json
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from relay.crypto.envelope import open_message
from relay.crypto.vault import vault
from relay.models.schema import Agent, FeatureFlag, Message

FOOTER_HINT = "You have unread agentmail — call check_inbox to read it."


def _address(handle: str) -> str:
    from relay.config import settings

    return f"{handle}@{settings.relay_domain}"


async def inbox_state(
    db: AsyncSession, agent_id: str
) -> tuple[int, Message | None]:
    """Return ``(unread_count, latest_unread_message)``.

    Two index-covered queries against ``messages_inbox_idx`` (§5.5).
    """
    now = datetime.datetime.now(datetime.UTC)
    live = (
        Message.recipient_id == agent_id,
        Message.deleted_at.is_(None),
        Message.expires_at > now,
        Message.read_at.is_(None),
    )

    count_result = await db.execute(
        select(func.count()).select_from(Message).where(*live)
    )
    unread = int(count_result.scalar_one())
    if unread == 0:
        return 0, None

    latest_result = await db.execute(
        select(Message).where(*live).order_by(Message.created_at.desc()).limit(1)
    )
    return unread, latest_result.scalar_one_or_none()


async def feature_flag_enabled(
    db: AsyncSession, agent_id: str, flag: str
) -> bool:
    """Per-agent flag check; an absent row means enabled (Phase 1 default)."""
    result = await db.execute(
        select(FeatureFlag.enabled).where(
            FeatureFlag.agent_id == agent_id, FeatureFlag.flag == flag
        )
    )
    enabled = result.scalar_one_or_none()
    return enabled is None or bool(enabled)


def should_emit(
    agent: Agent, unread: int, latest: Message | None
) -> bool:
    """Emission rules 3 and 4 (rules 1-2 are checked by the caller)."""
    if unread <= 0 or latest is None:
        return False
    return not (unread == agent.footer_unread and latest.id == agent.footer_latest)


def _latest_subject(latest: Message, enc_sk: bytes) -> str | None:
    """Decrypt the latest subject for the footer — best effort."""
    try:
        payload = json.loads(open_message(latest.ciphertext, enc_sk))
        subject = payload.get("subject")
        return subject if isinstance(subject, str) and subject else None
    except Exception:  # noqa: BLE001
        return None


async def apply_piggyback(
    db: AsyncSession,
    agent: Agent,
    tool_name: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Attach ``_inbox`` to *result* when all §5.5 rules hold."""
    if tool_name == "check_inbox":
        return result  # rule 2

    if not await feature_flag_enabled(db, agent.id, "inbox_piggyback"):
        return result  # rule 1

    unread, latest = await inbox_state(db, agent.id)
    if not should_emit(agent, unread, latest):
        return result  # rules 3 + 4
    assert latest is not None  # guaranteed by should_emit

    latest_info: dict[str, Any] = {
        "id": latest.id,
        "from": "unknown",
        "received_at": latest.created_at.isoformat() if latest.created_at else None,
    }

    sender_result = await db.execute(
        select(Agent.handle).where(Agent.id == latest.sender_id)
    )
    sender_handle = sender_result.scalar_one_or_none()
    if sender_handle:
        latest_info["from"] = _address(sender_handle)

    entry = await vault.get(agent.id)
    if entry is not None:
        subject = _latest_subject(latest, bytes(entry.enc_sk))
        if subject:
            latest_info["subject"] = subject

    await update_footer_markers(db, agent.id, unread, latest.id)

    return {
        **result,
        "_inbox": {
            "unread": unread,
            "latest": latest_info,
            "hint": FOOTER_HINT,
        },
    }


async def update_footer_markers(
    db: AsyncSession, agent_id: str, unread: int, latest_id: str
) -> None:
    """Persist the sticky-dedupe markers (rule 4 bookkeeping)."""
    await db.execute(
        update(Agent)
        .where(Agent.id == agent_id)
        .values(footer_unread=unread, footer_latest=latest_id)
    )
