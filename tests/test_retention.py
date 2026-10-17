"""Tests for RETENTION-01: 60d read / 30d unread retention policy."""

from __future__ import annotations

import datetime

import pytest
from sqlalchemy import select
from uuid_utils import uuid7

from relay.api.admin import run_purge
from relay.config import settings
from relay.models.schema import Agent, AuditLog, Message
from tests.conftest import insert_agent, requires_db


def test_retention_settings_defaults():
    """Verify settings defaults match RETENTION-01."""
    assert settings.read_ttl_days == 60
    assert settings.unread_ttl_days == 30


async def _create_test_message(
    db,
    sender: Agent,
    recipient: Agent,
    *,
    created_at: datetime.datetime,
    expires_at: datetime.datetime | None = None,
    read_at: datetime.datetime | None = None,
) -> Message:
    msg_id = str(uuid7())
    if expires_at is None:
        expires_at = created_at + datetime.timedelta(days=settings.unread_ttl_days)
    msg = Message(
        id=msg_id,
        thread_id=msg_id,
        sender_id=sender.id,
        recipient_id=recipient.id,
        ciphertext="dGVzdA==",
        sig="c2ln",
        key_epoch=1,
        size_bytes=100,
        created_at=created_at,
        expires_at=expires_at,
        read_at=read_at,
    )
    db.add(msg)
    await db.commit()
    return msg


async def _message_exists(db, msg_id: str) -> bool:
    res = await db.execute(select(Message.id).where(Message.id == msg_id))
    return res.scalar_one_or_none() is not None


@requires_db
@pytest.mark.asyncio
async def test_retention_scenarios(db):
    """Scenarios 1-7: retention rules and regression test for the §2 fix."""
    now = datetime.datetime.now(datetime.UTC)
    alice, _ = await insert_agent(db, "alice-ret")
    bob, _ = await insert_agent(db, "bob-ret")

    # 1. unread, created 29 days ago -> kept
    m1 = await _create_test_message(
        db, alice, bob, created_at=now - datetime.timedelta(days=29), read_at=None
    )

    # 2. unread, created 31 days ago -> purged
    m2 = await _create_test_message(
        db, alice, bob, created_at=now - datetime.timedelta(days=31), read_at=None
    )

    # 3. read 59 days ago -> kept
    m3 = await _create_test_message(
        db,
        alice,
        bob,
        created_at=now - datetime.timedelta(days=70),
        read_at=now - datetime.timedelta(days=59),
    )

    # 4. read 61 days ago -> purged
    m4 = await _create_test_message(
        db,
        alice,
        bob,
        created_at=now - datetime.timedelta(days=70),
        read_at=now - datetime.timedelta(days=61),
    )

    # 5. created 40 days ago, read 15 days ago -> kept
    # REGRESSION TEST for §2 fix: old query would purge this because expires_at was 10 days ago!
    m5 = await _create_test_message(
        db,
        alice,
        bob,
        created_at=now - datetime.timedelta(days=40),
        read_at=now - datetime.timedelta(days=15),
    )

    # 6. created 25 days ago, read 24 days ago -> kept (both rules pass)
    m6 = await _create_test_message(
        db,
        alice,
        bob,
        created_at=now - datetime.timedelta(days=25),
        read_at=now - datetime.timedelta(days=24),
    )

    # Execute purge with standard settings (read_ttl=60)
    result = await run_purge(db)
    assert result["purged_messages"] >= 2

    # Assert kept / purged states
    assert await _message_exists(db, m1.id), "m1 (unread 29d) should be kept"
    assert not await _message_exists(db, m2.id), "m2 (unread 31d) should be purged"
    assert await _message_exists(db, m3.id), "m3 (read 59d) should be kept"
    assert not await _message_exists(db, m4.id), "m4 (read 61d) should be purged"
    assert await _message_exists(db, m5.id), (
        "m5 (created 40d, read 15d) MUST be kept (regression test)"
    )
    assert await _message_exists(db, m6.id), "m6 (created 25d, read 24d) should be kept"

    # 7. env override READ_TTL_DAYS=1, read 2 days ago -> purged
    m7 = await _create_test_message(
        db,
        alice,
        bob,
        created_at=now - datetime.timedelta(days=5),
        read_at=now - datetime.timedelta(days=2),
    )
    result_override = await run_purge(db, read_ttl_days=1)
    assert result_override["purged_messages"] >= 1
    assert not await _message_exists(db, m7.id), "m7 should be purged with read_ttl_days=1"


@requires_db
@pytest.mark.asyncio
async def test_audit_log_deleted_count(db):
    """Scenario 8: audit row written with deleted_count after a sweep."""
    now = datetime.datetime.now(datetime.UTC)
    alice, _ = await insert_agent(db, "alice-audit")
    bob, _ = await insert_agent(db, "bob-audit")

    # Create 2 messages that are expired
    await _create_test_message(
        db, alice, bob, created_at=now - datetime.timedelta(days=35), read_at=None
    )
    await _create_test_message(
        db, alice, bob, created_at=now - datetime.timedelta(days=40), read_at=None
    )

    result = await run_purge(db)
    purged_count = result["purged_messages"]
    assert purged_count >= 2

    # Query latest audit_log entry for purge event
    audit_res = await db.execute(
        select(AuditLog).where(AuditLog.event == "purge").order_by(AuditLog.id.desc()).limit(1)
    )
    audit = audit_res.scalar_one_or_none()
    assert audit is not None
    assert f"deleted_count={purged_count}" in (audit.ip or "")
