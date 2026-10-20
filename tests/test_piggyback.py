"""Piggyback footer tests (§5.5) — emission rules and sticky dedupe."""

from __future__ import annotations

from relay.models.schema import FeatureFlag
from tests.conftest import TEST_PASSPHRASE, call_tool, insert_agent, requires_db

pytestmark = requires_db


async def setup_pair(db):
    alice, _ = await insert_agent(db, "alice-pig")
    bob, _ = await insert_agent(db, "bob-pig")
    await call_tool(db, alice, "unlock_keychain", passphrase=TEST_PASSPHRASE)
    await call_tool(db, bob, "unlock_keychain", passphrase=TEST_PASSPHRASE)
    return alice, bob


async def test_footer_emits_once_per_state_change(db):
    alice, bob = await setup_pair(db)
    await call_tool(db, alice, "send_message", to="bob-pig", subject="Ping", body="1")

    # First non-check_inbox tool call after the state change → footer.
    r1 = await call_tool(db, bob, "whois", handle="alice-pig")
    assert r1["_inbox"]["unread"] == 1
    assert r1["_inbox"]["latest"]["from"] == "alice-pig@agentmail"
    assert "subject" not in r1["_inbox"]["latest"]
    assert "check_inbox" in r1["_inbox"]["hint"]

    # Same state again → no footer.
    r2 = await call_tool(db, bob, "whois", handle="alice-pig")
    assert "_inbox" not in r2

    # New mail (even identical text) → footer with the new count.
    await call_tool(db, alice, "send_message", to="bob-pig", subject="Ping", body="2")
    r3 = await call_tool(db, bob, "keychain_status")
    assert r3["_inbox"]["unread"] == 2


async def test_check_inbox_never_carries_footer(db):
    alice, bob = await setup_pair(db)
    await call_tool(db, alice, "send_message", to="bob-pig", subject="Ping", body="1")

    r = await call_tool(db, bob, "check_inbox")
    assert "_inbox" not in r


async def test_reading_mail_clears_footer_until_state_changes(db):
    alice, bob = await setup_pair(db)
    sent = await call_tool(db, alice, "send_message", to="bob-pig", subject="Ping", body="1")
    msg_id = sent["result"]["id"]

    r1 = await call_tool(db, bob, "keychain_status")
    assert r1["_inbox"]["unread"] == 1

    await call_tool(db, bob, "read_message", id=msg_id)  # unread → 0

    r2 = await call_tool(db, bob, "keychain_status")
    assert "_inbox" not in r2


async def test_disabled_feature_flag_suppresses_footer(db):
    alice, bob = await setup_pair(db)
    await call_tool(db, alice, "send_message", to="bob-pig", subject="Ping", body="1")

    db.add(FeatureFlag(agent_id=bob.id, flag="inbox_piggyback", enabled=False))
    await db.commit()

    r = await call_tool(db, bob, "keychain_status")
    assert "_inbox" not in r


async def test_explicit_true_flag_still_emits(db):
    alice, bob = await setup_pair(db)
    db.add(FeatureFlag(agent_id=bob.id, flag="inbox_piggyback", enabled=True))
    await db.commit()
    await call_tool(db, alice, "send_message", to="bob-pig", subject="Ping", body="1")

    r = await call_tool(db, bob, "keychain_status")
    assert r["_inbox"]["unread"] == 1


async def test_footer_never_includes_subject(db):
    alice, bob = await setup_pair(db)
    await call_tool(db, alice, "send_message", to="bob-pig", subject="Top Secret", body="1")

    r = await call_tool(db, bob, "keychain_status")  # bob is unlocked
    assert r["_inbox"]["unread"] == 1
    assert "subject" not in r["_inbox"]["latest"]
