"""MCP tool behavioral tests — run through the real ``_execute`` pipeline."""
from __future__ import annotations

from tests.conftest import TEST_PASSPHRASE, call_tool, insert_agent, requires_db

pytestmark = requires_db


async def test_send_check_read_reply_thread_flow(db):
    alice, _ = await insert_agent(db, "alice-flow")
    bob, _ = await insert_agent(db, "bob-flow")
    await call_tool(db, alice, "unlock_keychain", passphrase=TEST_PASSPHRASE)

    # Bob is locked: he can receive, but subjects stay hidden.
    sent = await call_tool(
        db, alice, "send_message", to="bob-flow", subject="Hello Bob", body="First contact."
    )
    assert sent["result"]["status"] == "stored"
    assert sent["result"]["from"] == "alice-flow@agentmail"
    assert sent["result"]["to"] == "bob-flow@agentmail"
    msg_id = sent["result"]["id"]
    thread_id = sent["result"]["thread_id"]
    assert thread_id == msg_id  # root-anchored (§5.6)

    inbox = await call_tool(db, bob, "check_inbox")
    assert inbox["result"]["keychain"] == "locked"
    assert "note" in inbox["result"]
    assert len(inbox["result"]["messages"]) == 1
    assert "subject" not in inbox["result"]["messages"][0]

    unlocked = await call_tool(db, bob, "unlock_keychain", passphrase=TEST_PASSPHRASE)
    assert unlocked["result"]["unlocked"] is True
    assert unlocked["result"]["auto_lock_at"] is not None

    inbox2 = await call_tool(db, bob, "check_inbox")
    assert inbox2["result"]["keychain"] == "unlocked"
    assert inbox2["result"]["messages"][0]["subject"] == "Hello Bob"
    assert inbox2["result"]["messages"][0]["from"] == "alice-flow@agentmail"

    read = await call_tool(db, bob, "read_message", id=msg_id)
    assert read["result"]["body"] == "First contact."
    assert read["result"]["subject"] == "Hello Bob"
    assert read["result"]["signature_valid"] is True
    assert read["result"]["read"] is True

    # Sender sees the read receipt.
    sent_box = await call_tool(db, alice, "get_sent")
    assert sent_box["result"]["messages"][0]["status"] == "read"
    assert sent_box["result"]["messages"][0]["read_at"] is not None

    reply = await call_tool(db, bob, "reply", id=msg_id, body="Hi Alice!")
    assert reply["result"]["thread_id"] == thread_id
    reply_id = reply["result"]["id"]

    thread = await call_tool(db, alice, "get_thread", thread_id=thread_id)
    assert [m["id"] for m in thread["result"]["messages"]] == [msg_id, reply_id]
    assert thread["result"]["messages"][1]["subject"] == "Re: Hello Bob"
    assert thread["result"]["messages"][1]["body"] == "Hi Alice!"

    # Bob soft-deletes; his inbox drops it but the thread still shows for
    # him via sender-side visibility rules (he is party to the thread).
    deleted = await call_tool(db, bob, "delete_message", id=msg_id)
    assert deleted["result"]["deleted"] is True
    again = await call_tool(db, bob, "delete_message", id=msg_id)
    assert again["result"]["already_deleted"] is True

    inbox3 = await call_tool(db, bob, "check_inbox", unread_only=False)
    assert all(m["id"] != msg_id for m in inbox3["result"]["messages"])


async def test_reading_own_sent_message_does_not_set_receipt(db):
    alice, _ = await insert_agent(db, "alice-receipt")
    bob, _ = await insert_agent(db, "bob-receipt")
    await call_tool(db, alice, "unlock_keychain", passphrase=TEST_PASSPHRASE)

    sent = await call_tool(db, alice, "send_message", to="bob-receipt", subject="s", body="b")
    msg_id = sent["result"]["id"]

    read = await call_tool(db, alice, "read_message", id=msg_id)
    # Sent copies are sealed to the recipient: metadata + signature only,
    # and reading it must never set the recipient's read receipt.
    assert read["result"]["read"] is False  # sender reading ≠ recipient read
    assert "body" not in read["result"]
    assert "note" in read["result"]
    assert read["result"]["signature_valid"] is True

    sent_box = await call_tool(db, alice, "get_sent")
    assert sent_box["result"]["messages"][0]["status"] == "delivered"


async def test_locked_keychain_blocks_crypto_tools(db):
    alice, _ = await insert_agent(db, "alice-locked")
    await insert_agent(db, "bob-locked")

    sent = await call_tool(db, alice, "send_message", to="bob-locked", subject="s", body="b")
    assert sent["error"]["code"] == "KEYCHAIN_LOCKED"

    read = await call_tool(db, alice, "read_message", id="00000000-0000-0000-0000-000000000000")
    assert read["error"]["code"] == "KEYCHAIN_LOCKED"

    status = await call_tool(db, alice, "keychain_status")
    assert status["result"]["locked"] is True


async def test_auto_unlock_via_passphrase_header(db):
    alice, _ = await insert_agent(db, "alice-auto")
    await insert_agent(db, "bob-auto")

    sent = await call_tool(
        db, alice, "send_message", to="bob-auto", subject="s", body="b",
        passphrase=TEST_PASSPHRASE,
    )
    assert sent["result"]["status"] == "stored"

    status = await call_tool(db, alice, "keychain_status")
    assert status["result"]["locked"] is False


async def test_auto_unlock_bad_passphrase_is_ignored(db):
    alice, _ = await insert_agent(db, "alice-badpass")
    await insert_agent(db, "bob-badpass")

    sent = await call_tool(
        db, alice, "send_message", to="bob-badpass", subject="s", body="b",
        passphrase="wrong passphrase",
    )
    assert sent["error"]["code"] == "KEYCHAIN_LOCKED"


async def test_unlock_lockout_after_five_failures(db):
    alice, _ = await insert_agent(db, "alice-lockout")

    for _ in range(5):
        bad = await call_tool(db, alice, "unlock_keychain", passphrase="wrong")
        assert bad["error"]["code"] == "BAD_PASSPHRASE"

    locked = await call_tool(db, alice, "unlock_keychain", passphrase=TEST_PASSPHRASE)
    assert locked["error"]["code"] == "RATE_LIMITED"
    assert locked["error"]["retry_after"] is not None


async def test_idempotent_send_replay(db):
    alice, _ = await insert_agent(db, "alice-idem")
    await insert_agent(db, "bob-idem")
    await call_tool(db, alice, "unlock_keychain", passphrase=TEST_PASSPHRASE)

    first = await call_tool(
        db, alice, "send_message", to="bob-idem", subject="s", body="b",
        idempotency_key="retry-1",
    )
    second = await call_tool(
        db, alice, "send_message", to="bob-idem", subject="s", body="b",
        idempotency_key="retry-1",
    )
    assert first["result"]["idempotent_replay"] is False
    assert second["result"]["idempotent_replay"] is True
    assert second["result"]["id"] == first["result"]["id"]

    sent_box = await call_tool(db, alice, "get_sent")
    assert len(sent_box["result"]["messages"]) == 1


async def test_thread_injection_rejected(db):
    alice, _ = await insert_agent(db, "alice-inject")
    await insert_agent(db, "bob-inject")
    carol, _ = await insert_agent(db, "carol-inject")
    await call_tool(db, alice, "unlock_keychain", passphrase=TEST_PASSPHRASE)
    await call_tool(db, carol, "unlock_keychain", passphrase=TEST_PASSPHRASE)

    sent = await call_tool(db, alice, "send_message", to="bob-inject", subject="s", body="b")
    msg_id = sent["result"]["id"]

    # Carol is not a party to the thread.
    r1 = await call_tool(db, carol, "send_message", to="bob-inject", subject="s", body="b", in_reply_to=msg_id)
    assert r1["error"]["code"] == "NOT_FOUND"

    r2 = await call_tool(db, carol, "send_message", to="bob-inject", subject="s", body="b", thread_id=msg_id)
    assert r2["error"]["code"] == "VALIDATION_ERROR"


async def test_mailbox_quota_enforced(db):
    alice, _ = await insert_agent(db, "alice-quota")
    await insert_agent(db, "bob-quota", quota_bytes=1000)
    await call_tool(db, alice, "unlock_keychain", passphrase=TEST_PASSPHRASE)

    first = await call_tool(
        db, alice, "send_message", to="bob-quota", subject="s", body="x" * 300
    )
    assert first["result"]["status"] == "stored"

    second = await call_tool(
        db, alice, "send_message", to="bob-quota", subject="s", body="x" * 300
    )
    assert second["error"]["code"] == "MAILBOX_FULL"


async def test_validation_errors(db):
    alice, _ = await insert_agent(db, "alice-valid")
    await call_tool(db, alice, "unlock_keychain", passphrase=TEST_PASSPHRASE)

    r = await call_tool(db, alice, "send_message", to="  ", subject="s", body="b")
    assert r["error"]["code"] == "VALIDATION_ERROR"

    r = await call_tool(db, alice, "whois", handle="nobody-here")
    assert r["error"]["code"] == "AGENT_NOT_FOUND"

    r = await call_tool(db, alice, "send_message", to="nobody-here", subject="s", body="b")
    assert r["error"]["code"] == "AGENT_NOT_FOUND"

    r = await call_tool(db, alice, "read_message", id="not-a-uuid")
    assert r["error"]["code"] == "NOT_FOUND"

    r = await call_tool(db, alice, "check_inbox", before="not-a-timestamp")
    assert r["error"]["code"] == "VALIDATION_ERROR"

    r = await call_tool(db, alice, "send_message", to="alice-valid", subject="s", body="\x00")
    assert r["error"]["code"] == "VALIDATION_ERROR"


async def test_whois_returns_profile_and_fingerprint(db):
    alice, _ = await insert_agent(db, "alice-whois")
    target, _ = await insert_agent(db, "bob-whois")

    r = await call_tool(db, alice, "whois", handle="bob-whois@agentmail")
    assert r["result"]["handle"] == "bob-whois"
    assert r["result"]["address"] == "bob-whois@agentmail"
    assert r["result"]["enc_pub"] == target.enc_pub
    assert r["result"]["sign_pub"] == target.sign_pub
    assert len(r["result"]["fingerprint"].split(" ")) == 4
