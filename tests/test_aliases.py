"""Tests for ALIAS-01: Contact-Alias Resolution in the MCP Send Path."""

from __future__ import annotations

import logging

import pytest
from sqlalchemy import text
from uuid_utils import uuid7

from relay.config import settings
from relay.mcp import descriptions
from relay.mcp.contacts import reset_missing_table_warned
from relay.mcp.server import mcp_server
from tests.conftest import TEST_PASSPHRASE, call_tool, insert_agent


async def create_contacts_table(db):
    """Fixture helper: create user_contacts table in test DB."""
    await db.execute(
        text("""
            CREATE TABLE IF NOT EXISTS user_contacts (
              id            UUID PRIMARY KEY,
              owner_user_id UUID NOT NULL,
              alias         TEXT NOT NULL,
              target_handle TEXT NOT NULL,
              note          TEXT,
              created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
              updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
              UNIQUE (owner_user_id, alias)
            );
        """)
    )
    await db.commit()


async def insert_contact(db, owner_user_id: str, alias: str, target_handle: str):
    await db.execute(
        text("""
            INSERT INTO user_contacts (id, owner_user_id, alias, target_handle)
            VALUES (:id, :owner_user_id, :alias, :target_handle)
            ON CONFLICT (owner_user_id, alias) DO UPDATE SET target_handle = EXCLUDED.target_handle
        """),
        {
            "id": str(uuid7()),
            "owner_user_id": owner_user_id,
            "alias": alias.lower(),
            "target_handle": target_handle,
        },
    )
    await db.commit()


@pytest.mark.asyncio
async def test_01_alias_shadows_live_handle(db):
    """Test 1: Owner has dad -> dadagent; live handle 'dad' also exists; send to 'dad' delivers to dadagent."""
    await create_contacts_table(db)
    owner_id = str(uuid7())
    await insert_contact(db, owner_id, "dad", "dadagent")

    sender, _ = await insert_agent(db, "sender-1", owner_user_id=owner_id)
    dadagent, _ = await insert_agent(db, "dadagent")
    dad, _ = await insert_agent(db, "dad")

    res = await call_tool(
        db, sender, "send_message", passphrase=TEST_PASSPHRASE, to="dad", subject="s", body="b"
    )
    assert "result" in res, res
    result = res["result"]
    assert result["to"] == f"dadagent@{settings.relay_domain}"
    assert result["resolved_alias"] == "dad"

    # Delivered to dadagent
    dadagent_inbox = await call_tool(db, dadagent, "check_inbox", passphrase=TEST_PASSPHRASE)
    assert len(dadagent_inbox["result"]["messages"]) == 1

    # dad receives nothing
    dad_inbox = await call_tool(db, dad, "check_inbox", passphrase=TEST_PASSPHRASE)
    assert len(dad_inbox["result"]["messages"]) == 0


@pytest.mark.asyncio
async def test_02_fallback_regression_owned_agent(db):
    """Test 2: Owned agent, no such alias; to='alice' (live handle) -> normal delivery, no resolved_alias."""
    await create_contacts_table(db)
    owner_id = str(uuid7())
    sender, _ = await insert_agent(db, "sender-2", owner_user_id=owner_id)
    alice, _ = await insert_agent(db, "alice-norm")

    res = await call_tool(
        db,
        sender,
        "send_message",
        passphrase=TEST_PASSPHRASE,
        to="alice-norm",
        subject="s",
        body="b",
    )
    assert "result" in res, res
    result = res["result"]
    assert result["to"] == f"alice-norm@{settings.relay_domain}"
    assert "resolved_alias" not in result


@pytest.mark.asyncio
async def test_03_anonymous_agent_legacy_behavior(db):
    """Test 3: Anonymous agent (owner NULL): live handle works, unknown handle fails, no contacts access errors."""
    await create_contacts_table(db)
    sender, _ = await insert_agent(db, "anon-sender", owner_user_id=None)
    bob, _ = await insert_agent(db, "bob-target")

    # Live handle delivers
    res_ok = await call_tool(
        db,
        sender,
        "send_message",
        passphrase=TEST_PASSPHRASE,
        to="bob-target",
        subject="s",
        body="b",
    )
    assert "result" in res_ok, res_ok
    assert "resolved_alias" not in res_ok["result"]

    # Unknown handle returns standard error
    res_err = await call_tool(
        db, sender, "send_message", passphrase=TEST_PASSPHRASE, to="nobody", subject="s", body="b"
    )
    assert res_err["error"]["code"] == "AGENT_NOT_FOUND"


@pytest.mark.asyncio
async def test_04_full_address_bypasses_contacts_book(db):
    """Test 4: Full-address bypass: dad@agentmail bypasses alias lookup and delivers to handle 'dad'."""
    await create_contacts_table(db)
    owner_id = str(uuid7())
    await insert_contact(db, owner_id, "dad", "dadagent-4")

    sender, _ = await insert_agent(db, "sender-4", owner_user_id=owner_id)
    dadagent, _ = await insert_agent(db, "dadagent-4")
    dad, _ = await insert_agent(db, "dad-4")

    # Send to explicit address dad-4@agentmail
    res = await call_tool(
        db,
        sender,
        "send_message",
        passphrase=TEST_PASSPHRASE,
        to=f"dad-4@{settings.relay_domain}",
        subject="s",
        body="b",
    )
    assert "result" in res, res
    result = res["result"]
    assert result["to"] == f"dad-4@{settings.relay_domain}"
    assert "resolved_alias" not in result

    # Delivered to dad-4
    dad_inbox = await call_tool(db, dad, "check_inbox", passphrase=TEST_PASSPHRASE)
    assert len(dad_inbox["result"]["messages"]) == 1

    # dadagent receives nothing
    dadagent_inbox = await call_tool(db, dadagent, "check_inbox", passphrase=TEST_PASSPHRASE)
    assert len(dadagent_inbox["result"]["messages"]) == 0


@pytest.mark.asyncio
async def test_05_unregistered_target_error(db):
    """Test 5: ghost -> nosuchagent; existing recipient-not-found code, names alias and resolved address."""
    await create_contacts_table(db)
    owner_id = str(uuid7())
    await insert_contact(db, owner_id, "ghost", "nosuchagent")
    sender, _ = await insert_agent(db, "sender-5", owner_user_id=owner_id)

    res = await call_tool(
        db, sender, "send_message", passphrase=TEST_PASSPHRASE, to="ghost", subject="s", body="b"
    )
    assert res["error"]["code"] == "AGENT_NOT_FOUND"
    assert (
        "Your contact 'ghost' points to nosuchagent@agentmail, which is not a registered agent."
        in res["error"]["message"]
    )


@pytest.mark.asyncio
async def test_06_result_shape_and_echo(db):
    """Test 6: resolved_alias present on alias sends, echo shows resolved address; absent on non-alias sends."""
    await create_contacts_table(db)
    owner_id = str(uuid7())
    await insert_contact(db, owner_id, "partner", "charlie")
    sender, _ = await insert_agent(db, "sender-6", owner_user_id=owner_id)
    charlie, _ = await insert_agent(db, "charlie")

    # Alias send
    res_alias = await call_tool(
        db, sender, "send_message", passphrase=TEST_PASSPHRASE, to="partner", subject="s", body="b"
    )
    assert res_alias["result"]["to"] == f"charlie@{settings.relay_domain}"
    assert res_alias["result"]["resolved_alias"] == "partner"

    # Non-alias send
    res_direct = await call_tool(
        db, sender, "send_message", passphrase=TEST_PASSPHRASE, to="charlie", subject="s", body="b"
    )
    assert res_direct["result"]["to"] == f"charlie@{settings.relay_domain}"
    assert "resolved_alias" not in res_direct["result"]


@pytest.mark.asyncio
async def test_07_inbound_annotation_check_inbox_and_read_message(db):
    """Test 7: A -> B where B's owner has an alias for A: check_inbox item and read_message payload carry from_alias."""
    await create_contacts_table(db)
    owner_b = str(uuid7())
    await insert_contact(db, owner_b, "bestie", "agent-a")

    a, _ = await insert_agent(db, "agent-a")
    b, _ = await insert_agent(db, "agent-b", owner_user_id=owner_b)
    c, _ = await insert_agent(db, "agent-c")  # not in contacts

    # A sends to B
    send_a = await call_tool(
        db,
        a,
        "send_message",
        passphrase=TEST_PASSPHRASE,
        to="agent-b",
        subject="hello",
        body="body a",
    )
    msg_a_id = send_a["result"]["id"]

    # C sends to B
    send_c = await call_tool(
        db,
        c,
        "send_message",
        passphrase=TEST_PASSPHRASE,
        to="agent-b",
        subject="hello c",
        body="body c",
    )
    msg_c_id = send_c["result"]["id"]

    # Check inbox for B
    inbox_b = await call_tool(db, b, "check_inbox", passphrase=TEST_PASSPHRASE)
    items_by_id = {m["id"]: m for m in inbox_b["result"]["messages"]}

    assert items_by_id[msg_a_id]["from_alias"] == "bestie"
    assert "from_alias" not in items_by_id[msg_c_id]

    # Read message for B
    read_a = await call_tool(db, b, "read_message", passphrase=TEST_PASSPHRASE, id=msg_a_id)
    assert read_a["result"]["from_alias"] == "bestie"

    read_c = await call_tool(db, b, "read_message", passphrase=TEST_PASSPHRASE, id=msg_c_id)
    assert "from_alias" not in read_c["result"]


@pytest.mark.asyncio
async def test_08_missing_table_guard(db, caplog):
    """Test 8: Drop user_contacts table; send_message and check_inbox succeed gracefully with exactly one warn log."""
    await db.execute(text("DROP TABLE IF EXISTS user_contacts CASCADE"))
    await db.commit()
    reset_missing_table_warned()

    owner_id = str(uuid7())
    sender, _ = await insert_agent(db, "sender-8", owner_user_id=owner_id)
    recipient, _ = await insert_agent(db, "recipient-8")

    with caplog.at_level(logging.WARNING, logger="agentmail.contacts"):
        res_send = await call_tool(
            db,
            sender,
            "send_message",
            passphrase=TEST_PASSPHRASE,
            to="recipient-8",
            subject="s",
            body="b",
        )
        assert "result" in res_send, res_send

        res_inbox = await call_tool(db, recipient, "check_inbox", passphrase=TEST_PASSPHRASE)
        assert "result" in res_inbox, res_inbox

    warn_logs = [
        r for r in caplog.records if r.levelname == "WARNING" and "user_contacts" in r.message
    ]
    assert len(warn_logs) == 1, f"Expected exactly 1 warning log, got {len(warn_logs)}"


@pytest.mark.asyncio
async def test_09_description_guards():
    """Test 9: TOOLDESC-01 guard tests — description <= 900 chars, ASCII, single line, inputSchema unchanged."""
    tools = await mcp_server.list_tools()
    send_tool = next(t for t in tools if t.name == "send_message")
    desc = send_tool.description
    assert desc == descriptions.SEND_MESSAGE
    assert len(desc) <= 900
    assert desc.isascii()
    assert "\n" not in desc and "\r" not in desc
    assert "saved contact aliases" in desc


@pytest.mark.asyncio
async def test_10_multi_agent_owner(db):
    """Test 10: Two agents sharing the same owner_user_id both resolve to the same target."""
    await create_contacts_table(db)
    owner_id = str(uuid7())
    await insert_contact(db, owner_id, "shared-contact", "target-10")

    agent_1, _ = await insert_agent(db, "agent-1-shared", owner_user_id=owner_id)
    agent_2, _ = await insert_agent(db, "agent-2-shared", owner_user_id=owner_id)
    target, _ = await insert_agent(db, "target-10")

    res_1 = await call_tool(
        db,
        agent_1,
        "send_message",
        passphrase=TEST_PASSPHRASE,
        to="shared-contact",
        subject="s",
        body="b",
    )
    res_2 = await call_tool(
        db,
        agent_2,
        "send_message",
        passphrase=TEST_PASSPHRASE,
        to="shared-contact",
        subject="s",
        body="b",
    )

    assert res_1["result"]["to"] == f"target-10@{settings.relay_domain}"
    assert res_1["result"]["resolved_alias"] == "shared-contact"
    assert res_2["result"]["to"] == f"target-10@{settings.relay_domain}"
    assert res_2["result"]["resolved_alias"] == "shared-contact"
