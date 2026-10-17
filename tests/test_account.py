"""Tests for DASH-01: Relay-side account management, auto-provisioning,
contact aliases, and server-custody E2E.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from uuid_utils import uuid7

from relay.config import settings
from relay.crypto.envelope import generate_api_key
from relay.models.schema import Agent, AuditLog, UserContact
from tests.conftest import (
    TEST_PASSPHRASE,
    call_tool,
    insert_agent,
    mint_test_jwt,
)


@pytest.fixture(autouse=True)
def _disable_rest_rate_limits():
    """Disable slowapi limits during test suite."""
    from relay.ratelimit import limiter

    limiter.enabled = False
    yield
    limiter.enabled = True


# ---------------------------------------------------------------------------
# Test 1 & 2: Token Verification (§5.2)
# ---------------------------------------------------------------------------


async def test_01_valid_supabase_jwt(client, db):
    """Test 1: Valid Supabase JWT on /v1/account/* returns 200."""
    user_id = str(uuid7())
    token = mint_test_jwt(user_id)
    r = await client.get("/v1/account/agents", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json() == {"agents": []}


async def test_02_expired_wrong_issuer_garbage_token(app_client):
    """Test 2: Expired, wrong issuer, or garbage tokens return 401 with standard error body."""
    user_id = str(uuid7())

    # Expired token
    expired = mint_test_jwt(user_id, exp_minutes=-10)
    r1 = await app_client.get("/v1/account/agents", headers={"Authorization": f"Bearer {expired}"})
    assert r1.status_code == 401
    assert r1.json()["error"]["code"] == "UNAUTHORIZED"

    # Wrong issuer
    wrong_iss = mint_test_jwt(user_id, iss="https://wrong-issuer.com/auth/v1")
    r2 = await app_client.get(
        "/v1/account/agents", headers={"Authorization": f"Bearer {wrong_iss}"}
    )
    assert r2.status_code == 401
    assert r2.json()["error"]["code"] == "UNAUTHORIZED"

    # Garbage token
    r3 = await app_client.get("/v1/account/agents", headers={"Authorization": "Bearer not-a-jwt"})
    assert r3.status_code == 401
    assert r3.json()["error"]["code"] == "UNAUTHORIZED"

    # Missing authorization header
    r4 = await app_client.get("/v1/account/agents")
    assert r4.status_code == 401
    assert r4.json()["error"]["code"] == "UNAUTHORIZED"


# ---------------------------------------------------------------------------
# Test 3: Domain Separation (§2)
# ---------------------------------------------------------------------------


async def test_03_domain_separation(client, db):
    """Test 3: am_live_ key against /v1/account/* and Supabase JWT against /mcp both rejected 401."""
    user_id = str(uuid7())
    agent_key = generate_api_key()

    # am_live_ key against /v1/account/*
    r_acc = await client.get("/v1/account/agents", headers={"Authorization": f"Bearer {agent_key}"})
    assert r_acc.status_code == 401
    assert r_acc.json()["error"]["code"] == "UNAUTHORIZED"

    # Supabase JWT against /mcp
    jwt_token = mint_test_jwt(user_id)
    r_mcp = await client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {jwt_token}"},
        json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
    )
    assert r_mcp.status_code == 401
    assert r_mcp.json()["error"]["code"] == "UNAUTHORIZED"


# ---------------------------------------------------------------------------
# Test 4: Provisioning Idempotency (§6.2)
# ---------------------------------------------------------------------------


async def test_04_provisioning_idempotency(client, db):
    """Test 4: First POST provisions agent; second POST returns existing: true with same id."""
    user_id = str(uuid7())
    token = mint_test_jwt(user_id)

    # First POST creates agent
    r1 = await client.post(
        "/v1/account/agents",
        headers={"Authorization": f"Bearer {token}"},
        json={"handle": "alice-prov"},
    )
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1["existing"] is False
    assert data1["agent"]["handle"] == "alice-prov"
    assert data1["agent"]["custody_mode"] == "server_kek"
    assert data1["api_key"].startswith("am_live_")
    agent_id = data1["agent"]["id"]

    # Second POST (even with different handle) returns existing agent
    r2 = await client.post(
        "/v1/account/agents",
        headers={"Authorization": f"Bearer {token}"},
        json={"handle": "alice-different"},
    )
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["existing"] is True
    assert data2["agent"]["id"] == agent_id
    assert data2["agent"]["handle"] == "alice-prov"
    assert data2["api_key"] == data1["api_key"]

    # Exactly one agent row exists for user
    res = await db.execute(select(Agent).where(Agent.owner_user_id == user_id))
    assert len(res.scalars().all()) == 1


# ---------------------------------------------------------------------------
# Test 5 & 5b: Availability & Provisioning Validation (§6.1, §6.2)
# ---------------------------------------------------------------------------


async def test_05_handle_availability(client, db):
    """Test 5: Handle availability check semantics: available, reserved, invalid, taken (live or burned)."""
    user_id = str(uuid7())
    token = mint_test_jwt(user_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Available
    r_avail = await client.get("/v1/account/handle-available?handle=charlie-free", headers=headers)
    assert r_avail.status_code == 200
    assert r_avail.json() == {"handle": "charlie-free", "available": True}

    # Reserved
    r_res = await client.get("/v1/account/handle-available?handle=postmaster", headers=headers)
    assert r_res.status_code == 200
    assert r_res.json() == {"handle": "postmaster", "available": False, "reason": "reserved"}

    # Invalid
    r_inv = await client.get("/v1/account/handle-available?handle=a!", headers=headers)
    assert r_inv.status_code == 200
    assert r_inv.json() == {"handle": "a!", "available": False, "reason": "invalid"}

    # Taken (live handle)
    await insert_agent(db, "live-handle-test")
    r_taken = await client.get(
        "/v1/account/handle-available?handle=live-handle-test", headers=headers
    )
    assert r_taken.status_code == 200
    assert r_taken.json() == {"handle": "live-handle-test", "available": False, "reason": "taken"}

    # Taken (burned handle: deleted_at is set)
    burned_agent, _ = await insert_agent(db, "burned-handle-test")
    burned_agent.deleted_at = text("now()")
    await db.commit()
    r_burned = await client.get(
        "/v1/account/handle-available?handle=burned-handle-test", headers=headers
    )
    assert r_burned.status_code == 200
    assert r_burned.json() == {
        "handle": "burned-handle-test",
        "available": False,
        "reason": "taken",
    }


async def test_05b_provision_validation_and_conflict(client, db):
    """Test 5b: Provisioning validation: bare handle only, HANDLE_TAKEN on collision."""
    user_id = str(uuid7())
    token = mint_test_jwt(user_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Contains '@' -> 400 VALIDATION_ERROR
    r_at = await client.post(
        "/v1/account/agents", headers=headers, json={"handle": "alice@agentmail"}
    )
    assert r_at.status_code == 400
    assert r_at.json()["error"]["code"] == "VALIDATION_ERROR"

    # Reserved -> 400 VALIDATION_ERROR
    r_res = await client.post("/v1/account/agents", headers=headers, json={"handle": "postmaster"})
    assert r_res.status_code == 400
    assert r_res.json()["error"]["code"] == "VALIDATION_ERROR"

    # Already taken by another user -> 409 HANDLE_TAKEN
    await insert_agent(db, "already-taken-test")
    r_dup = await client.post(
        "/v1/account/agents", headers=headers, json={"handle": "already-taken-test"}
    )
    assert r_dup.status_code == 409
    assert r_dup.json()["error"]["code"] == "HANDLE_TAKEN"


# ---------------------------------------------------------------------------
# Test 6: Reveal API Key (§6.4)
# ---------------------------------------------------------------------------


async def test_06_reveal_api_key(client, db):
    """Test 6: Owner can reveal key; other user gets 404; audit row written."""
    user_a = str(uuid7())
    user_b = str(uuid7())
    token_a = mint_test_jwt(user_a)
    token_b = mint_test_jwt(user_b)

    # Provision agent for user A
    r_prov = await client.post(
        "/v1/account/agents",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"handle": "agent-user-a"},
    )
    assert r_prov.status_code == 200
    prov_data = r_prov.json()
    agent_id = prov_data["agent"]["id"]
    original_key = prov_data["api_key"]

    # Owner A reveals key
    r_reveal = await client.get(
        f"/v1/account/agents/{agent_id}/api-key",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert r_reveal.status_code == 200
    assert r_reveal.json()["api_key"] == original_key

    # Audit row written
    aud_res = await db.execute(
        select(AuditLog).where(AuditLog.agent_id == agent_id, AuditLog.event == "api_key_revealed")
    )
    assert aud_res.scalar_one_or_none() is not None

    # User B gets 404 (no existence oracle)
    r_b = await client.get(
        f"/v1/account/agents/{agent_id}/api-key",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert r_b.status_code == 404
    assert r_b.json()["error"]["code"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# Test 7: Rotate API Key (§6.5)
# ---------------------------------------------------------------------------


async def test_07_rotate_api_key(client, db):
    """Test 7: Rotate generates new key, invalidates old, updates api_key_enc and audit."""
    user_a = str(uuid7())
    token = mint_test_jwt(user_a)
    headers = {"Authorization": f"Bearer {token}"}

    r_prov = await client.post("/v1/account/agents", headers=headers, json={"handle": "rot-agent"})
    agent_id = r_prov.json()["agent"]["id"]
    old_key = r_prov.json()["api_key"]

    # Rotate
    r_rot = await client.post(f"/v1/account/agents/{agent_id}/api-key/rotate", headers=headers)
    assert r_rot.status_code == 200
    new_key = r_rot.json()["api_key"]
    assert new_key.startswith("am_live_")
    assert new_key != old_key

    # Reveal shows the new key
    r_rev = await client.get(f"/v1/account/agents/{agent_id}/api-key", headers=headers)
    assert r_rev.json()["api_key"] == new_key

    # Audit log contains api_key_rotated
    aud_res = await db.execute(
        select(AuditLog).where(AuditLog.agent_id == agent_id, AuditLog.event == "api_key_rotated")
    )
    assert aud_res.scalar_one_or_none() is not None

    # Old key invalidated: its hash no longer matches the stored api_key_hash.
    # (HTTP-level MCP auth rejection is covered by test_mcp_http; entering the
    # streamable-HTTP session manager here would break that test, since run()
    # may only be entered once per process.)
    from relay.crypto.envelope import hash_api_key
    from relay.models.schema import Agent as AgentModel

    ag_res = await db.execute(select(AgentModel).where(AgentModel.id == agent_id))
    ag = ag_res.scalar_one()
    assert ag.api_key_hash != hash_api_key(old_key)
    assert ag.api_key_hash == hash_api_key(new_key)


# ---------------------------------------------------------------------------
# Test 8: Server-Custody E2E without unlock (§4, Test 8)
# ---------------------------------------------------------------------------


async def test_08_server_custody_e2e_without_unlock(db):
    """Test 8: Two server_kek agents exchange mail via MCP without unlock_keychain."""
    owner_a = str(uuid7())
    owner_b = str(uuid7())

    agent_a, _ = await insert_agent(
        db, "agent-a-kek", owner_user_id=owner_a, custody_mode="server_kek"
    )
    agent_b, _ = await insert_agent(
        db, "agent-b-kek", owner_user_id=owner_b, custody_mode="server_kek"
    )

    # A sends to B without ANY unlock call
    send_res = await call_tool(
        db, agent_a, "send_message", to="agent-b-kek", subject="Hello KEK", body="Secret body"
    )
    assert "result" in send_res, send_res
    msg_id = send_res["result"]["id"]

    # B checks inbox without unlock
    inbox_res = await call_tool(db, agent_b, "check_inbox")
    assert "result" in inbox_res, inbox_res
    msgs = inbox_res["result"]["messages"]
    assert len(msgs) == 1
    assert msgs[0]["subject"] == "Hello KEK"  # subjects revealed when unlocked!

    # B reads message without unlock
    read_res = await call_tool(db, agent_b, "read_message", id=msg_id)
    assert "result" in read_res, read_res
    assert read_res["result"]["body"] == "Secret body"
    assert read_res["result"]["signature_valid"] is True

    # unlock_keychain for server_kek is an idempotent no-op
    unlock_res = await call_tool(db, agent_b, "unlock_keychain", passphrase="any")
    assert unlock_res["result"]["unlocked"] is True
    assert "server-side key custody" in unlock_res["result"]["note"]


# ---------------------------------------------------------------------------
# Test 9: Legacy Passphrase Agent Regression (§4, Test 9)
# ---------------------------------------------------------------------------


async def test_09_anonymous_register_agent_regression(db):
    """Test 9: user_passphrase agents still require unlock_keychain and get KEYCHAIN_LOCKED."""
    agent_leg, _ = await insert_agent(db, "agent-legacy", custody_mode="user_passphrase")

    # Send without unlock -> KEYCHAIN_LOCKED
    res_send = await call_tool(db, agent_leg, "send_message", to="someone", subject="s", body="b")
    assert res_send.get("error", {}).get("code") == "KEYCHAIN_LOCKED"

    # Unlock with correct passphrase
    res_unlock = await call_tool(db, agent_leg, "unlock_keychain", passphrase=TEST_PASSPHRASE)
    assert res_unlock["result"]["unlocked"] is True


# ---------------------------------------------------------------------------
# Test 10: CORS Preflight (§7.2, Test 10)
# ---------------------------------------------------------------------------


async def test_10_cors_preflight(app_client):
    """Test 10: CORS preflight from allowed origin returns headers; unknown origin does not."""
    # Allowed origin: http://localhost:5173
    r_allowed = await app_client.options(
        "/v1/account/agents",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r_allowed.status_code == 200
    assert r_allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"

    # Unknown origin: https://evil.com
    r_blocked = await app_client.options(
        "/v1/account/agents",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r_blocked.headers.get("access-control-allow-origin") != "https://evil.com"


# ---------------------------------------------------------------------------
# Test 11: Contacts CRUD (§6.7, Test 11)
# ---------------------------------------------------------------------------


async def test_11_contacts_crud(client, db):
    """Test 11: Create -> list (sorted, address derived) -> patch -> delete; scoped to owner."""
    user_id = str(uuid7())
    token = mint_test_jwt(user_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Create contact
    r_post = await client.post(
        "/v1/account/contacts",
        headers=headers,
        json={"alias": "dad", "target_handle": "dadagent", "note": "Dad's assistant"},
    )
    assert r_post.status_code == 201
    contact = r_post.json()["contact"]
    assert contact["alias"] == "dad"
    assert contact["target_handle"] == "dadagent"
    assert contact["address"] == f"dadagent@{settings.relay_domain}"
    assert contact["note"] == "Dad's assistant"
    contact_id = contact["id"]

    # List contacts
    r_list = await client.get("/v1/account/contacts", headers=headers)
    assert r_list.status_code == 200
    contacts = r_list.json()["contacts"]
    assert len(contacts) == 1
    assert contacts[0]["id"] == contact_id

    # Patch contact
    r_patch = await client.patch(
        f"/v1/account/contacts/{contact_id}",
        headers=headers,
        json={"note": "Updated note", "target_handle": "dad-new"},
    )
    assert r_patch.status_code == 200
    assert r_patch.json()["contact"]["note"] == "Updated note"
    assert r_patch.json()["contact"]["target_handle"] == "dad-new"
    assert r_patch.json()["contact"]["address"] == f"dad-new@{settings.relay_domain}"

    # Delete contact
    r_del = await client.delete(f"/v1/account/contacts/{contact_id}", headers=headers)
    assert r_del.status_code == 204

    # Verify deleted
    r_list2 = await client.get("/v1/account/contacts", headers=headers)
    assert r_list2.json()["contacts"] == []


# ---------------------------------------------------------------------------
# Test 12: Alias Rules (§6.7, Test 12)
# ---------------------------------------------------------------------------


async def test_12_alias_validation_and_uniqueness(client, db):
    """Test 12: Alias rules: uppercase Dad -> 400; too short d -> 400; dad! -> 400; duplicate -> 409; different user -> 201."""
    user_1 = str(uuid7())
    user_2 = str(uuid7())
    token_1 = mint_test_jwt(user_1)
    token_2 = mint_test_jwt(user_2)

    # Uppercase Dad -> 400
    r_up = await client.post(
        "/v1/account/contacts",
        headers={"Authorization": f"Bearer {token_1}"},
        json={"alias": "Dad", "target_handle": "dadagent"},
    )
    assert r_up.status_code == 400
    assert r_up.json()["error"]["code"] == "VALIDATION_ERROR"

    # Too short 'd' -> 400
    r_short = await client.post(
        "/v1/account/contacts",
        headers={"Authorization": f"Bearer {token_1}"},
        json={"alias": "d", "target_handle": "dadagent"},
    )
    assert r_short.status_code == 400

    # Invalid characters 'dad!' -> 400
    r_inv = await client.post(
        "/v1/account/contacts",
        headers={"Authorization": f"Bearer {token_1}"},
        json={"alias": "dad!", "target_handle": "dadagent"},
    )
    assert r_inv.status_code == 400

    # Valid dad -> 201
    r_ok = await client.post(
        "/v1/account/contacts",
        headers={"Authorization": f"Bearer {token_1}"},
        json={"alias": "dad", "target_handle": "dadagent"},
    )
    assert r_ok.status_code == 201

    # Duplicate dad for user 1 -> 409 ALIAS_EXISTS
    r_dup = await client.post(
        "/v1/account/contacts",
        headers={"Authorization": f"Bearer {token_1}"},
        json={"alias": "dad", "target_handle": "otheragent"},
    )
    assert r_dup.status_code == 409
    assert r_dup.json()["error"]["code"] == "ALIAS_EXISTS"

    # Same alias dad for user 2 -> 201 (per-account address book namespace)
    r_u2 = await client.post(
        "/v1/account/contacts",
        headers={"Authorization": f"Bearer {token_2}"},
        json={"alias": "dad", "target_handle": "someoneelse"},
    )
    assert r_u2.status_code == 201


# ---------------------------------------------------------------------------
# Test 13: Target Rules (§6.7, Test 13)
# ---------------------------------------------------------------------------


async def test_13_target_rules(client, db):
    """Test 13: Target rules: @ inside target -> 400; reserved -> 400; valid target -> 201; no whois."""
    user_id = str(uuid7())
    token = mint_test_jwt(user_id)
    headers = {"Authorization": f"Bearer {token}"}

    # @ in target_handle -> 400
    r_at = await client.post(
        "/v1/account/contacts",
        headers=headers,
        json={"alias": "mycontact", "target_handle": "agent@agentmail"},
    )
    assert r_at.status_code == 400
    assert r_at.json()["error"]["code"] == "VALIDATION_ERROR"

    # Reserved target_handle -> 400
    r_res = await client.post(
        "/v1/account/contacts",
        headers=headers,
        json={"alias": "myadmin", "target_handle": "postmaster"},
    )
    assert r_res.status_code == 400
    assert r_res.json()["error"]["code"] == "VALIDATION_ERROR"

    # Nonexistent agent handle -> 201 (no liveness check on save)
    r_ok = await client.post(
        "/v1/account/contacts",
        headers=headers,
        json={"alias": "unregistered-friend", "target_handle": "not-registered-yet"},
    )
    assert r_ok.status_code == 201
    assert r_ok.json()["contact"]["target_handle"] == "not-registered-yet"


# ---------------------------------------------------------------------------
# Test 14: Ownership and Limits (§6.7, Test 14)
# ---------------------------------------------------------------------------


async def test_14_ownership_and_limits(client, db):
    """Test 14: User B cannot PATCH/DELETE user A's contact (404); am_live_ on contacts -> 401; 101st contact -> 400."""
    user_a = str(uuid7())
    user_b = str(uuid7())
    token_a = mint_test_jwt(user_a)
    token_b = mint_test_jwt(user_b)

    # User A creates contact
    r_post = await client.post(
        "/v1/account/contacts",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"alias": "alias-a", "target_handle": "target-a"},
    )
    contact_id = r_post.json()["contact"]["id"]

    # User B tries to PATCH user A's contact -> 404
    r_patch_b = await client.patch(
        f"/v1/account/contacts/{contact_id}",
        headers={"Authorization": f"Bearer {token_b}"},
        json={"note": "hacked"},
    )
    assert r_patch_b.status_code == 404
    assert r_patch_b.json()["error"]["code"] == "NOT_FOUND"

    # User B tries to DELETE user A's contact -> 404
    r_del_b = await client.delete(
        f"/v1/account/contacts/{contact_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert r_del_b.status_code == 404
    assert r_del_b.json()["error"]["code"] == "NOT_FOUND"

    # am_live_ key on /v1/account/contacts -> 401
    agent_key = generate_api_key()
    r_key = await client.get(
        "/v1/account/contacts",
        headers={"Authorization": f"Bearer {agent_key}"},
    )
    assert r_key.status_code == 401
    assert r_key.json()["error"]["code"] == "UNAUTHORIZED"

    # 100-contact cap: insert 99 more contacts for user A directly
    for i in range(1, 100):
        db.add(
            UserContact(
                id=str(uuid7()),
                owner_user_id=user_a,
                alias=f"alias-{i}",
                target_handle="target-h",
            )
        )
    await db.commit()

    # 101st contact -> 400 VALIDATION_ERROR
    r_101 = await client.post(
        "/v1/account/contacts",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"alias": "alias-over-cap", "target_handle": "target-h"},
    )
    assert r_101.status_code == 400
    assert r_101.json()["error"]["code"] == "VALIDATION_ERROR"
