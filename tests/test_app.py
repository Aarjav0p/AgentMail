"""REST surface tests (§4): register, whois, reissue, admin, health, page."""
from __future__ import annotations

import base64

import pytest
from nacl.signing import SigningKey

from relay.config import settings
from tests.conftest import build_registration, requires_db

pytestmark = requires_db


@pytest.fixture(autouse=True)
def _disable_rest_rate_limits():
    """slowapi counts per client IP — tests share one, so switch it off."""
    from relay.ratelimit import limiter

    limiter.enabled = False
    yield
    limiter.enabled = True


async def test_health(client):
    r = await client.get("/v1/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "version": "0.1.0"}


async def test_register_page_served(client):
    r = await client.get("/register")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "agentmail" in r.text
    assert "/static/vendor/sodium.mjs" in r.text


async def test_vendored_crypto_bundles_served(client):
    for name, min_bytes in (("sodium.mjs", 100_000), ("argon2.mjs", 10_000)):
        r = await client.get(f"/static/vendor/{name}")
        assert r.status_code == 200, name
        assert len(r.content) > min_bytes, name


async def test_register_then_whois_round_trip(client):
    reg = build_registration("alice-rest")
    r = await client.post("/v1/agents", json=reg["payload"])
    assert r.status_code == 201, r.text

    body = r.json()
    api_key = body["api_key"]
    assert api_key.startswith("am_live_") and len(api_key) == 51
    assert body["agent"]["handle"] == "alice-rest"
    assert body["agent"]["address"] == "alice-rest@agentmail"
    assert body["agent"]["fingerprint"] == reg["fingerprint"]

    r2 = await client.get("/v1/agents/alice-rest")
    assert r2.status_code == 200
    whois = r2.json()
    assert whois["enc_pub"] == reg["payload"]["enc_pub"]
    assert whois["sign_pub"] == reg["payload"]["sign_pub"]
    assert whois["fingerprint"] == reg["fingerprint"]
    assert whois["display_name"] == "alice-rest test agent"


async def test_register_rejects_bad_input(client):
    reg = build_registration("carol-rest")

    dup = {**reg["payload"]}
    assert (await client.post("/v1/agents", json=dup)).status_code == 201
    assert (await client.post("/v1/agents", json=dup)).status_code == 409

    bad_handle = build_registration("dave-rest")["payload"]
    bad_handle["handle"] = "Not Valid!"
    assert (await client.post("/v1/agents", json=bad_handle)).status_code == 422

    bad_key = build_registration("erin-rest")["payload"]
    bad_key["enc_pub"] = "ab" * 31  # 31 bytes, not 32
    assert (await client.post("/v1/agents", json=bad_key)).status_code == 422

    bad_kdf = build_registration("frank-rest")["payload"]
    bad_kdf["kdf_params"] = {**bad_kdf["kdf_params"], "m": 100}  # below floor
    assert (await client.post("/v1/agents", json=bad_kdf)).status_code == 422

    assert (await client.get("/v1/agents/ghost-handle")).status_code == 404


async def test_reissue_challenge_response_flow(client):
    reg = build_registration("grace-rest")
    r = await client.post("/v1/agents", json=reg["payload"])
    assert r.status_code == 201
    old_key = r.json()["api_key"]

    # No challenge requested yet → 400.
    assert (
        await client.post(
            "/v1/agents/grace-rest/reissue", json={"challenge_response": "AAAA"}
        )
    ).status_code == 400

    ch = await client.post("/v1/agents/grace-rest/reissue/challenge")
    assert ch.status_code == 200
    challenge = base64.b64decode(ch.json()["challenge"])
    assert ch.json()["key_blob"] == reg["payload"]["key_blob"]
    assert ch.json()["kdf_params"] == reg["payload"]["kdf_params"]

    # Wrong signature → 400.
    bad_sig = base64.b64encode(b"\x00" * 64).decode()
    assert (
        await client.post(
            "/v1/agents/grace-rest/reissue", json={"challenge_response": bad_sig}
        )
    ).status_code == 400

    # Correct signature → new key.
    signing_key = SigningKey(reg["sign_seed"])
    sig = base64.b64encode(signing_key.sign(challenge).signature).decode()
    ok = await client.post(
        "/v1/agents/grace-rest/reissue", json={"challenge_response": sig}
    )
    assert ok.status_code == 200, ok.text
    new_key = ok.json()["api_key"]
    assert new_key != old_key
    assert ok.json()["address"] == "grace-rest@agentmail"

    # Challenge is single-use.
    assert (
        await client.post(
            "/v1/agents/grace-rest/reissue", json={"challenge_response": sig}
        )
    ).status_code == 400


async def test_admin_purge_requires_token(client, monkeypatch):
    r = await client.post("/v1/admin/purge")
    assert r.status_code == 403

    r = await client.post("/v1/admin/purge", headers={"X-Admin-Token": "nope"})
    assert r.status_code == 403

    monkeypatch.setattr(settings, "admin_token", "sekrit")
    r = await client.post("/v1/admin/purge", headers={"X-Admin-Token": "sekrit"})
    assert r.status_code == 200
    assert r.json() == {"purged_messages": 0, "purged_audit": 0}
