"""Shared test fixtures.

DB-backed tests need ``TEST_DATABASE_URL`` (a Postgres URL with the
``postgresql+asyncpg://`` scheme); without it they skip cleanly so the
crypto/vault suites still run anywhere.
"""
from __future__ import annotations

import base64
import json
import os

import nacl.pwhash
import nacl.secret
import pytest
import pytest_asyncio
from nacl.public import PrivateKey
from nacl.signing import SigningKey
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from uuid_utils import uuid7

from relay.crypto.envelope import generate_api_key, generate_fingerprint, hash_api_key
from relay.models.schema import Agent, Base

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")

# Cheap-but-real Argon2id parameters for tests (8 MiB, 1 pass, 16-byte salt).
TEST_KDF = {"algo": "argon2id", "m": 8192, "t": 1, "p": 1}
TEST_PASSPHRASE = "correct horse battery staple"

requires_db = pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL not set")


# ---------------------------------------------------------------------------
# Crypto helpers — replicate exactly what the browser page does
# ---------------------------------------------------------------------------


def derive_test_key(passphrase: str, salt_b64: str) -> bytes:
    salt = base64.b64decode(salt_b64)
    return nacl.pwhash.argon2id.kdf(
        32,
        passphrase.encode("utf-8"),
        salt,
        opslimit=TEST_KDF["t"],
        memlimit=TEST_KDF["m"] * 1024,
    )


def make_key_blob(enc_sk: bytes, sign_seed: bytes, derived_key: bytes) -> str:
    """base64(nonce || secretbox({"epochs": [...]})) — the §4.2 blob."""
    blob = json.dumps(
        {"epochs": [{"epoch": 1, "enc_sk": enc_sk.hex(), "sign_sk": sign_seed.hex()}]}
    )
    box = nacl.secret.SecretBox(derived_key)
    return base64.b64encode(bytes(box.encrypt(blob.encode("utf-8")))).decode()


def build_registration(handle: str, passphrase: str = TEST_PASSPHRASE) -> dict:
    """A complete POST /v1/agents payload + the secrets behind it."""
    enc = PrivateKey.generate()
    sign = SigningKey.generate()
    salt_b64 = base64.b64encode(os.urandom(16)).decode()
    kdf_params = {**TEST_KDF, "salt_b64": salt_b64}
    derived = derive_test_key(passphrase, salt_b64)
    payload = {
        "handle": handle,
        "display_name": f"{handle} test agent",
        "enc_pub": enc.public_key.encode().hex(),
        "sign_pub": sign.verify_key.encode().hex(),
        "key_blob": make_key_blob(enc.encode(), sign.encode(), derived),
        "kdf_params": kdf_params,
    }
    return {
        "payload": payload,
        "passphrase": passphrase,
        "enc_sk": enc.encode(),
        "sign_seed": sign.encode(),
        "fingerprint": generate_fingerprint(payload["enc_pub"], payload["sign_pub"]),
    }


async def insert_agent(
    db: AsyncSession,
    handle: str,
    *,
    passphrase: str = TEST_PASSPHRASE,
    quota_bytes: int | None = None,
) -> tuple[Agent, str]:
    """Insert a live agent row directly (bypassing the REST route)."""
    reg = build_registration(handle, passphrase)
    api_key = generate_api_key()
    agent = Agent(
        id=str(uuid7()),
        handle=handle,
        display_name=reg["payload"]["display_name"],
        api_key_hash=hash_api_key(api_key),
        enc_pub=reg["payload"]["enc_pub"],
        sign_pub=reg["payload"]["sign_pub"],
        key_blob=reg["payload"]["key_blob"],
        kdf_params=reg["payload"]["kdf_params"],
    )
    if quota_bytes is not None:
        agent.quota_bytes = quota_bytes
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return agent, api_key


async def call_tool(
    db: AsyncSession,
    agent: Agent,
    name: str,
    passphrase: str | None = None,
    **kwargs,
):
    """Invoke a registered MCP tool wrapper with a bound request context.

    ``passphrase`` doubles as the simulated ``X-Agentmail-Passphrase``
    header (transparent auto-unlock) and, for ``unlock_keychain``, as the
    tool's own argument.  This exercises the real pipeline — rate limits,
    auto-unlock, piggyback, commit — not just the tool functions.
    """
    from relay.mcp.context import (
        MCPRequestContext,
        reset_request_context,
        set_request_context,
    )

    if name == "unlock_keychain" and "passphrase" not in kwargs:
        kwargs["passphrase"] = passphrase
    wrapper = _tool_wrappers()[name]
    token = set_request_context(
        MCPRequestContext(agent=agent, db=db, passphrase=passphrase)
    )
    try:
        return json.loads(await wrapper(**kwargs))
    finally:
        reset_request_context(token)


def _tool_wrappers() -> dict:
    from relay.mcp import server as mcp_module

    return {
        name.removeprefix("tool_"): obj
        for name, obj in vars(mcp_module).items()
        if name.startswith("tool_") and callable(obj)
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def engine():
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set")
    eng = create_async_engine(TEST_DATABASE_URL, poolclass=None)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine, monkeypatch):
    import relay.db as db_module

    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(db_module, "async_session", maker)
    monkeypatch.setattr(db_module, "engine", engine)
    async with maker() as session:
        yield session


@pytest_asyncio.fixture
async def client(db):
    from httpx import ASGITransport, AsyncClient

    from relay.app import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http
