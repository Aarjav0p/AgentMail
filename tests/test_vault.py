"""KeyVault tests — in-memory, no database required."""

from __future__ import annotations

import datetime
import os

from relay.crypto.vault import KeyVault

ENC_SK = os.urandom(32)
SIGN_SK = os.urandom(64)


async def unlock(vault: KeyVault, agent_id: str) -> None:
    await vault.unlock(
        agent_id,
        enc_sk=ENC_SK,
        sign_sk=SIGN_SK,
        enc_pub=b"e" * 32,
        sign_pub=b"s" * 32,
    )


async def test_unlock_get_and_is_unlocked():
    vault = KeyVault(ttl_minutes=15, max_entries=10)
    assert await vault.is_unlocked("a") is False
    assert await vault.get("a") is None

    await unlock(vault, "a")
    entry = await vault.get("a")
    assert entry is not None
    assert bytes(entry.enc_sk) == ENC_SK
    assert bytes(entry.sign_sk) == SIGN_SK
    assert await vault.is_unlocked("a") is True


async def test_lock_zeroes_and_removes():
    vault = KeyVault(ttl_minutes=15, max_entries=10)
    await unlock(vault, "a")
    entry = await vault.get("a")
    assert entry is not None

    await vault.lock("a")
    assert entry.enc_sk == bytearray(len(ENC_SK))  # zeroed
    assert entry.sign_sk == bytearray(len(SIGN_SK))
    assert await vault.get("a") is None
    assert await vault.lock("nonexistent") is None  # idempotent


async def test_idle_expiry_on_access():
    vault = KeyVault(ttl_minutes=15, max_entries=10)
    await unlock(vault, "a")
    entry = vault._store["a"]
    entry.last_used -= datetime.timedelta(minutes=16)

    assert await vault.get("a") is None  # expired lazily
    assert entry.enc_sk == bytearray(len(ENC_SK))  # zeroed on purge


async def test_auto_lock_at_reports_deadline():
    vault = KeyVault(ttl_minutes=15, max_entries=10)
    assert await vault.auto_lock_at("a") is None

    await unlock(vault, "a")
    deadline = await vault.auto_lock_at("a")
    assert deadline is not None
    delta = deadline - datetime.datetime.now(datetime.UTC)
    assert datetime.timedelta(minutes=14) < delta <= datetime.timedelta(minutes=15)


async def test_purge_expired_removes_only_stale_entries():
    vault = KeyVault(ttl_minutes=15, max_entries=10)
    await unlock(vault, "stale")
    await unlock(vault, "fresh")
    vault._store["stale"].last_used -= datetime.timedelta(minutes=16)

    assert await vault.purge_expired() == 1
    assert await vault.is_unlocked("fresh") is True
    assert await vault.is_unlocked("stale") is False
    assert await vault.purge_expired() == 0


async def test_lru_eviction_at_capacity():
    vault = KeyVault(ttl_minutes=15, max_entries=2)
    await unlock(vault, "a")
    await unlock(vault, "b")
    await vault.get("a")  # touch "a" → "b" becomes LRU
    await unlock(vault, "c")  # evicts "b"

    assert await vault.is_unlocked("a") is True
    assert await vault.is_unlocked("c") is True
    assert await vault.is_unlocked("b") is False
    assert vault.size == 2


async def test_reunlock_zeroes_previous_entry():
    vault = KeyVault(ttl_minutes=15, max_entries=10)
    await unlock(vault, "a")
    old_entry = vault._store["a"]
    await unlock(vault, "a")
    assert old_entry.enc_sk == bytearray(len(ENC_SK))
    assert vault.size == 1
