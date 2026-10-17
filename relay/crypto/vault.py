"""In-memory vault for unlocked agent cryptographic keys.

Keys are cached after the agent unlocks (authenticates) and automatically
purged after an idle TTL.  LRU eviction keeps memory bounded.  All secret
material is zeroed before eviction.
"""
from __future__ import annotations

import asyncio
import collections
import datetime
from dataclasses import dataclass, field

from relay.config import settings


@dataclass
class VaultEntry:
    """A single set of unlocked keys for one agent."""

    enc_sk: bytearray
    sign_sk: bytearray
    enc_pub: bytes
    sign_pub: bytes
    last_used: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(datetime.UTC))
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def _zero_entry(entry: VaultEntry) -> None:
    """Overwrite secret key bytes with zeros before discarding."""
    for i in range(len(entry.enc_sk)):
        entry.enc_sk[i] = 0
    for i in range(len(entry.sign_sk)):
        entry.sign_sk[i] = 0


class KeyVault:
    """Thread-safe (asyncio) in-memory vault with idle TTL and LRU eviction.

    Parameters are sourced from :pydata:`relay.config.settings`:
    * ``vault_ttl_minutes`` — idle timeout before automatic lock (default 15).
    * ``vault_max_entries`` — maximum cached entries before LRU eviction.
    """

    def __init__(
        self,
        ttl_minutes: int | None = None,
        max_entries: int | None = None,
    ) -> None:
        self._ttl = datetime.timedelta(minutes=ttl_minutes or settings.vault_ttl_minutes)
        self._max = max_entries or settings.vault_max_entries
        # Ordered dict keeps insertion order — we maintain LRU by
        # moving accessed entries to the end.
        self._store: collections.OrderedDict[str, VaultEntry] = collections.OrderedDict()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def unlock(
        self,
        agent_id: str,
        enc_sk: bytes,
        sign_sk: bytes,
        enc_pub: bytes,
        sign_pub: bytes,
    ) -> None:
        """Store (or refresh) unlocked keys for *agent_id*.

        If the vault is already at capacity, the least-recently-used entry is
        evicted and its keys zeroed.
        """
        async with self._lock:
            # If already present, zero old keys first.
            if agent_id in self._store:
                _zero_entry(self._store.pop(agent_id))

            # Evict LRU if at capacity.
            while len(self._store) >= self._max:
                oldest_id = next(iter(self._store))
                _zero_entry(self._store.pop(oldest_id))

            self._store[agent_id] = VaultEntry(
                enc_sk=bytearray(enc_sk),
                sign_sk=bytearray(sign_sk),
                enc_pub=enc_pub,
                sign_pub=sign_pub,
            )

    async def get(self, agent_id: str) -> VaultEntry | None:
        """Return the vault entry if present *and* not expired, else ``None``.

        A successful lookup refreshes ``last_used`` and moves the entry to
        the end of the LRU queue.
        """
        async with self._lock:
            entry = self._store.get(agent_id)
            if entry is None:
                return None

            now = datetime.datetime.now(datetime.UTC)
            if now - entry.last_used > self._ttl:
                # Expired — zero and remove.
                _zero_entry(self._store.pop(agent_id))
                return None

            # Refresh last_used and move to end (most-recently-used).
            entry.last_used = now
            self._store.move_to_end(agent_id)
            return entry

    async def lock(self, agent_id: str) -> None:
        """Explicitly remove an agent's keys, zeroing secret material."""
        async with self._lock:
            entry = self._store.pop(agent_id, None)
            if entry is not None:
                _zero_entry(entry)

    async def is_unlocked(self, agent_id: str) -> bool:
        """Return ``True`` if *agent_id* has a non-expired entry."""
        return (await self.get(agent_id)) is not None

    async def auto_lock_at(self, agent_id: str) -> datetime.datetime | None:
        """Return the timestamp at which *agent_id* will be auto-locked.

        Returns ``None`` when the agent is not currently unlocked.
        """
        async with self._lock:
            entry = self._store.get(agent_id)
            if entry is None:
                return None
            deadline = entry.last_used + self._ttl
            if deadline <= datetime.datetime.now(datetime.UTC):
                # Already expired — clean up.
                _zero_entry(self._store.pop(agent_id))
                return None
            return deadline

    async def purge_expired(self) -> int:
        """Remove all expired entries, zeroing their keys.

        Returns the number of entries purged.  Intended to be called
        periodically from a background task.
        """
        async with self._lock:
            now = datetime.datetime.now(datetime.UTC)
            expired_ids = [
                aid
                for aid, entry in self._store.items()
                if now - entry.last_used > self._ttl
            ]
            for aid in expired_ids:
                _zero_entry(self._store.pop(aid))
            return len(expired_ids)

    # ------------------------------------------------------------------
    # Introspection helpers (non-private for testing / admin endpoints)
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Current number of cached entries (not locked — for metrics only)."""
        return len(self._store)


# Module-level singleton used by the rest of the relay.
vault = KeyVault()
