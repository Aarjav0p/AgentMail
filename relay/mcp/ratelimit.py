"""In-memory sliding-window rate limits for MCP tool calls (§8.1).

Process-local by design: ``render.yaml`` pins ``--workers 1`` and the
vault is per-process anyway.  Limits reset on restart, which is an
accepted Phase 1 tradeoff for abuse control (the durable backstops are
the daily send cap and the per-recipient mailbox quota).
"""
from __future__ import annotations

import collections
import time

# (limit, window_seconds) per §8.1.
_GENERAL = (60, 60.0)  # tool calls / minute / agent
_SEND_MINUTE = (10, 60.0)  # send_message + reply / minute / agent
_SEND_DAY = (100, 86_400.0)  # send_message + reply / day / agent

# unlock_keychain failures: 5 failures per 15 min → 15-min lockout.
_UNLOCK_FAILURES = 5
_UNLOCK_WINDOW = 900.0
_UNLOCK_LOCKOUT = 900.0


class RateLimiter:
    """Sliding-window counter keyed by ``(agent_id, scope)``."""

    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], collections.deque[float]] = {}
        self._unlock_failures: dict[str, collections.deque[float]] = {}
        self._unlock_locked_until: dict[str, float] = {}

    # -- internals ---------------------------------------------------------

    def _hit(self, agent_id: str, scope: str, limit: int, window: float) -> int | None:
        """Record a hit. Returns ``retry_after`` seconds when over limit."""
        now = time.monotonic()
        key = (agent_id, scope)
        bucket = self._hits.setdefault(key, collections.deque())
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = int(window - (now - bucket[0])) + 1
            return max(retry_after, 1)
        bucket.append(now)
        return None

    # -- public API --------------------------------------------------------

    def check_general(self, agent_id: str) -> int | None:
        """60 tool calls / minute / agent."""
        return self._hit(agent_id, "general", *_GENERAL)

    def check_send(self, agent_id: str) -> int | None:
        """10 sends / minute and 100 sends / day / agent."""
        retry_after = self._hit(agent_id, "send:minute", *_SEND_MINUTE)
        if retry_after is None:
            retry_after = self._hit(agent_id, "send:day", *_SEND_DAY)
        return retry_after

    def unlock_retry_after(self, agent_id: str) -> int | None:
        """Seconds remaining on an unlock lockout, or ``None``."""
        locked_until = self._unlock_locked_until.get(agent_id)
        if locked_until is None:
            return None
        remaining = locked_until - time.monotonic()
        if remaining <= 0:
            del self._unlock_locked_until[agent_id]
            return None
        return int(remaining) + 1

    def record_unlock_failure(self, agent_id: str) -> None:
        """Count a failed unlock; engages the lockout at 5 in 15 min."""
        now = time.monotonic()
        bucket = self._unlock_failures.setdefault(agent_id, collections.deque())
        while bucket and now - bucket[0] > _UNLOCK_WINDOW:
            bucket.popleft()
        bucket.append(now)
        if len(bucket) >= _UNLOCK_FAILURES:
            bucket.clear()
            self._unlock_locked_until[agent_id] = now + _UNLOCK_LOCKOUT

    def clear_unlock_failures(self, agent_id: str) -> None:
        """Reset the failure counter after a successful unlock."""
        self._unlock_failures.pop(agent_id, None)
        self._unlock_locked_until.pop(agent_id, None)


# Module-level singleton — one limiter for the whole process.
limiter = RateLimiter()
