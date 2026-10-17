"""Reserved handle list (§6.6).

These handles cannot be registered via anonymous registration or dashboard
provisioning, and cannot be used as contact targets.
"""

from __future__ import annotations

RESERVED_HANDLES: frozenset[str] = frozenset(
    {
        "admin",
        "root",
        "support",
        "postmaster",
        "security",
        "abuse",
        "noreply",
        "no-reply",
        "mail",
        "agentmail",
        "system",
        "api",
        "help",
        "info",
        "billing",
    }
)


def is_reserved_handle(handle: str) -> bool:
    """Return True if handle matches any reserved handle (case-insensitive)."""
    return handle.strip().lower() in RESERVED_HANDLES
