"""Contact-alias resolution and inbound annotation for MCP (ALIAS-01).

Maps short personal contact names (e.g. "dad") to addresses (e.g. "dadagent@agentmail")
at send time, and annotates inbound messages with from_alias.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession

from relay.config import settings

logger = logging.getLogger("agentmail.contacts")

_missing_table_warned: bool = False


def reset_missing_table_warned() -> None:
    """Reset the missing table warning flag (useful for tests)."""
    global _missing_table_warned
    _missing_table_warned = False


async def find_contact_alias(
    db: AsyncSession,
    owner_user_id: str | None,
    raw_to: str,
) -> tuple[str, str | None]:
    """Resolve a recipient input against the owner's contacts address book.

    Semantics (§1-§2):
    - Bare names only: if raw_to contains '@', bypass the book.
    - Legacy / anonymous agents (owner_user_id is None): bypass the book.
    - Aliases shadow live handles: user's stated contact takes precedence.
    - Miss falls through to normal handle resolution.
    - Missing user_contacts table degrades gracefully to no aliases.

    Returns:
        (effective_to, resolved_alias):
        - If matched: (target_handle, alias)
        - Otherwise: (raw_to, None)
    """
    global _missing_table_warned
    if not owner_user_id or "@" in raw_to:
        return raw_to, None

    alias = raw_to.strip().lower()
    try:
        result = await db.execute(
            text(
                "SELECT target_handle FROM user_contacts "
                "WHERE owner_user_id = :owner AND alias = :alias LIMIT 1"
            ),
            {"owner": owner_user_id, "alias": alias},
        )
        row = result.fetchone()
        if row is not None:
            return row[0], alias
        return raw_to, None
    except (ProgrammingError, DBAPIError) as exc:
        if not _missing_table_warned:
            logger.warning("user_contacts table does not exist; alias resolution degraded: %s", exc)
            _missing_table_warned = True
        return raw_to, None


async def load_alias_map(
    db: AsyncSession,
    owner_user_id: str | None,
) -> dict[str, str]:
    """Load map of {"<handle>@<domain>": "<alias>"} for an owner's contacts.

    Used by check_inbox and read_message to annotate incoming mail with from_alias.
    """
    global _missing_table_warned
    if not owner_user_id:
        return {}

    try:
        result = await db.execute(
            text("SELECT target_handle, alias FROM user_contacts WHERE owner_user_id = :owner"),
            {"owner": owner_user_id},
        )
        rows: list[Any] = result.fetchall()
        alias_map: dict[str, str] = {}
        for target_handle, alias in rows:
            address = f"{target_handle}@{settings.relay_domain}"
            alias_map[address] = alias
        return alias_map
    except (ProgrammingError, DBAPIError) as exc:
        if not _missing_table_warned:
            logger.warning("user_contacts table does not exist; alias resolution degraded: %s", exc)
            _missing_table_warned = True
        return {}
