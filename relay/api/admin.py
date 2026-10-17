"""Admin endpoints — TTL sweeper (``POST /v1/admin/purge``)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from relay.config import settings
from relay.db import get_db
from relay.models.schema import AuditLog

router = APIRouter(prefix="/v1")


def _require_admin_token(request: Request) -> None:
    """Validate the ``X-Admin-Token`` header against the configured secret.

    Raises:
        HTTPException 403: token missing or does not match.
    """
    token = request.headers.get("x-admin-token", "")
    if not token or token != settings.admin_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin token.",
        )


async def run_purge(
    db: AsyncSession,
    *,
    read_ttl_days: int | None = None,
    client_ip: str | None = None,
) -> dict[str, int]:
    """Execute the TTL sweep for messages and audit log entries (RETENTION-01).

    * Unread messages: purged only when ``expires_at < now()`` (30 days from creation).
    * Read messages: judged solely by time-of-reading (``read_at < now() - read_ttl_days``).
    * Trim audit_log entries older than 90 days.
    """
    if read_ttl_days is None:
        read_ttl_days = settings.read_ttl_days

    # Restructured two-branch sweep (Step 3 / §2 fix).
    # Parameterized with make_interval to avoid hardcoded strings.
    result_messages = await db.execute(
        text("""
            DELETE FROM messages
            WHERE (read_at IS NULL AND expires_at < now())
               OR (read_at IS NOT NULL AND read_at < now() - make_interval(days => :read_ttl))
        """),
        {"read_ttl": read_ttl_days},
    )
    purged_messages: int = result_messages.rowcount or 0

    # Trim audit log (90 days).
    result_audit = await db.execute(
        text("DELETE FROM audit_log WHERE created_at < now() - interval '90 days'")
    )
    purged_audit: int = result_audit.rowcount or 0

    # Audit the purge itself with deleted_count (Step 5).
    ip_detail = f"deleted_count={purged_messages}"
    if client_ip:
        ip_detail = f"{client_ip} | {ip_detail}"

    db.add(
        AuditLog(
            event="purge",
            ip=ip_detail,
        )
    )
    await db.commit()

    return {
        "purged_messages": purged_messages,
        "purged_audit": purged_audit,
    }


@router.post("/admin/purge")
async def purge(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    """Run the TTL sweep.

    Protected by ``X-Admin-Token``.
    """
    _require_admin_token(request)
    client_ip = request.client.host if request.client else None
    return await run_purge(db, client_ip=client_ip)
