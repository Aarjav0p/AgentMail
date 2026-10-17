"""Admin endpoints — TTL sweeper (``POST /v1/admin/purge``)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from relay.config import settings
from relay.db import get_db
from relay.models.schema import AuditLog, Message

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


@router.post("/admin/purge")
async def purge(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Run the TTL sweep.

    * Delete messages whose ``expires_at`` has passed.
    * Delete messages read longer than ``read_ttl_days`` ago.
    * Trim ``audit_log`` entries older than 90 days.

    Protected by ``X-Admin-Token``.
    """
    _require_admin_token(request)

    read_ttl = settings.read_ttl_days

    # 1. Expired messages.
    result_expired = await db.execute(
        delete(Message).where(Message.expires_at < func.now())
    )
    purged_expired: int = result_expired.rowcount  # type: ignore[assignment]

    # 2. Read messages past read-TTL.
    result_read = await db.execute(
        delete(Message).where(
            Message.read_at.is_not(None),
            Message.read_at < func.now() - text(f"interval '{read_ttl} days'"),
        )
    )
    purged_read: int = result_read.rowcount  # type: ignore[assignment]

    total_purged_messages = purged_expired + purged_read

    # 3. Trim audit log (90 days).
    result_audit = await db.execute(
        delete(AuditLog).where(
            AuditLog.created_at < func.now() - text("interval '90 days'"),
        )
    )
    purged_audit: int = result_audit.rowcount  # type: ignore[assignment]

    # Audit the purge itself.
    db.add(
        AuditLog(
            event="purge",
            ip=request.client.host if request.client else None,
        )
    )

    return {
        "purged_messages": total_purged_messages,
        "purged_audit": purged_audit,
    }
