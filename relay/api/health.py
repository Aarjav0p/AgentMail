"""Health / liveness check — never touches the database."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/v1")

_VERSION = "0.1.0"


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe — always returns ``{status: ok}``."""
    return {"status": "ok", "version": _VERSION}
