"""Async database engine and session factory for Neon Postgres."""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from relay.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,       # handle Neon cold-resume transparently
    pool_size=5,               # small pool — single worker, bursty traffic
    max_overflow=5,
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields an async session, auto-commits on success."""
    async with async_session() as session, session.begin():
        yield session
