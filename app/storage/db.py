"""Database engine + session factory.

SQLite for Phase 1, via async SQLAlchemy. The repository layer (see repository.py)
is what callers actually use, so swapping SQLite for Postgres later means changing
`get_engine()`'s connection string — nothing else in the app touches this module
directly except through the repository.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.storage.models import Base


def get_engine(storage_path: str) -> AsyncEngine:
    return create_async_engine(f"sqlite+aiosqlite:///{storage_path}", echo=False)


async def init_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def make_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@asynccontextmanager
async def session_scope(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
