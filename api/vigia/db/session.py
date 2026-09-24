"""Async engine/session factory for the configured DATABASE_URL."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from vigia.config import get_settings


def make_engine(database_url: str | None = None) -> AsyncEngine:
    url = database_url or get_settings().database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_async_engine(url, connect_args=connect_args)


_engine = make_engine()
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession]:
    async with _session_factory() as session:
        yield session


@asynccontextmanager
async def session_scope() -> AsyncGenerator[AsyncSession]:
    """A plain async-context-manager session, for non-FastAPI callers (the CLI)."""
    async with _session_factory() as session:
        yield session
