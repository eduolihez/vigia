"""Async engine/session factory for the configured DATABASE_URL.

SQLite is opened in WAL mode (brief section 1: "SQLite by default (WAL)") with a
busy timeout: WAL lets readers and a writer proceed concurrently instead of
SQLite's default single-writer-blocks-everyone behavior, and the busy timeout makes
a second writer wait briefly for the first to finish instead of failing immediately
with "database is locked" — which is exactly what happened in manual testing with
one background scan task and one API request both writing at once.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from vigia.config import get_settings

SQLITE_BUSY_TIMEOUT_MS = 5000


def make_engine(database_url: str | None = None) -> AsyncEngine:
    url = database_url or get_settings().database_url
    is_sqlite = url.startswith("sqlite")
    connect_args = {"check_same_thread": False} if is_sqlite else {}
    engine = create_async_engine(url, connect_args=connect_args)

    if is_sqlite:

        @event.listens_for(engine.sync_engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection: object, _: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
            cursor.close()

    return engine


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
