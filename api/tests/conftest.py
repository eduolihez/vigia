"""Test-wide fixtures. Sets an isolated SQLite DB before any `vigia` module is imported."""

import asyncio
import contextlib
import os
from collections.abc import AsyncGenerator
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_vigia.db")
os.environ.setdefault("VIGIA_SECRET_KEY", "test-secret-key")

import pytest
from sqlmodel import SQLModel

from vigia.db import session as db_session

TEST_DB_PATH = Path("test_vigia.db")


@pytest.fixture(autouse=True, scope="session")
async def _prepare_database() -> AsyncGenerator[None]:
    async with db_session._engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    await db_session._engine.dispose()
    with contextlib.suppress(OSError):
        await asyncio.to_thread(TEST_DB_PATH.unlink, missing_ok=True)
