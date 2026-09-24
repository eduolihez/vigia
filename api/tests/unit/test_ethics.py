import pytest
from sqlalchemy import delete
from sqlmodel import col

from vigia.db.models import Setting
from vigia.db.session import _session_factory
from vigia.ethics import (
    ETHICS_SETTING_KEY,
    EthicsNoticeNotAccepted,
    accept,
    ensure_accepted,
    is_accepted,
)


async def _reset() -> None:
    """Other test modules share this DB and may have already accepted the notice —
    clear it so these tests don't depend on collection order."""
    async with _session_factory() as session:
        await session.execute(delete(Setting).where(col(Setting.key) == ETHICS_SETTING_KEY))
        await session.commit()


async def test_notice_not_accepted_by_default() -> None:
    await _reset()
    async with _session_factory() as session:
        assert await is_accepted(session) is False
        with pytest.raises(EthicsNoticeNotAccepted):
            await ensure_accepted(session)


async def test_accept_persists_and_is_idempotent() -> None:
    await _reset()
    async with _session_factory() as session:
        await accept(session)
        assert await is_accepted(session) is True
        await ensure_accepted(session)  # does not raise

        await accept(session)  # calling again is a no-op, not an error
        assert await is_accepted(session) is True
