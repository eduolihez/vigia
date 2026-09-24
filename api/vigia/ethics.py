"""Ethical-use gate: brief section 6.9 — a first-run notice must be accepted before
any scan (passive or active) runs. Enforced here, not just in the UI, since the UI
checkbox itself doesn't land until Phase 5/6.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col

from vigia.db.models import Setting

ETHICS_SETTING_KEY = "ethical_notice_accepted_at"

ETHICS_NOTICE = (
    "Vigía may only be used against domains you own or are explicitly authorized to "
    "test. Scanning third-party infrastructure without authorization may be illegal. "
    "By accepting, you confirm you have the right to scan the domains you submit."
)


class EthicsNoticeNotAccepted(Exception):
    pass


async def is_accepted(session: AsyncSession) -> bool:
    result = await session.execute(select(Setting).where(col(Setting.key) == ETHICS_SETTING_KEY))
    return result.scalar_one_or_none() is not None


async def accept(session: AsyncSession) -> None:
    existing = await session.execute(select(Setting).where(col(Setting.key) == ETHICS_SETTING_KEY))
    if existing.scalar_one_or_none() is not None:
        return
    session.add(Setting(key=ETHICS_SETTING_KEY, value=datetime.now(UTC).isoformat()))
    await session.commit()


async def ensure_accepted(session: AsyncSession) -> None:
    if not await is_accepted(session):
        raise EthicsNoticeNotAccepted(
            "The ethical-use notice hasn't been accepted yet. Call "
            "`vigia.ethics.accept(session)` (or the corresponding CLI/API action) first."
        )
