"""Ethical-use notice endpoints — the GUI's first-run gate (brief section 6.9)."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from vigia.api.deps import SessionDep
from vigia.ethics import ETHICS_NOTICE, accept, is_accepted

router = APIRouter(prefix="/ethics", tags=["ethics"])


class EthicsStatus(BaseModel):
    accepted: bool
    notice: str


@router.get("")
async def get_ethics_status(session: SessionDep) -> EthicsStatus:
    return EthicsStatus(accepted=await is_accepted(session), notice=ETHICS_NOTICE)


@router.post("/accept")
async def accept_ethics_notice(session: SessionDep) -> EthicsStatus:
    await accept(session)
    return EthicsStatus(accepted=True, notice=ETHICS_NOTICE)
