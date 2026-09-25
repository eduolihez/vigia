"""Settings endpoints (Phase 6): runtime-editable model choice, scan budgets, and
encrypted API keys. See `vigia/settings_store.py` for where these actually live —
this module is just the HTTP shape around it.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from vigia.api.deps import SessionDep
from vigia.config import get_settings
from vigia.settings_store import (
    API_KEY_SOURCES,
    get_effective_settings,
    set_api_key,
    update_overrides,
)

router = APIRouter(prefix="/settings", tags=["settings"])


class SettingsOut(BaseModel):
    planner_model: str
    extractor_model: str
    scan_max_steps: int
    scan_max_minutes: int
    scan_max_deep_dives: int
    configured_api_keys: dict[str, bool]


class SettingsUpdate(BaseModel):
    planner_model: str | None = None
    extractor_model: str | None = None
    scan_max_steps: int | None = None
    scan_max_minutes: int | None = None
    scan_max_deep_dives: int | None = None
    api_keys: dict[str, str] | None = None
    """Maps API key source name (see `API_KEY_SOURCES`) to its new value; an empty
    string clears that key. Unknown source names are ignored."""


async def _read(session: AsyncSession) -> SettingsOut:
    effective = await get_effective_settings(session, get_settings())
    return SettingsOut(
        planner_model=effective.planner_model,
        extractor_model=effective.extractor_model,
        scan_max_steps=effective.scan_max_steps,
        scan_max_minutes=effective.scan_max_minutes,
        scan_max_deep_dives=effective.scan_max_deep_dives,
        configured_api_keys=effective.configured_api_keys,
    )


@router.get("")
async def read_settings(session: SessionDep) -> SettingsOut:
    return await _read(session)


@router.put("")
async def update_settings(request: SettingsUpdate, session: SessionDep) -> SettingsOut:
    await update_overrides(
        session,
        planner_model=request.planner_model,
        extractor_model=request.extractor_model,
        scan_max_steps=request.scan_max_steps,
        scan_max_minutes=request.scan_max_minutes,
        scan_max_deep_dives=request.scan_max_deep_dives,
    )
    if request.api_keys:
        secret = get_settings().secret_key
        for source, value in request.api_keys.items():
            if source in API_KEY_SOURCES:
                await set_api_key(session, secret, source, value)
    return await _read(session)
