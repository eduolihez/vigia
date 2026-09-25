"""Runtime-editable settings (brief Phase 6 Settings UI): model choice and scan
budgets can be overridden without restarting the process, stored in the `Setting`
key/value table (same pattern as `vigia/ethics.py`). API keys are stored encrypted
in the `ApiKey` table (`vigia/crypto.py`) rather than as plaintext `.env` values —
`GET /settings` only ever reports whether one is configured, never its value.

`build_effective_config` is what scan creation and report generation actually use:
it returns a full `Settings` copy with every override/decrypted key applied, so the
rest of the codebase (`tool_router.py`, `pipeline.py`, `orchestrator.py`) keeps
reading plain `Settings` attributes and doesn't need to know overrides exist.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col

from vigia.config import Settings
from vigia.crypto import decrypt, encrypt
from vigia.db.models import ApiKey, Setting

_OVERRIDE_PREFIX = "override."
API_KEY_SOURCES = ("censys_api_id", "censys_api_secret", "github_token", "hibp_api_key")


@dataclass
class EffectiveSettings:
    planner_model: str
    extractor_model: str
    scan_max_steps: int
    scan_max_minutes: int
    scan_max_deep_dives: int
    configured_api_keys: dict[str, bool]


async def _get_override(session: AsyncSession, key: str) -> str | None:
    result = await session.execute(
        select(Setting).where(col(Setting.key) == f"{_OVERRIDE_PREFIX}{key}")
    )
    row = result.scalar_one_or_none()
    return row.value if row is not None else None


async def _set_override(session: AsyncSession, key: str, value: str | None) -> None:
    full_key = f"{_OVERRIDE_PREFIX}{key}"
    result = await session.execute(select(Setting).where(col(Setting.key) == full_key))
    row = result.scalar_one_or_none()
    if value is None:
        if row is not None:
            await session.delete(row)
        return
    if row is None:
        session.add(Setting(key=full_key, value=value))
    else:
        row.value = value
        session.add(row)


async def get_effective_settings(session: AsyncSession, defaults: Settings) -> EffectiveSettings:
    planner = await _get_override(session, "planner_model") or defaults.planner_model
    extractor = await _get_override(session, "extractor_model") or defaults.extractor_model
    max_steps_raw = await _get_override(session, "scan_max_steps")
    max_minutes_raw = await _get_override(session, "scan_max_minutes")
    max_deep_dives_raw = await _get_override(session, "scan_max_deep_dives")

    result = await session.execute(select(ApiKey))
    configured = {row.source for row in result.scalars().all()}

    return EffectiveSettings(
        planner_model=planner,
        extractor_model=extractor,
        scan_max_steps=int(max_steps_raw) if max_steps_raw else defaults.scan_max_steps,
        scan_max_minutes=int(max_minutes_raw) if max_minutes_raw else defaults.scan_max_minutes,
        scan_max_deep_dives=(
            int(max_deep_dives_raw) if max_deep_dives_raw else defaults.scan_max_deep_dives
        ),
        configured_api_keys={source: source in configured for source in API_KEY_SOURCES},
    )


async def update_overrides(
    session: AsyncSession,
    *,
    planner_model: str | None = None,
    extractor_model: str | None = None,
    scan_max_steps: int | None = None,
    scan_max_minutes: int | None = None,
    scan_max_deep_dives: int | None = None,
) -> None:
    """Each `None` parameter leaves that override untouched; an empty string clears
    it back to the `.env`/default value."""
    if planner_model is not None:
        await _set_override(session, "planner_model", planner_model or None)
    if extractor_model is not None:
        await _set_override(session, "extractor_model", extractor_model or None)
    if scan_max_steps is not None:
        await _set_override(session, "scan_max_steps", str(scan_max_steps))
    if scan_max_minutes is not None:
        await _set_override(session, "scan_max_minutes", str(scan_max_minutes))
    if scan_max_deep_dives is not None:
        await _set_override(session, "scan_max_deep_dives", str(scan_max_deep_dives))
    await session.commit()


async def set_api_key(
    session: AsyncSession, secret_key: str, source: str, value: str | None
) -> None:
    if source not in API_KEY_SOURCES:
        raise ValueError(f"Unknown API key source: {source!r}")
    result = await session.execute(select(ApiKey).where(col(ApiKey.source) == source))
    row = result.scalar_one_or_none()
    if not value:
        if row is not None:
            await session.delete(row)
        await session.commit()
        return
    encrypted = encrypt(secret_key, value)
    if row is None:
        session.add(ApiKey(source=source, encrypted_value=encrypted))
    else:
        row.encrypted_value = encrypted
        session.add(row)
    await session.commit()


async def get_api_key(session: AsyncSession, secret_key: str, source: str) -> str | None:
    result = await session.execute(select(ApiKey).where(col(ApiKey.source) == source))
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return decrypt(secret_key, row.encrypted_value)


async def build_effective_config(session: AsyncSession, defaults: Settings) -> Settings:
    """A full `Settings` copy with every stored override/decrypted API key applied —
    what scan creation (`POST /scans`) and report generation actually pass down."""
    effective = await get_effective_settings(session, defaults)
    secret = defaults.secret_key
    censys_api_id = await get_api_key(session, secret, "censys_api_id") or defaults.censys_api_id
    censys_api_secret = (
        await get_api_key(session, secret, "censys_api_secret") or defaults.censys_api_secret
    )
    github_token = await get_api_key(session, secret, "github_token") or defaults.github_token
    hibp_api_key = await get_api_key(session, secret, "hibp_api_key") or defaults.hibp_api_key

    return defaults.model_copy(
        update={
            "planner_model": effective.planner_model,
            "extractor_model": effective.extractor_model,
            "scan_max_steps": effective.scan_max_steps,
            "scan_max_minutes": effective.scan_max_minutes,
            "scan_max_deep_dives": effective.scan_max_deep_dives,
            "censys_api_id": censys_api_id,
            "censys_api_secret": censys_api_secret,
            "github_token": github_token,
            "hibp_api_key": hibp_api_key,
        }
    )
