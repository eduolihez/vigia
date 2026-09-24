from sqlalchemy import select
from sqlmodel import col

from vigia.db.models import Asset, AssetType, Scan, ScanMode, ScanStatus
from vigia.db.session import _session_factory


async def test_scan_and_asset_roundtrip() -> None:
    async with _session_factory() as session:
        scan = Scan(
            domain="example.com",
            mode=ScanMode.PASSIVE,
            planner_model="qwen3.6:35b",
            extractor_model="granite4.1:8b",
            status=ScanStatus.PENDING,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        asset = Asset(scan_id=scan.id, type=AssetType.DOMAIN, value="example.com")
        session.add(asset)
        await session.commit()

        result = await session.execute(select(Asset).where(col(Asset.scan_id) == scan.id))
        assets = result.scalars().all()

    assert len(assets) == 1
    assert assets[0].value == "example.com"
