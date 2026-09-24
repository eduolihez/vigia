from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from vigia.api.main import app
from vigia.db.models import Scan, ScanMode, ScanStatus, ToolCall, ToolCallStatus
from vigia.db.session import _session_factory


async def test_audit_export_404_for_unknown_scan() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/scans/does-not-exist/audit")
    assert response.status_code == 404


async def test_audit_export_returns_tool_calls() -> None:
    async with _session_factory() as session:
        scan = Scan(
            domain="example.com",
            mode=ScanMode.PASSIVE,
            planner_model="fake",
            extractor_model="fake",
            status=ScanStatus.COMPLETED,
        )
        session.add(scan)
        await session.flush()
        session.add(
            ToolCall(
                scan_id=scan.id,
                phase="enumerate",
                tool="ct_subdomains",
                args={"domain": "example.com"},
                reason="test",
                status=ToolCallStatus.SUCCESS,
                duration_ms=42,
                result_sha256="abc123",
            )
        )
        await session.commit()
        scan_id = scan.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/scans/{scan_id}/audit")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["tool"] == "ct_subdomains"
    assert body[0]["status"] == "success"
    assert body[0]["duration_ms"] == 42


async def test_start_agent_scan_requires_ethics_acceptance(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the not-accepted path regardless of whether another test in this shared
    # test DB already called `ethics.accept()` — the stream's first (and only) event
    # should then be the EthicsNoticeNotAccepted error, not a real scan.
    from vigia.agent import orchestrator as orchestrator_module
    from vigia.ethics import EthicsNoticeNotAccepted

    async def fake_ensure_accepted(session: object) -> None:
        raise EthicsNoticeNotAccepted("not accepted (forced for this test)")

    monkeypatch.setattr(orchestrator_module, "ensure_accepted", fake_ensure_accepted)

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://test") as client,
        client.stream("POST", "/scans/agent", json={"domain": "example.com"}) as response,
    ):
        assert response.status_code == 200
        body = b""
        async for chunk in response.aiter_bytes():
            body += chunk
    assert b"event: error" in body
    assert b"accept" in body.lower()
