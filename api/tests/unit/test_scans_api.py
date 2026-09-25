from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from vigia.agent.events import AgentEvent, AgentEventType
from vigia.api.main import app
from vigia.db.models import (
    Finding,
    FindingSeverity,
    Scan,
    ScanMode,
    ScanStatus,
    ToolCall,
    ToolCallStatus,
)
from vigia.db.session import _session_factory
from vigia.ethics import accept as accept_ethics_notice


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


async def test_create_scan_creates_pending_row() -> None:
    async with _session_factory() as session:
        await accept_ethics_notice(session)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/scans", json={"domain": "example.com", "model": "fake-model"}
        )

    assert response.status_code == 201
    body = response.json()
    assert body["domain"] == "example.com"
    assert body["status"] == "pending"
    assert body["id"]


async def test_create_scan_requires_ethics_acceptance(monkeypatch: pytest.MonkeyPatch) -> None:
    from vigia.ethics import EthicsNoticeNotAccepted

    async def fake_ensure_accepted(session: object) -> None:
        raise EthicsNoticeNotAccepted("not accepted (forced for this test)")

    monkeypatch.setattr("vigia.ethics.ensure_accepted", fake_ensure_accepted)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/scans", json={"domain": "example.com", "model": "fake-model"}
        )

    assert response.status_code == 400


async def test_list_and_get_scan() -> None:
    async with _session_factory() as session:
        await accept_ethics_notice(session)
        scan = Scan(
            domain="list-me.example",
            mode=ScanMode.PASSIVE,
            planner_model="fake",
            extractor_model="fake",
            status=ScanStatus.COMPLETED,
        )
        session.add(scan)
        await session.flush()
        session.add(
            Finding(
                scan_id=scan.id,
                type="dmarc_missing",
                severity=FindingSeverity.HIGH,
                score=6.5,
                title="No DMARC",
                explanation="...",
                remediation="...",
            )
        )
        await session.commit()
        scan_id = scan.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        listing = await client.get("/scans")
        detail = await client.get(f"/scans/{scan_id}")
        missing = await client.get("/scans/does-not-exist")

    assert listing.status_code == 200
    assert any(s["id"] == scan_id for s in listing.json())

    assert detail.status_code == 200
    body = detail.json()
    assert body["domain"] == "list-me.example"
    assert body["findings_count"] == 1
    assert body["max_severity"] == "high"

    assert missing.status_code == 404


async def test_list_findings_for_scan() -> None:
    async with _session_factory() as session:
        scan = Scan(
            domain="findings.example",
            mode=ScanMode.PASSIVE,
            planner_model="fake",
            extractor_model="fake",
            status=ScanStatus.COMPLETED,
        )
        session.add(scan)
        await session.flush()
        session.add(
            Finding(
                scan_id=scan.id,
                type="known_vulnerability",
                severity=FindingSeverity.CRITICAL,
                score=9.8,
                title="Log4Shell",
                explanation="...",
                remediation="...",
                cve="CVE-2021-44228",
                kev=True,
            )
        )
        await session.commit()
        scan_id = scan.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/scans/{scan_id}/findings")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["cve"] == "CVE-2021-44228"
    assert body[0]["kev"] is True
    assert body[0]["severity"] == "critical"


async def test_stream_scan_starts_background_task_and_broadcasts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vigia.api import scans as scans_module

    async def fake_run_agent_scan_for(session: object, scan: Scan, settings: object):  # type: ignore[no-untyped-def]
        yield AgentEvent(type=AgentEventType.THOUGHT, scan_id=scan.id, data={"reason": "hi"})
        yield AgentEvent(type=AgentEventType.DONE, scan_id=scan.id, data={})

    monkeypatch.setattr("vigia.agent.orchestrator.run_agent_scan_for", fake_run_agent_scan_for)

    async with _session_factory() as session:
        await accept_ethics_notice(session)
        scan = Scan(
            domain="stream.example",
            mode=ScanMode.PASSIVE,
            planner_model="fake-model",
            extractor_model="fake",
            status=ScanStatus.PENDING,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        scan_id = scan.id

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://test") as client,
        client.stream("GET", f"/scans/{scan_id}/stream") as response,
    ):
        assert response.status_code == 200
        body = b""
        async for chunk in response.aiter_bytes():
            body += chunk

    assert b"event: thought" in body
    assert b"event: done" in body

    # give the background task's finally-block a tick to clean itself up
    await asyncio.sleep(0)
    assert scan_id not in scans_module._running_tasks


async def test_stream_scan_404_for_unknown_scan() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/scans/does-not-exist/stream")
    assert response.status_code == 404


async def test_stop_scan_marks_it_stopped() -> None:
    async with _session_factory() as session:
        scan = Scan(
            domain="stop-me.example",
            mode=ScanMode.PASSIVE,
            planner_model="fake",
            extractor_model="fake",
            status=ScanStatus.RUNNING,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        scan_id = scan.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.delete(f"/scans/{scan_id}")

    assert response.status_code == 204
    async with _session_factory() as session:
        stopped = await session.get(Scan, scan_id)
        assert stopped is not None
        assert stopped.status == ScanStatus.STOPPED


async def test_list_assets_for_scan() -> None:
    from vigia.db.models import Asset, AssetType

    async with _session_factory() as session:
        scan = Scan(
            domain="graph-me.example",
            mode=ScanMode.PASSIVE,
            planner_model="fake",
            extractor_model="fake",
            status=ScanStatus.COMPLETED,
        )
        session.add(scan)
        await session.flush()
        root = Asset(scan_id=scan.id, type=AssetType.DOMAIN, value="graph-me.example")
        session.add(root)
        await session.flush()
        session.add(
            Asset(
                scan_id=scan.id,
                type=AssetType.SUBDOMAIN,
                value="www.graph-me.example",
                parent_id=root.id,
            )
        )
        await session.commit()
        scan_id = scan.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/scans/{scan_id}/assets")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    values = {a["value"] for a in body}
    assert values == {"graph-me.example", "www.graph-me.example"}


_SCRIPTED_DRAFT = {
    "executive_summary": "report-me.example has one finding.",
    "top_risks": [{"title": "No DMARC", "reason": "spoofing is possible"}],
    "findings": [
        {
            "title": "No DMARC record",
            "explanation": "report-me.example has no DMARC record.",
            "impact": "Email spoofing is possible.",
            "remediation": "Publish a DMARC record.",
        }
    ],
    "positive_observations": ["No other issues found."],
}


class _FakeStructuredGenerator:
    def __init__(self, host: str, model: str) -> None:
        del host, model

    async def generate(
        self, *, system_prompt: str, user_message: str, json_schema: dict[str, object]
    ) -> str:
        del system_prompt, user_message, json_schema
        import json

        return json.dumps(_SCRIPTED_DRAFT)


async def _make_report_ready_scan() -> str:
    from vigia.db.models import FindingSeverity

    async with _session_factory() as session:
        scan = Scan(
            domain="report-me.example",
            mode=ScanMode.PASSIVE,
            planner_model="fake",
            extractor_model="fake",
            status=ScanStatus.COMPLETED,
        )
        session.add(scan)
        await session.flush()
        session.add(
            Finding(
                scan_id=scan.id,
                type="dmarc_missing",
                severity=FindingSeverity.HIGH,
                score=6.5,
                title="No DMARC record",
                explanation="report-me.example has no DMARC record.",
                remediation="Publish a DMARC record.",
            )
        )
        await session.commit()
        return scan.id


async def test_generate_scan_report(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vigia.agent.llm_client.OllamaStructuredGenerator", _FakeStructuredGenerator
    )
    scan_id = await _make_report_ready_scan()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(f"/scans/{scan_id}/report", json={})

    assert response.status_code == 200
    body = response.json()
    assert body["executive_summary"] == _SCRIPTED_DRAFT["executive_summary"]
    assert len(body["findings"]) == 1
    assert body["dropped_items"] == []


async def test_generate_scan_report_404_for_unknown_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vigia.agent.llm_client.OllamaStructuredGenerator", _FakeStructuredGenerator
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/scans/does-not-exist/report", json={})
    assert response.status_code == 404


async def test_export_scan_report_markdown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vigia.agent.llm_client.OllamaStructuredGenerator", _FakeStructuredGenerator
    )
    scan_id = await _make_report_ready_scan()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(f"/scans/{scan_id}/report/export?format=md", json={})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "No DMARC record" in response.text


async def test_export_scan_report_rejects_unknown_format(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vigia.agent.llm_client.OllamaStructuredGenerator", _FakeStructuredGenerator
    )
    scan_id = await _make_report_ready_scan()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(f"/scans/{scan_id}/report/export?format=xml", json={})

    assert response.status_code == 400
