"""Scan endpoints.

`POST /scans/agent` (Phase 3) runs a scan end-to-end within one streamed request —
handy for `curl`, awkward for a browser GUI, since `EventSource` (the browser's
native SSE client) only issues GET requests with no body. The GUI (Phase 5) instead:

1. `POST /scans` creates the `Scan` row and returns its id immediately.
2. The browser navigates to `/scans/{id}/live` and opens an `EventSource` against
   `GET /scans/{id}/stream`, which lazily starts the orchestrator as a background
   task on first connection and broadcasts its events to every connected viewer.

Scan state itself always lives in the DB (`Scan`/`Asset`/`Finding`/`ToolCall`) — the
in-memory broadcast queues here are purely a live-updates convenience; a page
refreshed after the stream ends still sees the right state via `GET /scans/{id}` and
`GET /scans/{id}/findings`.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlmodel import col

from vigia.agent.events import AgentEvent, AgentEventType
from vigia.api.deps import SessionDep
from vigia.config import get_settings
from vigia.db.models import Asset, Finding, Scan, ScanMode, ScanStatus, ToolCall
from vigia.ethics import EthicsNoticeNotAccepted

router = APIRouter(prefix="/scans", tags=["scans"])

# scan_id -> set of subscriber queues (None sentinel marks stream end).
_subscribers: dict[str, set[asyncio.Queue[AgentEvent | None]]] = {}
# scan_id -> the background task actually running the orchestrator.
_running_tasks: dict[str, asyncio.Task[None]] = {}


class StartScanRequest(BaseModel):
    domain: str
    model: str | None = None
    mode: str = "passive"
    """"passive" or "active". Active mode requires domain-ownership verification —
    see `CreateScanResponse.verification_token`; the scan's VERIFY phase checks it
    live on first run and fails closed if it's missing/wrong (brief section 6.1)."""


class CreateScanResponse(BaseModel):
    id: str
    domain: str
    status: str
    mode: str
    verification_token: str | None = None
    """Set only for `mode="active"`: publish this exact value as a
    `vigia-verify=<token>` TXT record on the domain's root before starting the scan
    (subscribing to `GET /scans/{id}/stream`)."""


class ScanSummary(BaseModel):
    id: str
    domain: str
    mode: str
    status: str
    verified: bool
    verification_token: str | None
    started_at: str | None
    finished_at: str | None
    findings_count: int
    max_severity: str | None


class FindingOut(BaseModel):
    id: str
    asset_id: str | None
    type: str
    severity: str
    score: float
    title: str
    explanation: str
    remediation: str
    kev: bool
    known_ransomware: bool
    epss: float | None
    cve: str | None


@router.post("/agent")
async def start_agent_scan(request: StartScanRequest) -> StreamingResponse:
    """Run an LLM-driven passive scan against `domain`, streaming SSE events for
    the lifetime of this one request. See `GET /scans/{id}/stream` for the
    create-then-subscribe flow the GUI uses instead."""
    from vigia.agent.orchestrator import run_agent_scan
    from vigia.db.session import session_scope

    settings = get_settings()

    async def event_stream() -> AsyncGenerator[str]:
        try:
            async with session_scope() as session:
                async for event in run_agent_scan(
                    session, request.domain, settings, model_override=request.model
                ):
                    yield event.for_sse()
        except EthicsNoticeNotAccepted as exc:
            yield AgentEvent(
                type=AgentEventType.ERROR, scan_id="", data={"message": str(exc)}
            ).for_sse()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.post("", status_code=201)
async def create_scan(request: StartScanRequest, session: SessionDep) -> CreateScanResponse:
    """Create a pending `Scan` row. Nothing runs until a client subscribes to
    `GET /scans/{id}/stream` — that's the actual scan trigger."""
    from vigia.ethics import ensure_accepted
    from vigia.settings_store import build_effective_config

    try:
        await ensure_accepted(session)
    except EthicsNoticeNotAccepted as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        mode = ScanMode(request.mode)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail=f"Unknown mode {request.mode!r}; use 'passive' or 'active'."
        ) from exc

    config = await build_effective_config(session, get_settings())
    from vigia.agent.orchestrator import resolve_planner

    planner_model = await resolve_planner(config, request.model)

    verification_token = None
    if mode == ScanMode.ACTIVE:
        from vigia.agent.ownership import generate_token

        verification_token = generate_token()

    scan = Scan(
        domain=request.domain,
        mode=mode,
        verification_token=verification_token,
        planner_model=planner_model,
        extractor_model=config.extractor_model,
        budget_max_steps=config.scan_max_steps,
        budget_max_minutes=config.scan_max_minutes,
        status=ScanStatus.PENDING,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return CreateScanResponse(
        id=scan.id,
        domain=scan.domain,
        status=scan.status.value,
        mode=scan.mode.value,
        verification_token=scan.verification_token,
    )


@router.get("")
async def list_scans(session: SessionDep, limit: int = 25) -> list[ScanSummary]:
    """Most recent scans first, for the dashboard."""
    scans = (
        (await session.execute(select(Scan).order_by(col(Scan.created_at).desc()).limit(limit)))
        .scalars()
        .all()
    )
    out = []
    for scan in scans:
        findings = (
            (await session.execute(select(Finding).where(col(Finding.scan_id) == scan.id)))
            .scalars()
            .all()
        )
        max_severity = None
        if findings:
            order = ["critical", "high", "medium", "low", "info"]
            present = {f.severity.value for f in findings}
            max_severity = next((s for s in order if s in present), None)
        out.append(
            ScanSummary(
                id=scan.id,
                domain=scan.domain,
                mode=scan.mode.value,
                status=scan.status.value,
                verified=scan.verified,
                verification_token=scan.verification_token,
                started_at=scan.started_at.isoformat() if scan.started_at else None,
                finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
                findings_count=len(findings),
                max_severity=max_severity,
            )
        )
    return out


@router.get("/{scan_id}")
async def get_scan(scan_id: str, session: SessionDep) -> ScanSummary:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = (
        (await session.execute(select(Finding).where(col(Finding.scan_id) == scan_id)))
        .scalars()
        .all()
    )
    order = ["critical", "high", "medium", "low", "info"]
    present = {f.severity.value for f in findings}
    max_severity = next((s for s in order if s in present), None)
    return ScanSummary(
        id=scan.id,
        domain=scan.domain,
        mode=scan.mode.value,
        status=scan.status.value,
        verified=scan.verified,
        verification_token=scan.verification_token,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        findings_count=len(findings),
        max_severity=max_severity,
    )


@router.get("/{scan_id}/findings")
async def list_findings(scan_id: str, session: SessionDep) -> list[FindingOut]:
    findings = (
        (await session.execute(select(Finding).where(col(Finding.scan_id) == scan_id)))
        .scalars()
        .all()
    )
    return [
        FindingOut(
            id=f.id,
            asset_id=f.asset_id,
            type=f.type,
            severity=f.severity.value,
            score=f.score,
            title=f.title,
            explanation=f.explanation,
            remediation=f.remediation,
            kev=f.kev,
            known_ransomware=f.known_ransomware,
            epss=f.epss,
            cve=f.cve,
        )
        for f in findings
    ]


class AssetOut(BaseModel):
    id: str
    type: str
    value: str
    parent_id: str | None
    first_seen: str
    last_seen: str


@router.get("/{scan_id}/assets")
async def list_assets(scan_id: str, session: SessionDep) -> list[AssetOut]:
    """Every discovered `Asset` for one scan, parent links included — the raw
    material the graph view (`/scans/{id}/graph`) lays out."""
    assets = (
        (await session.execute(select(Asset).where(col(Asset.scan_id) == scan_id)))
        .scalars()
        .all()
    )
    return [
        AssetOut(
            id=a.id,
            type=a.type.value,
            value=a.value,
            parent_id=a.parent_id,
            first_seen=a.first_seen.isoformat(),
            last_seen=a.last_seen.isoformat(),
        )
        for a in assets
    ]


class ReportRequest(BaseModel):
    model: str | None = None


class TopRiskOut(BaseModel):
    title: str
    reason: str


class ReportFindingOut(BaseModel):
    title: str
    explanation: str
    impact: str
    remediation: str


class ReportOut(BaseModel):
    executive_summary: str
    top_risks: list[TopRiskOut]
    findings: list[ReportFindingOut]
    positive_observations: list[str]
    dropped_items: list[str]
    attempts_used: int


@router.post("/{scan_id}/report")
async def generate_scan_report(
    scan_id: str, request: ReportRequest, session: SessionDep
) -> ReportOut:
    """Draft a fresh report via the planner LLM and return it as JSON for the report
    viewer page. Not persisted — same on-demand-generation model as `vigia report`
    (there's no `Report` table in the schema); `POST /scans/{id}/report/export`
    drafts again for a specific downloadable format."""
    from vigia.agent.llm_client import OllamaStructuredGenerator
    from vigia.report.writer import generate_report
    from vigia.settings_store import build_effective_config

    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    config = await build_effective_config(session, get_settings())
    model = request.model or config.planner_model
    generator = OllamaStructuredGenerator(host=config.ollama_host, model=model)
    result = await generate_report(session, scan, generator)

    return ReportOut(
        executive_summary=result.draft.executive_summary,
        top_risks=[TopRiskOut(title=r.title, reason=r.reason) for r in result.draft.top_risks],
        findings=[
            ReportFindingOut(
                title=f.title,
                explanation=f.explanation,
                impact=f.impact,
                remediation=f.remediation,
            )
            for f in result.draft.findings
        ],
        positive_observations=result.draft.positive_observations,
        dropped_items=result.dropped_items,
        attempts_used=result.attempts_used,
    )


@router.post("/{scan_id}/report/export")
async def export_scan_report(
    scan_id: str, format: str, request: ReportRequest, session: SessionDep
) -> Response:
    """Draft a fresh report (see `POST /scans/{id}/report`) and return it as a
    downloadable file in `format` (`md`, `json`, or `pdf`)."""
    import json as _json

    from vigia.agent.llm_client import OllamaStructuredGenerator
    from vigia.report.exporters.json_export import to_json_dict
    from vigia.report.exporters.markdown import to_markdown
    from vigia.report.exporters.pdf import markdown_to_pdf_bytes
    from vigia.report.writer import generate_report
    from vigia.settings_store import build_effective_config

    if format not in ("md", "json", "pdf"):
        raise HTTPException(status_code=400, detail="format must be md, json, or pdf")

    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    config = await build_effective_config(session, get_settings())
    model = request.model or config.planner_model
    generator = OllamaStructuredGenerator(host=config.ollama_host, model=model)
    result = await generate_report(session, scan, generator)

    findings = (
        (await session.execute(select(Finding).where(col(Finding.scan_id) == scan_id)))
        .scalars()
        .all()
    )

    content: bytes
    if format == "json":
        content = _json.dumps(to_json_dict(scan, result, list(findings)), indent=2).encode("utf-8")
        media_type = "application/json"
    elif format == "md":
        content = to_markdown(scan, result, list(findings)).encode("utf-8")
        media_type = "text/markdown"
    else:
        content = await markdown_to_pdf_bytes(to_markdown(scan, result, list(findings)))
        media_type = "application/pdf"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="vigia-report-{scan_id}.{format}"'},
    )


@router.get("/{scan_id}/audit")
async def export_audit_log(scan_id: str, session: SessionDep) -> list[dict[str, object]]:
    """Export the immutable `ToolCall` audit trail for one scan as JSON."""
    result = await session.execute(select(ToolCall).where(col(ToolCall.scan_id) == scan_id))
    calls = result.scalars().all()
    if not calls:
        raise HTTPException(status_code=404, detail="No tool calls found for this scan id")
    return [
        {
            "id": c.id,
            "scan_id": c.scan_id,
            "phase": c.phase,
            "tool": c.tool,
            "args": c.args,
            "reason": c.reason,
            "status": c.status.value,
            "duration_ms": c.duration_ms,
            "result_sha256": c.result_sha256,
            "created_at": c.created_at.isoformat(),
        }
        for c in calls
    ]


async def _broadcast(scan_id: str, event: AgentEvent | None) -> None:
    for queue in list(_subscribers.get(scan_id, ())):
        await queue.put(event)


async def _run_scan_and_broadcast(scan_id: str) -> None:
    from vigia.agent.orchestrator import run_agent_scan_for
    from vigia.config import get_settings as _get_settings
    from vigia.db.session import session_scope
    from vigia.settings_store import build_effective_config

    defaults = _get_settings()
    try:
        async with session_scope() as session:
            scan = await session.get(Scan, scan_id)
            if scan is None:
                return
            config = await build_effective_config(session, defaults)
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(UTC)
            await session.commit()
            async for event in run_agent_scan_for(session, scan, config):
                await _broadcast(scan_id, event)
    finally:
        await _broadcast(scan_id, None)
        _running_tasks.pop(scan_id, None)


@router.get("/{scan_id}/stream")
async def stream_scan(scan_id: str, session: SessionDep) -> StreamingResponse:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan_id not in _running_tasks and scan.status == ScanStatus.PENDING:
        _running_tasks[scan_id] = asyncio.create_task(_run_scan_and_broadcast(scan_id))

    queue: asyncio.Queue[AgentEvent | None] = asyncio.Queue()
    _subscribers.setdefault(scan_id, set()).add(queue)

    async def event_stream() -> AsyncGenerator[str]:
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield event.for_sse()
        finally:
            _subscribers.get(scan_id, set()).discard(queue)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.delete("/{scan_id}", status_code=204)
async def stop_scan(scan_id: str, session: SessionDep) -> None:
    """Best-effort cancel of a running scan. Whatever's already persisted stays."""
    task = _running_tasks.get(scan_id)
    if task is not None:
        task.cancel()
    scan = await session.get(Scan, scan_id)
    if scan is not None and scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        scan.status = ScanStatus.STOPPED
        scan.finished_at = datetime.now(UTC)
        await session.commit()
