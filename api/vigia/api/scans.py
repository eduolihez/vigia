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

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlmodel import col

from vigia.agent.events import AgentEvent, AgentEventType
from vigia.api.deps import SessionDep
from vigia.config import get_settings
from vigia.db.models import Finding, Scan, ScanMode, ScanStatus, ToolCall
from vigia.ethics import EthicsNoticeNotAccepted

router = APIRouter(prefix="/scans", tags=["scans"])

# scan_id -> set of subscriber queues (None sentinel marks stream end).
_subscribers: dict[str, set[asyncio.Queue[AgentEvent | None]]] = {}
# scan_id -> the background task actually running the orchestrator.
_running_tasks: dict[str, asyncio.Task[None]] = {}


class StartScanRequest(BaseModel):
    domain: str
    model: str | None = None


class CreateScanResponse(BaseModel):
    id: str
    domain: str
    status: str


class ScanSummary(BaseModel):
    id: str
    domain: str
    mode: str
    status: str
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

    try:
        await ensure_accepted(session)
    except EthicsNoticeNotAccepted as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    settings = get_settings()
    from vigia.agent.orchestrator import resolve_planner

    planner_model = await resolve_planner(settings, request.model)

    scan = Scan(
        domain=request.domain,
        mode=ScanMode.PASSIVE,
        planner_model=planner_model,
        extractor_model=settings.extractor_model,
        status=ScanStatus.PENDING,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return CreateScanResponse(id=scan.id, domain=scan.domain, status=scan.status.value)


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

    settings = _get_settings()
    try:
        async with session_scope() as session:
            scan = await session.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(UTC)
            await session.commit()
            async for event in run_agent_scan_for(session, scan, settings):
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
