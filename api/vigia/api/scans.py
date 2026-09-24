"""Scan endpoints: launch an agent-driven passive scan (SSE) and export its audit log.

The full REST surface (`/scans`, `/scans/[id]/live`, `/scans/[id]/graph`, ...) is
Phase 5 GUI scope. This is the minimal slice Phase 3 needs to prove the SSE event
stream works end-to-end over HTTP, and to satisfy the "exportable audit log"
guardrail (brief section 6.7) with a real endpoint rather than just a DB table.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlmodel import col

from vigia.api.deps import SessionDep
from vigia.config import get_settings
from vigia.db.models import ToolCall
from vigia.ethics import EthicsNoticeNotAccepted

router = APIRouter(prefix="/scans", tags=["scans"])


class StartScanRequest(BaseModel):
    domain: str
    model: str | None = None


@router.post("/agent")
async def start_agent_scan(request: StartScanRequest) -> StreamingResponse:
    """Run an LLM-driven passive scan against `domain`, streaming SSE events.

    Opens its own DB session (rather than the request-scoped `SessionDep`) because
    `StreamingResponse` iterates its generator *after* the route handler returns —
    by then a request-scoped session dependency would already be closed.
    """
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
            from vigia.agent.events import AgentEvent, AgentEventType

            yield AgentEvent(
                type=AgentEventType.ERROR, scan_id="", data={"message": str(exc)}
            ).for_sse()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


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
