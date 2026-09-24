"""SSE event types the orchestrator emits during a scan.

`AgentEvent.for_sse()` renders one Server-Sent-Events frame; the API layer (Phase 5+
GUI consumer) streams these as they're yielded by the orchestrator's async generator.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AgentEventType(StrEnum):
    THOUGHT = "thought"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    ASSET_ADDED = "asset_added"
    FINDING_ADDED = "finding_added"
    PHASE_CHANGED = "phase_changed"
    ERROR = "error"
    DONE = "done"


class AgentEvent(BaseModel):
    type: AgentEventType
    scan_id: str
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def for_sse(self) -> str:
        payload = {"type": self.type.value, "scan_id": self.scan_id, **self.data}
        return f"event: {self.type.value}\ndata: {json.dumps(payload, default=str)}\n\n"
