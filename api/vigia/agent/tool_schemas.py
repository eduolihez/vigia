"""Turns tool Pydantic input models into Ollama/OpenAI-style function-calling defs.

Every tool call the planner makes must include a short `reason` alongside its normal
arguments (brief section 5, "one tool call per turn plus a short `reason` field") —
that property is injected into every generated schema here, then stripped back out by
`agent/orchestrator.py` before the remaining args are handed to `tool_router.invoke`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from vigia.tools import TOOL_MODULES

REASON_PROPERTY: dict[str, Any] = {
    "type": "string",
    "description": "One short sentence: why this tool call helps meet the scan's objective.",
}

ADVANCE_PHASE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "advance_phase",
        "description": (
            "Move on to the next phase of the scan. Use when this phase's tools "
            "have nothing more useful to add."
        ),
        "parameters": {
            "type": "object",
            "properties": {"reason": REASON_PROPERTY},
            "required": ["reason"],
        },
    },
}

DEEP_DIVE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "deep_dive",
        "description": (
            "Return to the EXPOSURE phase for one specific asset that looks worth a closer "
            "look (dev/staging hosts, login panels, services with a KEV CVE, dangling DNS, "
            "missing/permissive DMARC)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "asset_id": {"type": "string", "description": "The asset's id."},
                "reason": REASON_PROPERTY,
            },
            "required": ["asset_id", "reason"],
        },
    },
}


def _tool_def(tool_name: str) -> dict[str, Any]:
    module = TOOL_MODULES[tool_name]
    input_model = next(
        v
        for name, v in vars(module).items()
        if name.endswith("Input") and isinstance(v, type) and issubclass(v, BaseModel)
    )
    schema = input_model.model_json_schema()
    schema.pop("title", None)
    properties = dict(schema.get("properties", {}))
    properties["reason"] = REASON_PROPERTY
    schema["properties"] = properties
    schema["required"] = [*schema.get("required", []), "reason"]

    return {
        "type": "function",
        "function": {
            "name": tool_name,
            "description": module.SPEC.description,
            "parameters": schema,
        },
    }


def build_tool_defs(tool_names: list[str], *, include_meta: bool = True) -> list[dict[str, Any]]:
    defs = [_tool_def(name) for name in tool_names]
    if include_meta:
        defs.append(ADVANCE_PHASE_TOOL)
        defs.append(DEEP_DIVE_TOOL)
    return defs
