"""Planner LLM client: wraps `ollama.AsyncClient` chat + tool-calling.

Verified 2026-09-24 against the installed `ollama` Python package: `AsyncClient.chat()`
takes `tools=[{"type": "function", "function": {...}}, ...]` (plain dicts are
accepted, no need to construct `ollama.Tool`), and a response's
`message.tool_calls[i].function` has `.name` (str) and `.arguments` (dict) — confirmed
with a live call against a local Ollama instance running `qwen2.5:7b-instruct`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import ollama
from pydantic import BaseModel


class PlannerToolCall(BaseModel):
    tool: str
    args: dict[str, Any] = {}
    reason: str = ""


class InvalidPlannerResponse(Exception):
    """The planner didn't return exactly one tool call — treated as an invalid turn."""


class Planner(Protocol):
    """What `AgentOrchestrator` needs from a planner — satisfied by `PlannerClient`
    and, in tests, by a scripted fake."""

    async def decide(
        self, *, system_prompt: str, user_message: str, tools: list[dict[str, Any]]
    ) -> PlannerToolCall: ...


class StructuredGenerator(Protocol):
    """What the Report Writer (Phase 4) needs from a planner — satisfied by
    `OllamaStructuredGenerator` and, in tests, by a scripted fake."""

    async def generate(
        self, *, system_prompt: str, user_message: str, json_schema: dict[str, Any]
    ) -> str: ...


@dataclass
class ModelAvailability:
    configured: str
    chosen: str
    available_tool_capable: list[str]
    fallback_used: bool


async def check_model_availability(host: str, configured_model: str) -> ModelAvailability:
    """Confirm `configured_model` is pulled and supports tool-calling; if not, fall
    back to the first installed model that does (brief section 2: "if the configured
    model is missing, warn and offer the installed ones that support tools").

    `Client.list()` (`/api/tags`) doesn't surface `capabilities` in this ollama
    Python package version — confirmed live — so this calls `show()` per installed
    model (`/api/show`, which does return `capabilities`) to find tool-capable ones.
    """
    client = ollama.AsyncClient(host=host)
    listing = await client.list()
    model_names = [m.model for m in listing.models if m.model]

    tool_capable: list[str] = []
    for name in model_names:
        info = await client.show(name)
        if "tools" in (info.capabilities or []):
            tool_capable.append(name)

    if configured_model in tool_capable:
        return ModelAvailability(configured_model, configured_model, tool_capable, False)

    fallback = tool_capable[0] if tool_capable else configured_model
    return ModelAvailability(configured_model, fallback, tool_capable, True)


class PlannerClient:
    def __init__(self, host: str, model: str) -> None:
        self._client = ollama.AsyncClient(host=host)
        self.model = model

    async def decide(
        self,
        *,
        system_prompt: str,
        user_message: str,
        tools: list[dict[str, Any]],
    ) -> PlannerToolCall:
        response = await self._client.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            tools=tools,
        )
        tool_calls = response.message.tool_calls or []
        if len(tool_calls) != 1:
            raise InvalidPlannerResponse(f"expected exactly one tool call, got {len(tool_calls)}")
        call = tool_calls[0].function
        args = dict(call.arguments)
        reason = str(args.pop("reason", ""))
        return PlannerToolCall(tool=call.name, args=args, reason=reason)


class OllamaStructuredGenerator:
    """Structured (JSON-schema-constrained) generation, for the Report Writer.

    Verified live 2026-09-24: `chat(..., format=<json schema dict>)` makes Ollama
    return `message.content` as a JSON string matching the schema.
    """

    def __init__(self, host: str, model: str) -> None:
        self._client = ollama.AsyncClient(host=host)
        self.model = model

    async def generate(
        self, *, system_prompt: str, user_message: str, json_schema: dict[str, Any]
    ) -> str:
        response = await self._client.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            format=json_schema,
        )
        return response.message.content or ""
