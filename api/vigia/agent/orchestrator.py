"""Agent orchestrator: the LLM-driven state machine loop (brief section 5).

The planner LLM *decides* (which tool, or advance_phase / deep_dive) and *why*;
everything else — validating the call against the phase/scope, executing it,
persisting evidence, updating the asset graph, and deciding when to stop — is
deterministic Python. If the planner goes off the rails (3 consecutive invalid
calls), the rest of the current phase runs as a fixed deterministic pipeline instead,
and normal LLM-driven behavior resumes at the next phase.

Yields `AgentEvent`s as it goes (SSE consumer-ready); also persists everything to the
DB itself, so a caller that only cares about the final state can just drain the
generator.
"""

from __future__ import annotations

import gzip
import json
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col

from vigia.agent.events import AgentEvent, AgentEventType
from vigia.agent.llm_client import (
    InvalidPlannerResponse,
    Planner,
    PlannerClient,
    check_model_availability,
)
from vigia.agent.phases import PHASE_TOOLS, AgentPhase, next_phase
from vigia.agent.scope_guard import ScopeGuard, ScopeViolation
from vigia.agent.tool_router import ToolContext, ToolNotAllowedError, invoke
from vigia.agent.tool_schemas import build_tool_defs
from vigia.config import Settings
from vigia.db.models import (
    Asset,
    AssetType,
    Evidence,
    Finding,
    FindingSeverity,
    Scan,
    ScanMode,
    ScanStatus,
    ToolCall,
    ToolCallStatus,
)
from vigia.ethics import ensure_accepted
from vigia.tools import base as tools_base

MAX_INVALID_CALLS_BEFORE_FALLBACK = 3
MAX_NO_NEW_ASSETS_BEFORE_STOP = 2
DEFAULT_MAX_DEEP_DIVES = 5
MAX_ITEMS_PER_PHASE_TARGET = 20  # bound for fallback-mode per-asset iteration

# Phases whose tools are meant to discover new assets — the "stop after N consecutive
# empty iterations" heuristic only applies here. EMAIL_AND_SPOOFING/LEAKS/RISK tools
# are findings-only by design (email_auth, github_leaks, hibp_domain, kev_epss_enrich
# never populate `assets_discovered`), so counting their empty results would trip an
# early stop mid-scan for entirely expected behavior.
ASSET_DISCOVERY_PHASES = {AgentPhase.ENUMERATE, AgentPhase.RESOLVE, AgentPhase.EXPOSURE}

PLACEHOLDER_SEVERITY = FindingSeverity.INFO
PLACEHOLDER_SCORE = 0.0
PLACEHOLDER_REMEDIATION = "Pending: severity/remediation are assigned by the Risk Engine (Phase 4)."

_PROMPT_PATH = Path(__file__).parent / "prompts" / "planner_system.md"


def _sse(event_type: AgentEventType, scan_id: str, **data: Any) -> AgentEvent:
    return AgentEvent(type=event_type, scan_id=scan_id, data=data)


@dataclass
class _AgentState:
    phase: AgentPhase = AgentPhase.VERIFY
    step_count: int = 0
    deep_dives_used: int = 0
    consecutive_invalid_calls: int = 0
    consecutive_no_new_assets: int = 0
    deterministic_fallback: bool = False
    deep_dive_return_phase: AgentPhase | None = None
    focus_asset_id: str | None = None
    assets_by_value: dict[str, Asset] = field(default_factory=dict)
    kev_epss_by_cve: dict[str, dict[str, Any]] = field(default_factory=dict)


class AgentOrchestrator:
    def __init__(
        self,
        session: AsyncSession,
        scan: Scan,
        settings: Settings,
        client: httpx.AsyncClient,
        planner: Planner,
        *,
        max_deep_dives: int = DEFAULT_MAX_DEEP_DIVES,
    ) -> None:
        self.session = session
        self.scan = scan
        self.settings = settings
        self.client = client
        self.planner = planner
        self.max_deep_dives = max_deep_dives
        self.scope_guard = ScopeGuard(root_domain=scan.domain)
        self.ctx = ToolContext(client=client, settings=settings)
        self._state = _AgentState()
        self._start = time.monotonic()
        self._cves_seen: set[str] = set()

    async def run(self) -> AsyncGenerator[AgentEvent]:
        s = self._state
        domain_asset = await self._upsert_asset("domain", self.scan.domain)
        s.assets_by_value[self.scan.domain] = domain_asset

        while s.phase != AgentPhase.DONE:
            if self._budget_exceeded():
                break

            if s.phase == AgentPhase.VERIFY:
                # Passive mode never needs ownership verification; active mode isn't
                # implemented until Phase 7, so there's nothing to do here yet either
                # way but advance.
                async for ev in self._advance_phase("passive mode needs no verification"):
                    yield ev
                continue

            if s.phase == AgentPhase.REPORT:
                # Report Writer lands in Phase 4.
                async for ev in self._advance_phase("report writer not implemented yet"):
                    yield ev
                continue

            if s.phase == AgentPhase.SEED:
                # A single bootstrap lookup (WHOIS/ASN) — nothing here needs planner
                # judgment, and for a bare domain it typically finds no new *assets*
                # (only informational findings), which would otherwise trip the
                # no-new-assets early stop before the scan even reaches ENUMERATE.
                async for ev in self._run_deterministic_phase(PHASE_TOOLS[AgentPhase.SEED]):
                    yield ev
                async for ev in self._advance_phase("seed lookup complete"):
                    yield ev
                continue

            available_tools = PHASE_TOOLS[s.phase]
            if not available_tools:
                async for ev in self._advance_phase("no tools available in this phase"):
                    yield ev
                continue

            if s.deterministic_fallback:
                async for ev in self._run_deterministic_phase(available_tools):
                    yield ev
                s.deterministic_fallback = False
                async for ev in self._advance_phase("deterministic fallback completed"):
                    yield ev
                continue

            async for ev in self._step(available_tools):
                yield ev

            if (
                s.phase in ASSET_DISCOVERY_PHASES
                and s.consecutive_no_new_assets >= MAX_NO_NEW_ASSETS_BEFORE_STOP
            ):
                yield _sse(
                    AgentEventType.ERROR,
                    self.scan.id,
                    message=(
                        f"{MAX_NO_NEW_ASSETS_BEFORE_STOP} consecutive steps found no new "
                        "assets — stopping early."
                    ),
                )
                break

        await self._finish()
        yield _sse(
            AgentEventType.DONE,
            self.scan.id,
            assets=len(s.assets_by_value),
            status=self.scan.status.value,
        )

    # -- one LLM-driven step -------------------------------------------------

    async def _step(self, available_tools: list[str]) -> AsyncGenerator[AgentEvent]:
        s = self._state
        s.step_count += 1

        system_prompt = self._render_prompt()
        tools = build_tool_defs(available_tools)

        try:
            decision = await self.planner.decide(
                system_prompt=system_prompt,
                user_message="Decide your next action.",
                tools=tools,
            )
        except InvalidPlannerResponse as exc:
            async for ev in self._invalid_turn(f"invalid planner response: {exc}"):
                yield ev
            return

        yield _sse(AgentEventType.THOUGHT, self.scan.id, reason=decision.reason, tool=decision.tool)

        if decision.tool == "advance_phase":
            s.consecutive_invalid_calls = 0
            async for ev in self._advance_phase(decision.reason):
                yield ev
            return

        if decision.tool == "deep_dive":
            async for ev in self._handle_deep_dive(decision.args, decision.reason):
                yield ev
            return

        if decision.tool not in available_tools:
            async for ev in self._invalid_turn(
                f"planner requested {decision.tool!r}, not allowed in phase {s.phase.value!r}"
            ):
                yield ev
            return

        async for ev in self._run_tool(s.phase, decision.tool, decision.args, decision.reason):
            yield ev

    async def _invalid_turn(self, message: str) -> AsyncGenerator[AgentEvent]:
        s = self._state
        s.consecutive_invalid_calls += 1
        yield _sse(AgentEventType.ERROR, self.scan.id, message=message)
        if s.consecutive_invalid_calls >= MAX_INVALID_CALLS_BEFORE_FALLBACK:
            s.deterministic_fallback = True
            s.consecutive_invalid_calls = 0
            yield _sse(
                AgentEventType.ERROR,
                self.scan.id,
                message=(
                    f"{MAX_INVALID_CALLS_BEFORE_FALLBACK} consecutive invalid planner "
                    f"turns — switching to deterministic pipeline for phase {s.phase.value!r}."
                ),
            )

    async def _advance_phase(self, reason: str) -> AsyncGenerator[AgentEvent]:
        s = self._state
        old_phase = s.phase
        if s.deep_dive_return_phase is not None:
            s.phase = next_phase(s.deep_dive_return_phase)
            s.deep_dive_return_phase = None
            s.focus_asset_id = None
        else:
            s.phase = next_phase(s.phase)
        yield _sse(
            AgentEventType.PHASE_CHANGED,
            self.scan.id,
            from_phase=old_phase.value,
            to_phase=s.phase.value,
            reason=reason,
        )

    async def _handle_deep_dive(
        self, args: dict[str, Any], reason: str
    ) -> AsyncGenerator[AgentEvent]:
        s = self._state
        asset_id = args.get("asset_id")
        if asset_id is None or not await self._asset_exists(asset_id):
            async for ev in self._invalid_turn(f"deep_dive: unknown asset_id {asset_id!r}"):
                yield ev
            return
        if s.deep_dives_used >= self.max_deep_dives:
            async for ev in self._invalid_turn("deep_dive: max deep dives already used"):
                yield ev
            return

        s.consecutive_invalid_calls = 0
        s.deep_dives_used += 1
        if s.deep_dive_return_phase is None:
            s.deep_dive_return_phase = s.phase
        old_phase = s.phase
        s.phase = AgentPhase.EXPOSURE
        s.focus_asset_id = asset_id

        yield _sse(
            AgentEventType.PHASE_CHANGED,
            self.scan.id,
            from_phase=old_phase.value,
            to_phase=s.phase.value,
            reason=f"deep_dive: {reason}",
            focus_asset_id=asset_id,
        )

    async def _asset_exists(self, asset_id: str) -> bool:
        result = await self.session.execute(
            select(Asset).where(col(Asset.id) == asset_id, col(Asset.scan_id) == self.scan.id)
        )
        return result.scalar_one_or_none() is not None

    async def _run_tool(
        self, phase: AgentPhase, tool_name: str, args: dict[str, Any], reason: str
    ) -> AsyncGenerator[AgentEvent]:
        s = self._state
        try:
            result = await invoke(
                tool_name, args, phase=phase, scope_guard=self.scope_guard, ctx=self.ctx
            )
        except (ToolNotAllowedError, ScopeViolation) as exc:
            async for ev in self._invalid_turn(str(exc)):
                yield ev
            return
        except Exception as exc:  # a malformed args dict, etc — still an invalid turn
            async for ev in self._invalid_turn(f"{tool_name}: {exc}"):
                yield ev
            return

        s.consecutive_invalid_calls = 0
        yield _sse(AgentEventType.TOOL_CALL, self.scan.id, tool=tool_name, args=args, reason=reason)

        await self._record_tool_call(phase, result, args, reason)
        yield _sse(
            AgentEventType.TOOL_RESULT,
            self.scan.id,
            tool=tool_name,
            error=result.error,
            assets_found=len(result.assets_discovered),
            findings_found=len(result.findings_candidates),
        )

        new_asset_count = 0
        for a in result.assets_discovered:
            if a.value not in s.assets_by_value:
                new_asset_count += 1
                parent = s.assets_by_value.get(a.parent_value or "")
                asset = await self._upsert_asset(a.type, a.value, parent.id if parent else None)
                s.assets_by_value[a.value] = asset
                if a.type in ("subdomain", "domain"):
                    self.scope_guard.add_subdomain(a.value)
                elif a.type == "ip":
                    self.scope_guard.add_ip(a.value)
                yield _sse(
                    AgentEventType.ASSET_ADDED,
                    self.scan.id,
                    asset_id=asset.id,
                    type=a.type,
                    value=a.value,
                )
        if phase in ASSET_DISCOVERY_PHASES:
            s.consecutive_no_new_assets = 0 if new_asset_count else s.consecutive_no_new_assets + 1

        for f in result.findings_candidates:
            finding = await self._persist_finding(f)
            yield _sse(
                AgentEventType.FINDING_ADDED,
                self.scan.id,
                finding_id=finding.id,
                type=f.type,
                title=f.title,
            )

        if tool_name == "kev_epss_enrich" and not result.error:
            await self._apply_kev_enrichment(result)

    # -- deterministic fallback ----------------------------------------------

    async def _run_deterministic_phase(self, tools: list[str]) -> AsyncGenerator[AgentEvent]:
        s = self._state
        for tool_name in tools:
            for args in self._default_args(tool_name):
                async for ev in self._run_tool(
                    s.phase, tool_name, args, "deterministic pipeline fallback"
                ):
                    yield ev

    def _default_args(self, tool_name: str) -> list[dict[str, Any]]:
        s = self._state
        domain = self.scan.domain
        domain_only_tools = (
            "ct_subdomains",
            "wayback_urls",
            "typosquat",
            "email_auth",
            "github_leaks",
            "hibp_domain",
            "subfinder_enum",
        )
        if tool_name == "whois_asn":
            return [{"resource": domain}]
        if tool_name in domain_only_tools:
            return [{"domain": domain}]
        if tool_name == "dns_resolve":
            hostnames = [domain] + [
                v for v, a in s.assets_by_value.items() if a.type == AssetType.SUBDOMAIN
            ]
            return [{"hostname": h} for h in hostnames[:MAX_ITEMS_PER_PHASE_TARGET]]
        if tool_name == "dangling_dns":
            hostnames = [v for v, a in s.assets_by_value.items() if a.type == AssetType.SUBDOMAIN]
            return [{"hostname": h} for h in hostnames[:MAX_ITEMS_PER_PHASE_TARGET]]
        if tool_name in ("shodan_internetdb", "censys_hosts"):
            ips = [v for v, a in s.assets_by_value.items() if a.type == AssetType.IP]
            return [{"ip": ip} for ip in ips[:MAX_ITEMS_PER_PHASE_TARGET]]
        if tool_name == "kev_epss_enrich":
            cves = self._known_cves()
            return [{"cves": cves}] if cves else []
        return []

    def _known_cves(self) -> list[str]:
        # populated as findings are persisted during EXPOSURE
        return sorted(self._cves_seen)

    # -- persistence -----------------------------------------------------------

    async def _upsert_asset(self, type_: str, value: str, parent_id: str | None = None) -> Asset:
        asset_type = AssetType(type_)
        result = await self.session.execute(
            select(Asset).where(
                col(Asset.scan_id) == self.scan.id,
                col(Asset.type) == asset_type,
                col(Asset.value) == value,
            )
        )
        asset = result.scalar_one_or_none()
        if asset:
            asset.last_seen = datetime.now(UTC)
            return asset
        asset = Asset(scan_id=self.scan.id, type=asset_type, value=value, parent_id=parent_id)
        self.session.add(asset)
        await self.session.flush()
        return asset

    async def _record_tool_call(
        self, phase: AgentPhase, result: tools_base.ToolResult, args: dict[str, Any], reason: str
    ) -> None:
        status = ToolCallStatus.ERROR if result.error else ToolCallStatus.SUCCESS
        self.session.add(
            ToolCall(
                scan_id=self.scan.id,
                phase=phase.value,
                tool=result.tool,
                args=args,
                reason=reason,
                status=status,
                duration_ms=result.duration_ms,
                result_sha256=result.sha256 or None,
            )
        )
        if result.raw_output:
            self.session.add(
                Evidence(
                    tool=result.tool,
                    raw_output=gzip.compress(result.raw_output),
                    sha256=result.sha256,
                )
            )
        await self.session.flush()
        if result.error is None:
            for f in result.findings_candidates:
                if f.cve:
                    self._cves_seen.add(f.cve)

    async def _persist_finding(self, candidate: tools_base.FindingCandidate) -> Finding:
        asset = self._state.assets_by_value.get(candidate.asset_value or "")
        enrichment = self._state.kev_epss_by_cve.get(candidate.cve or "", {})
        finding = Finding(
            scan_id=self.scan.id,
            asset_id=asset.id if asset else None,
            type=candidate.type,
            severity=PLACEHOLDER_SEVERITY,
            score=PLACEHOLDER_SCORE,
            title=candidate.title,
            explanation=candidate.detail,
            remediation=PLACEHOLDER_REMEDIATION,
            kev=bool(enrichment.get("in_kev", False)),
            epss=enrichment.get("epss"),
            cve=candidate.cve,
        )
        self.session.add(finding)
        await self.session.flush()
        return finding

    async def _apply_kev_enrichment(self, result: tools_base.ToolResult) -> None:
        payload = json.loads(result.raw_output or b"{}")
        entries = {e["cve"]: e for e in payload.get("enrichment", [])}
        self._state.kev_epss_by_cve.update(entries)
        if not entries:
            return
        result_ids = await self.session.execute(
            select(Finding).where(
                col(Finding.scan_id) == self.scan.id, col(Finding.cve).in_(entries.keys())
            )
        )
        for finding in result_ids.scalars().all():
            entry = entries.get(finding.cve or "")
            if entry:
                finding.kev = bool(entry.get("in_kev", False))
                finding.epss = entry.get("epss")
        await self.session.flush()

    async def _finish(self) -> None:
        self.scan.status = ScanStatus.COMPLETED
        self.scan.finished_at = datetime.now(UTC)
        await self.session.commit()

    # -- misc -----------------------------------------------------------------

    def _budget_exceeded(self) -> bool:
        s = self._state
        if s.step_count >= self.settings.scan_max_steps:
            return True
        elapsed_minutes = (time.monotonic() - self._start) / 60
        return elapsed_minutes >= self.settings.scan_max_minutes

    def _render_prompt(self) -> str:
        s = self._state
        elapsed_minutes = (time.monotonic() - self._start) / 60
        template = _PROMPT_PATH.read_text(encoding="utf-8")
        graph_summary = self._graph_summary()
        if s.focus_asset_id:
            focus = s.assets_by_value.get(s.focus_asset_id)
            if focus:
                graph_summary += f"\n\nDeep-dive focus asset: {focus.value} ({focus.type})"
        return template.format(
            root_domain=self.scan.domain,
            phase=s.phase.value,
            steps_remaining=max(0, self.settings.scan_max_steps - s.step_count),
            minutes_remaining=max(0.0, self.settings.scan_max_minutes - elapsed_minutes),
            deep_dives_used=s.deep_dives_used,
            max_deep_dives=self.max_deep_dives,
            graph_summary=graph_summary,
        )

    def _graph_summary(self) -> str:
        s = self._state
        by_type: dict[str, int] = {}
        for a in s.assets_by_value.values():
            by_type[a.type.value] = by_type.get(a.type.value, 0) + 1
        parts = ", ".join(f"{count} {type_}" for type_, count in sorted(by_type.items()))
        return f"Assets discovered: {parts or 'none yet'}."


async def run_agent_scan(
    session: AsyncSession,
    domain: str,
    settings: Settings,
    *,
    model_override: str | None = None,
) -> AsyncGenerator[AgentEvent]:
    """Create a `Scan`, wire up the planner (checking model availability first per
    brief section 2), and drive `AgentOrchestrator.run()`. Raises
    `EthicsNoticeNotAccepted` if the first-run notice hasn't been accepted."""
    await ensure_accepted(session)

    availability = await check_model_availability(settings.ollama_host, settings.planner_model)
    planner_model = model_override or availability.chosen

    scan = Scan(
        domain=domain,
        mode=ScanMode.PASSIVE,
        planner_model=planner_model,
        extractor_model=settings.extractor_model,
        status=ScanStatus.RUNNING,
        started_at=datetime.now(UTC),
    )
    session.add(scan)
    await session.flush()

    async with httpx.AsyncClient(timeout=tools_base.DEFAULT_TIMEOUT_SECONDS) as client:
        planner = PlannerClient(host=settings.ollama_host, model=planner_model)
        orchestrator = AgentOrchestrator(
            session, scan, settings, client, planner, max_deep_dives=settings.scan_max_deep_dives
        )
        async for event in orchestrator.run():
            yield event
