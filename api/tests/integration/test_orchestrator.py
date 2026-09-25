"""Orchestrator integration tests: phase transitions, Scope Guard enforcement,
deterministic fallback, deep dive, and budget/early-stop behavior.

Tool execution itself is already covered by `tests/unit/tools/`; here the tools are
swapped for fakes (via `tool_router.INVOKERS`) so these tests exercise only the
orchestration logic, deterministically and without network calls.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import httpx
import pytest

from vigia.agent import tool_router
from vigia.agent.llm_client import InvalidPlannerResponse, PlannerToolCall
from vigia.agent.orchestrator import AgentOrchestrator
from vigia.config import Settings
from vigia.db.models import Scan, ScanMode, ScanStatus, ToolCall
from vigia.db.session import _session_factory
from vigia.tools.base import DiscoveredAsset, FindingCandidate, ToolResult


class FakePlanner:
    """Returns pre-scripted decisions in order; raises on malformed/exhausted script."""

    def __init__(self, script: Sequence[PlannerToolCall | None]) -> None:
        self._script = list(script)
        self.calls = 0

    async def decide(
        self, *, system_prompt: str, user_message: str, tools: list[dict[str, Any]]
    ) -> PlannerToolCall:
        self.calls += 1
        if not self._script:
            raise InvalidPlannerResponse("script exhausted")
        decision = self._script.pop(0)
        if decision is None:
            raise InvalidPlannerResponse("scripted invalid turn")
        return decision


async def _make_scan(domain: str = "example.com") -> Scan:
    async with _session_factory() as session:
        scan = Scan(
            domain=domain,
            mode=ScanMode.PASSIVE,
            planner_model="fake-model",
            extractor_model="fake-model",
            status=ScanStatus.RUNNING,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan


def _settings(**overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "VIGIA_PLANNER_MODEL": "fake-model",
        "VIGIA_EXTRACTOR_MODEL": "fake-model",
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


def _ok_result(
    tool: str,
    *,
    assets: list[DiscoveredAsset] | None = None,
    findings: list[FindingCandidate] | None = None,
) -> ToolResult:
    return ToolResult(
        tool=tool,
        assets_discovered=assets or [],
        findings_candidates=findings or [],
        raw_output=b"{}",
        sha256="x",
        duration_ms=1,
    )


async def _fake_whois_asn(args: dict[str, Any], ctx: object) -> ToolResult:
    return _ok_result("whois_asn")


async def test_full_happy_path_persists_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    scan = await _make_scan()

    async def fake_ct(args: dict[str, Any], ctx: object) -> ToolResult:
        return _ok_result(
            "ct_subdomains",
            assets=[
                DiscoveredAsset(
                    type="subdomain", value="www.example.com", parent_value="example.com"
                )
            ],
        )

    async def fake_dns(args: dict[str, Any], ctx: object) -> ToolResult:
        return _ok_result(
            "dns_resolve",
            assets=[DiscoveredAsset(type="ip", value="1.2.3.4", parent_value=args["hostname"])],
        )

    async def fake_shodan(args: dict[str, Any], ctx: object) -> ToolResult:
        return _ok_result(
            "shodan_internetdb",
            findings=[
                FindingCandidate(
                    type="known_vulnerability",
                    title="CVE found",
                    detail="...",
                    asset_value=args["ip"],
                    cve="CVE-2021-44228",
                )
            ],
        )

    async def fake_email_auth(args: dict[str, Any], ctx: object) -> ToolResult:
        return _ok_result(
            "email_auth",
            findings=[
                FindingCandidate(
                    type="spf_missing", title="No SPF", detail="...", asset_value=args["domain"]
                )
            ],
        )

    monkeypatch.setitem(tool_router.INVOKERS, "whois_asn", _fake_whois_asn)
    monkeypatch.setitem(tool_router.INVOKERS, "ct_subdomains", fake_ct)
    monkeypatch.setitem(tool_router.INVOKERS, "dns_resolve", fake_dns)
    monkeypatch.setitem(tool_router.INVOKERS, "shodan_internetdb", fake_shodan)
    monkeypatch.setitem(tool_router.INVOKERS, "email_auth", fake_email_auth)

    async def fake_kev_real(args: dict[str, Any], ctx: object) -> ToolResult:
        import json

        payload = json.dumps(
            {
                "enrichment": [
                    {"cve": "CVE-2021-44228", "in_kev": True, "known_ransomware": True, "epss": 0.9}
                ]
            }
        ).encode()
        return ToolResult(tool="kev_epss_enrich", raw_output=payload, sha256="x", duration_ms=1)

    monkeypatch.setitem(tool_router.INVOKERS, "kev_epss_enrich", fake_kev_real)

    script = [
        PlannerToolCall(tool="ct_subdomains", args={"domain": "example.com"}, reason="enumerate"),
        PlannerToolCall(tool="advance_phase", reason="done enumerating"),
        PlannerToolCall(tool="dns_resolve", args={"hostname": "www.example.com"}, reason="resolve"),
        PlannerToolCall(tool="advance_phase", reason="done resolving"),
        PlannerToolCall(tool="shodan_internetdb", args={"ip": "1.2.3.4"}, reason="check exposure"),
        PlannerToolCall(tool="advance_phase", reason="done"),
        PlannerToolCall(tool="email_auth", args={"domain": "example.com"}, reason="check email"),
        PlannerToolCall(tool="advance_phase", reason="done"),
        PlannerToolCall(tool="advance_phase", reason="nothing in leaks"),
        PlannerToolCall(tool="kev_epss_enrich", args={"cves": ["CVE-2021-44228"]}, reason="enrich"),
        PlannerToolCall(tool="advance_phase", reason="done"),
    ]

    async with _session_factory() as session:
        fetched_scan = await session.get(Scan, scan.id)
        assert fetched_scan is not None
        scan = fetched_scan
        async with httpx.AsyncClient() as client:
            orch = AgentOrchestrator(session, scan, _settings(), client, FakePlanner(script))
            events = [e async for e in orch.run()]

        assert scan.status == ScanStatus.COMPLETED
        assert any(e.type.value == "done" for e in events)
        assert any(e.type.value == "asset_added" for e in events)
        assert any(e.type.value == "finding_added" for e in events)

        from sqlalchemy import select
        from sqlmodel import col

        from vigia.db.models import Asset, Finding

        assets = (
            (await session.execute(select(Asset).where(col(Asset.scan_id) == scan.id)))
            .scalars()
            .all()
        )
        values = {a.value for a in assets}
        assert {"example.com", "www.example.com", "1.2.3.4"} <= values

        findings = (
            (await session.execute(select(Finding).where(col(Finding.scan_id) == scan.id)))
            .scalars()
            .all()
        )
        kev_finding = next(f for f in findings if f.cve == "CVE-2021-44228")
        assert kev_finding.kev is True
        assert kev_finding.epss == pytest.approx(0.9)


async def test_scope_violation_is_rejected_and_never_executed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = await _make_scan()
    executed = False

    async def fake_ct(args: dict[str, Any], ctx: object) -> ToolResult:
        nonlocal executed
        executed = True
        return _ok_result("ct_subdomains")

    monkeypatch.setitem(tool_router.INVOKERS, "whois_asn", _fake_whois_asn)
    monkeypatch.setitem(tool_router.INVOKERS, "ct_subdomains", fake_ct)

    script = [
        PlannerToolCall(
            tool="ct_subdomains", args={"domain": "evil.com"}, reason="scope escape attempt"
        ),
        PlannerToolCall(tool="advance_phase", reason="give up"),
    ]

    async with _session_factory() as session:
        fetched_scan = await session.get(Scan, scan.id)
        assert fetched_scan is not None
        scan = fetched_scan
        async with httpx.AsyncClient() as client:
            orch = AgentOrchestrator(session, scan, _settings(), client, FakePlanner(script))
            events = [e async for e in orch.run()]

    assert executed is False
    assert any(e.type.value == "error" and "evil.com" in e.data.get("message", "") for e in events)

    async with _session_factory() as session:
        from sqlalchemy import select
        from sqlmodel import col

        calls = (
            (await session.execute(select(ToolCall).where(col(ToolCall.scan_id) == scan.id)))
            .scalars()
            .all()
        )
        assert not any("evil.com" in str(c.args) for c in calls)


async def test_three_invalid_turns_trigger_deterministic_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = await _make_scan()
    fallback_calls: list[str] = []

    async def fake_ct(args: dict[str, Any], ctx: object) -> ToolResult:
        fallback_calls.append("ct_subdomains")
        return _ok_result("ct_subdomains")

    async def fake_subfinder(args: dict[str, Any], ctx: object) -> ToolResult:
        fallback_calls.append("subfinder_enum")
        return _ok_result("subfinder_enum")

    async def fake_wayback(args: dict[str, Any], ctx: object) -> ToolResult:
        fallback_calls.append("wayback_urls")
        return _ok_result("wayback_urls")

    async def fake_typosquat(args: dict[str, Any], ctx: object) -> ToolResult:
        fallback_calls.append("typosquat")
        return _ok_result("typosquat")

    monkeypatch.setitem(tool_router.INVOKERS, "whois_asn", _fake_whois_asn)
    monkeypatch.setitem(tool_router.INVOKERS, "ct_subdomains", fake_ct)
    monkeypatch.setitem(tool_router.INVOKERS, "subfinder_enum", fake_subfinder)
    monkeypatch.setitem(tool_router.INVOKERS, "wayback_urls", fake_wayback)
    monkeypatch.setitem(tool_router.INVOKERS, "typosquat", fake_typosquat)

    # Three consecutive invalid turns in ENUMERATE: a bogus tool name each time.
    script = [
        PlannerToolCall(tool="http_probe", reason="not allowed passively"),
        PlannerToolCall(tool="http_probe", reason="still not allowed"),
        PlannerToolCall(tool="http_probe", reason="really not allowed"),
        # After the fallback runs the whole ENUMERATE phase and auto-advances, the
        # planner is asked again starting at RESOLVE.
        PlannerToolCall(tool="advance_phase", reason="nothing to resolve"),
        PlannerToolCall(tool="advance_phase", reason="nothing in exposure"),
        PlannerToolCall(tool="advance_phase", reason="nothing in email"),
        PlannerToolCall(tool="advance_phase", reason="nothing in leaks"),
        PlannerToolCall(tool="advance_phase", reason="nothing to enrich"),
    ]

    async with _session_factory() as session:
        fetched_scan = await session.get(Scan, scan.id)
        assert fetched_scan is not None
        scan = fetched_scan
        async with httpx.AsyncClient() as client:
            planner = FakePlanner(script)
            orch = AgentOrchestrator(session, scan, _settings(), client, planner)
            events = [e async for e in orch.run()]

    assert set(fallback_calls) == {"ct_subdomains", "subfinder_enum", "wayback_urls", "typosquat"}
    assert any(
        e.type.value == "error" and "deterministic pipeline" in e.data.get("message", "")
        for e in events
    )
    assert scan.status == ScanStatus.COMPLETED


async def test_deep_dive_from_leaks_returns_to_risk_not_back_to_leaks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """deep_dive from LEAKS jumps to EXPOSURE; advance_phase from there must resume
    at RISK (the phase after LEAKS) — not loop back into LEAKS again."""
    scan = await _make_scan()
    monkeypatch.setitem(tool_router.INVOKERS, "whois_asn", _fake_whois_asn)

    async with _session_factory() as session:
        fetched_scan = await session.get(Scan, scan.id)
        assert fetched_scan is not None
        scan = fetched_scan
        async with httpx.AsyncClient() as client:
            orch = AgentOrchestrator(session, scan, _settings(), client, FakePlanner([]))
            domain_asset = await orch._upsert_asset("domain", scan.domain)
            orch._state.assets_by_value[scan.domain] = domain_asset

            script = [
                PlannerToolCall(tool="advance_phase", reason="nothing to enumerate"),
                PlannerToolCall(tool="advance_phase", reason="nothing to resolve"),
                PlannerToolCall(tool="advance_phase", reason="nothing in exposure"),
                PlannerToolCall(tool="advance_phase", reason="nothing in email"),
                # Now in LEAKS: deep dive back to EXPOSURE for the domain asset.
                PlannerToolCall(
                    tool="deep_dive", args={"asset_id": domain_asset.id}, reason="worth a look"
                ),
                PlannerToolCall(tool="advance_phase", reason="deep dive done"),
                PlannerToolCall(tool="advance_phase", reason="nothing to enrich"),
            ]
            orch.planner = FakePlanner(script)
            events = [e async for e in orch.run()]

    phase_changes = [
        (e.data.get("from_phase"), e.data.get("to_phase"))
        for e in events
        if e.type.value == "phase_changed"
    ]
    assert ("leaks", "exposure") in phase_changes  # the deep dive jump
    assert ("exposure", "risk") in phase_changes  # resumes AFTER leaks, not back into it
    assert ("leaks", "leaks") not in phase_changes
    assert scan.status == ScanStatus.COMPLETED


async def test_budget_exceeded_stops_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    scan = await _make_scan()
    monkeypatch.setitem(tool_router.INVOKERS, "whois_asn", _fake_whois_asn)

    async with _session_factory() as session:
        fetched_scan = await session.get(Scan, scan.id)
        assert fetched_scan is not None
        scan = fetched_scan
        async with httpx.AsyncClient() as client:
            settings = _settings(VIGIA_SCAN_MAX_STEPS=0)
            orch = AgentOrchestrator(session, scan, settings, client, FakePlanner([]))
            events = [e async for e in orch.run()]

    assert scan.status == ScanStatus.COMPLETED
    assert any(e.type.value == "done" for e in events)


async def test_stalled_enumeration_skips_only_that_phase_not_the_whole_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Found live via the Phase 8 benchmark lab (eval/README.md): 2 consecutive
    empty-handed tool calls in ENUMERATE used to abort the entire scan, silently
    skipping EXPOSURE/EMAIL_AND_SPOOFING/LEAKS/RISK even though those checks have
    nothing to do with subdomain discovery. It should give up on ENUMERATE only."""
    scan = await _make_scan()
    monkeypatch.setitem(tool_router.INVOKERS, "whois_asn", _fake_whois_asn)

    email_auth_called = False

    async def fake_ct(args: dict[str, Any], ctx: object) -> ToolResult:
        return _ok_result("ct_subdomains")  # no assets, every time

    async def fake_email_auth(args: dict[str, Any], ctx: object) -> ToolResult:
        nonlocal email_auth_called
        email_auth_called = True
        return _ok_result(
            "email_auth",
            findings=[
                FindingCandidate(
                    type="dmarc_missing", title="No DMARC", detail="...", asset_value="example.com"
                )
            ],
        )

    monkeypatch.setitem(tool_router.INVOKERS, "ct_subdomains", fake_ct)
    monkeypatch.setitem(tool_router.INVOKERS, "email_auth", fake_email_auth)

    script = [
        PlannerToolCall(tool="ct_subdomains", args={"domain": "example.com"}, reason="try 1"),
        PlannerToolCall(tool="ct_subdomains", args={"domain": "example.com"}, reason="try 2"),
        # ENUMERATE gets force-advanced here — RESOLVE/EXPOSURE are empty of
        # scripted tools below, so they auto-advance without consuming a turn.
        PlannerToolCall(tool="advance_phase", reason="nothing to resolve"),
        PlannerToolCall(tool="advance_phase", reason="nothing in exposure"),
        PlannerToolCall(
            tool="email_auth", args={"domain": "example.com"}, reason="check email auth"
        ),
        PlannerToolCall(tool="advance_phase", reason="done with email"),
        PlannerToolCall(tool="advance_phase", reason="nothing in leaks"),
        PlannerToolCall(tool="advance_phase", reason="nothing to enrich"),
    ]

    async with _session_factory() as session:
        fetched_scan = await session.get(Scan, scan.id)
        assert fetched_scan is not None
        scan = fetched_scan
        async with httpx.AsyncClient() as client:
            orch = AgentOrchestrator(session, scan, _settings(), client, FakePlanner(script))
            events = [e async for e in orch.run()]

    assert email_auth_called is True
    assert scan.status == ScanStatus.COMPLETED
    assert any(
        e.type.value == "error" and "moving to the next phase" in e.data.get("message", "")
        for e in events
    )
    assert any(
        e.type.value == "finding_added" and e.data.get("type") == "dmarc_missing" for e in events
    )


async def _make_active_scan(*, verification_token: str = "vigia-verify=test-token") -> Scan:
    async with _session_factory() as session:
        scan = Scan(
            domain="example.com",
            mode=ScanMode.ACTIVE,
            verification_token=verification_token,
            planner_model="fake-model",
            extractor_model="fake-model",
            status=ScanStatus.RUNNING,
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan


async def test_active_scan_fails_closed_without_a_matching_txt_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """VERIFY fails (no TXT record published, or wrong token) -> the scan stops
    immediately at VERIFY, status FAILED, and no tool — not even the passive
    whois_asn SEED lookup — ever runs."""
    scan = await _make_active_scan()
    ran_any_tool = False

    async def fail_verify(domain: str, expected_token: str) -> bool:
        return False

    async def fake_whois_asn(args: dict[str, Any], ctx: object) -> ToolResult:
        nonlocal ran_any_tool
        ran_any_tool = True
        return _ok_result("whois_asn")

    monkeypatch.setattr("vigia.agent.ownership.verify_ownership", fail_verify)
    monkeypatch.setitem(tool_router.INVOKERS, "whois_asn", fake_whois_asn)

    async with _session_factory() as session:
        fetched_scan = await session.get(Scan, scan.id)
        assert fetched_scan is not None
        scan = fetched_scan
        async with httpx.AsyncClient() as client:
            orch = AgentOrchestrator(session, scan, _settings(), client, FakePlanner([]))
            events = [e async for e in orch.run()]

    assert ran_any_tool is False
    assert scan.status == ScanStatus.FAILED
    assert scan.verified is False
    assert any(e.type.value == "error" for e in events)
    assert any(e.type.value == "done" for e in events)


async def test_active_scan_proceeds_once_ownership_is_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = await _make_active_scan()

    async def succeed_verify(domain: str, expected_token: str) -> bool:
        return True

    monkeypatch.setattr("vigia.agent.ownership.verify_ownership", succeed_verify)
    monkeypatch.setitem(tool_router.INVOKERS, "whois_asn", _fake_whois_asn)

    script = [
        PlannerToolCall(tool="advance_phase", reason="nothing to enumerate"),
        PlannerToolCall(tool="advance_phase", reason="nothing to resolve"),
        PlannerToolCall(tool="advance_phase", reason="nothing in exposure"),
        PlannerToolCall(tool="advance_phase", reason="nothing in email"),
        PlannerToolCall(tool="advance_phase", reason="nothing in leaks"),
        PlannerToolCall(tool="advance_phase", reason="nothing to enrich"),
    ]

    async with _session_factory() as session:
        fetched_scan = await session.get(Scan, scan.id)
        assert fetched_scan is not None
        scan = fetched_scan
        async with httpx.AsyncClient() as client:
            orch = AgentOrchestrator(session, scan, _settings(), client, FakePlanner(script))
            events = [e async for e in orch.run()]

    assert scan.verified is True
    assert scan.status == ScanStatus.COMPLETED
    phase_changes = [
        (e.data.get("from_phase"), e.data.get("to_phase"))
        for e in events
        if e.type.value == "phase_changed"
    ]
    assert ("verify", "seed") in phase_changes


async def test_active_tools_are_offered_only_once_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The EXPOSURE-phase tool schema built for the planner includes http_probe once
    `Scan.verified` is True — this is the actual reachability path a compromised
    planner would need, and it's gated on real verification, not on scan.mode alone."""
    scan = await _make_active_scan()

    async def succeed_verify(domain: str, expected_token: str) -> bool:
        return True

    monkeypatch.setattr("vigia.agent.ownership.verify_ownership", succeed_verify)
    monkeypatch.setitem(tool_router.INVOKERS, "whois_asn", _fake_whois_asn)

    called_with: dict[str, Any] = {}

    async def fake_http_probe(args: dict[str, Any], ctx: object) -> ToolResult:
        called_with.update(args)
        return _ok_result("http_probe")

    monkeypatch.setitem(tool_router.INVOKERS, "http_probe", fake_http_probe)

    script = [
        PlannerToolCall(tool="advance_phase", reason="nothing to enumerate"),
        PlannerToolCall(tool="advance_phase", reason="nothing to resolve"),
        PlannerToolCall(
            tool="http_probe", args={"hostname": "example.com"}, reason="active check"
        ),
        PlannerToolCall(tool="advance_phase", reason="done with exposure"),
        PlannerToolCall(tool="advance_phase", reason="nothing in email"),
        PlannerToolCall(tool="advance_phase", reason="nothing in leaks"),
        PlannerToolCall(tool="advance_phase", reason="nothing to enrich"),
    ]

    async with _session_factory() as session:
        fetched_scan = await session.get(Scan, scan.id)
        assert fetched_scan is not None
        scan = fetched_scan
        async with httpx.AsyncClient() as client:
            orch = AgentOrchestrator(session, scan, _settings(), client, FakePlanner(script))
            events = [e async for e in orch.run()]

    assert called_with == {"hostname": "example.com"}
    assert scan.status == ScanStatus.COMPLETED
    assert any(
        e.type.value == "tool_call" and e.data.get("tool") == "http_probe" for e in events
    )
