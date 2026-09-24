"""End-to-end test of the deterministic passive pipeline against a real (test) DB.

All external calls are mocked (respx for HTTP, monkeypatch for DNS/subprocess) — per
the brief's rule 6, no real network calls happen in the automated test suite.
"""

from __future__ import annotations

import checkdmarc
import dns.asyncresolver
import dns.resolver
import pytest
import respx
from sqlalchemy import select
from sqlmodel import col

import vigia.tools.subfinder_enum as subfinder_module
import vigia.tools.typosquat as typosquat_module
from vigia.config import Settings
from vigia.db.models import Asset, Finding, Scan, ToolCall
from vigia.db.session import _session_factory
from vigia.ethics import accept as accept_ethics_notice
from vigia.pipeline import run_passive_scan

DNS_A_ANSWERS = {
    "example.com": ["93.184.216.34"],
    "www.example.com": ["93.184.216.35"],
}


class _FakeRdata:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


async def _fake_resolve(self: object, hostname: str, rtype: str) -> list[_FakeRdata]:
    if rtype == "A" and hostname in DNS_A_ANSWERS:
        return [_FakeRdata(ip) for ip in DNS_A_ANSWERS[hostname]]
    raise dns.resolver.NXDOMAIN()


def _fake_check_domains(domains: list[str], **kwargs: object) -> dict[str, object]:
    return {
        "domain": domains[0],
        "spf": {"valid": True},
        "dmarc": {"valid": True, "tags": {"p": {"value": "reject"}}},
    }


async def _fake_run_subprocess_missing(
    *args: str, timeout_seconds: float = 60.0
) -> tuple[int, bytes, bytes]:
    raise FileNotFoundError()


@respx.mock
async def test_passive_pipeline_persists_assets_and_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", _fake_resolve)
    monkeypatch.setattr(checkdmarc, "check_domains", _fake_check_domains)
    monkeypatch.setattr(subfinder_module, "run_subprocess", _fake_run_subprocess_missing)
    monkeypatch.setattr(typosquat_module, "run_subprocess", _fake_run_subprocess_missing)

    respx.get("https://stat.ripe.net/data/whois/data.json").respond(json={"data": {}})
    respx.get("https://stat.ripe.net/data/network-info/data.json").respond(
        json={"data": {"asns": [], "prefix": ""}}
    )
    respx.get("https://crt.sh/").respond(json=[{"name_value": "www.example.com"}])
    respx.get("https://internetdb.shodan.io/93.184.216.34").respond(
        json={
            "ip": "93.184.216.34",
            "ports": [443],
            "cpes": [],
            "hostnames": [],
            "tags": [],
            "vulns": ["CVE-2021-44228"],
        }
    )
    respx.get("https://internetdb.shodan.io/93.184.216.35").respond(status_code=404)
    respx.get("http://web.archive.org/cdx/search/cdx").respond(
        json=[["original"], ["http://example.com/"]]
    )
    respx.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ).respond(
        json={
            "vulnerabilities": [{"cveID": "CVE-2021-44228", "knownRansomwareCampaignUse": "Known"}]
        }
    )
    respx.get("https://api.first.org/data/v1/epss").respond(
        json={"data": [{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"}]}
    )

    settings = Settings(
        VIGIA_PLANNER_MODEL="qwen3.6:35b",
        VIGIA_EXTRACTOR_MODEL="granite4.1:8b",
    )

    async with _session_factory() as session:
        await accept_ethics_notice(session)
        summary = await run_passive_scan(session, "example.com", settings)

        assert summary.status == "completed"
        assert summary.assets_count >= 3  # domain, subdomain, at least one IP

        scan = await session.get(Scan, summary.scan_id)
        assert scan is not None
        assert scan.status == "completed"

        assets = (
            (await session.execute(select(Asset).where(col(Asset.scan_id) == scan.id)))
            .scalars()
            .all()
        )
        asset_values = {a.value for a in assets}
        assert "example.com" in asset_values
        assert "www.example.com" in asset_values
        assert "93.184.216.34" in asset_values

        findings = (
            (await session.execute(select(Finding).where(col(Finding.scan_id) == scan.id)))
            .scalars()
            .all()
        )
        kev_finding = next((f for f in findings if f.cve == "CVE-2021-44228"), None)
        assert kev_finding is not None
        assert kev_finding.kev is True
        assert kev_finding.epss == pytest.approx(0.97)

        tool_calls = (
            (await session.execute(select(ToolCall).where(col(ToolCall.scan_id) == scan.id)))
            .scalars()
            .all()
        )
        tool_names = {tc.tool for tc in tool_calls}
        assert "whois_asn" in tool_names
        assert "ct_subdomains" in tool_names
        assert "shodan_internetdb" in tool_names
        assert "kev_epss_enrich" in tool_names
