"""Deterministic Risk Engine (brief section 7).

`score = base × kev_mult × (1 + epss) × exposure_factor`. `base` is the CVE's real
CVSS v3 base score (fetched from NVD, cached — CVSS scores are effectively immutable
once published) when a CVE is known; otherwise a per-finding-type weight from
`weights.yaml`. See ADR-014/015 in docs/decisions.md for the CVSS source and the
weight calibration.

This never talks to the LLM — the Risk Engine is exactly the kind of scoring/
validation work the brief assigns to deterministic code, not the planner.
"""

from __future__ import annotations

import asyncio
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx
import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col

from vigia.db.models import Asset, Finding, FindingSeverity
from vigia.tools.base import request_with_retry

WEIGHTS_PATH = Path(__file__).parent / "weights.yaml"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVSS_CACHE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60  # CVSS base scores don't change
DEFAULT_CVSS_CACHE_PATH = Path.home() / ".cache" / "vigia" / "cvss.json"
NVD_RATE_LIMIT_SECONDS = 6.5  # NVD's public (no API key) limit is 5 req / 30s


@lru_cache(maxsize=1)
def load_weights() -> dict[str, Any]:
    return yaml.safe_load(WEIGHTS_PATH.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _read_cvss_cache(path: Path) -> dict[str, float]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _write_cvss_cache(path: Path, cache: dict[str, float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache), encoding="utf-8")


def _extract_base_score(cve_payload: dict[str, Any]) -> float | None:
    metrics = cve_payload.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0]["cvssData"]["baseScore"]  # type: ignore[no-any-return]
    return None


async def fetch_cvss_scores(
    client: httpx.AsyncClient,
    cves: list[str],
    *,
    cache_path: Path = DEFAULT_CVSS_CACHE_PATH,
    rate_limit_seconds: float = NVD_RATE_LIMIT_SECONDS,
) -> dict[str, float]:
    """CVSS v3 (falling back to v2) base score per CVE, from NVD, disk-cached."""
    cache = await asyncio.to_thread(_read_cvss_cache, cache_path)
    missing = [cve for cve in cves if cve not in cache]

    for cve in missing:
        await asyncio.sleep(rate_limit_seconds)
        try:
            response = await request_with_retry(
                client, "GET", NVD_CVE_URL, params={"cveId": cve}, retries=1
            )
            response.raise_for_status()
            vulnerabilities = response.json().get("vulnerabilities", [])
            if vulnerabilities:
                score = _extract_base_score(vulnerabilities[0]["cve"])
                if score is not None:
                    cache[cve] = score
        except httpx.HTTPError:
            continue  # fall back to the weights.yaml default for this CVE

    if missing:
        await asyncio.to_thread(_write_cvss_cache, cache_path, cache)
    return {cve: cache[cve] for cve in cves if cve in cache}


def _severity_for_score(score: float, thresholds: dict[str, float]) -> FindingSeverity:
    if score >= thresholds["critical"]:
        return FindingSeverity.CRITICAL
    if score >= thresholds["high"]:
        return FindingSeverity.HIGH
    if score >= thresholds["medium"]:
        return FindingSeverity.MEDIUM
    if score >= thresholds["low"]:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def _exposure_factor(asset_value: str | None, weights: dict[str, Any]) -> float:
    if not asset_value:
        return weights["default_exposure_factor"]  # type: ignore[no-any-return]
    lowered = asset_value.lower()
    for keyword, factor in weights["exposure_keywords"].items():
        if keyword in lowered:
            return factor  # type: ignore[no-any-return]
    return weights["default_exposure_factor"]  # type: ignore[no-any-return]


def score_finding(
    *,
    finding_type: str,
    cve: str | None,
    cvss_by_cve: dict[str, float],
    kev: bool,
    known_ransomware: bool,
    epss: float | None,
    asset_value: str | None,
    weights: dict[str, Any] | None = None,
) -> tuple[FindingSeverity, float]:
    """Pure function: everything the score formula needs, no DB/network access."""
    w = weights or load_weights()

    if cve and cve in cvss_by_cve:
        base = cvss_by_cve[cve]
    else:
        base = w["base_scores"].get(finding_type, w["default_base_score"])

    if kev:
        kev_mult = w["kev_ransomware_multiplier"] if known_ransomware else w["kev_multiplier"]
    else:
        kev_mult = 1.0

    exposure_factor = _exposure_factor(asset_value, w)
    score = round(base * kev_mult * (1 + (epss or 0.0)) * exposure_factor, 1)
    severity = _severity_for_score(score, w["severity_thresholds"])
    return severity, score


async def score_scan_findings(
    session: AsyncSession,
    scan_id: str,
    client: httpx.AsyncClient,
    *,
    cvss_rate_limit_seconds: float = NVD_RATE_LIMIT_SECONDS,
) -> int:
    """Re-score every `Finding` for `scan_id` in place. Returns the count updated."""
    weights = load_weights()

    findings_result = await session.execute(select(Finding).where(col(Finding.scan_id) == scan_id))
    findings = list(findings_result.scalars().all())

    cves = sorted({f.cve for f in findings if f.cve})
    cvss_by_cve = (
        await fetch_cvss_scores(client, cves, rate_limit_seconds=cvss_rate_limit_seconds)
        if cves
        else {}
    )

    assets_result = await session.execute(select(Asset).where(col(Asset.scan_id) == scan_id))
    asset_value_by_id = {a.id: a.value for a in assets_result.scalars().all()}

    for finding in findings:
        asset_value = asset_value_by_id.get(finding.asset_id or "")
        severity, score = score_finding(
            finding_type=finding.type,
            cve=finding.cve,
            cvss_by_cve=cvss_by_cve,
            kev=finding.kev,
            known_ransomware=finding.known_ransomware,
            epss=finding.epss,
            asset_value=asset_value,
            weights=weights,
        )
        finding.severity = severity
        finding.score = score

    await session.commit()
    return len(findings)
