from __future__ import annotations

import httpx
import respx

from vigia.risk.engine import fetch_cvss_scores, load_weights, score_finding


def test_dangling_dns_has_high_base_score() -> None:
    severity, score = score_finding(
        finding_type="dangling_dns_candidate",
        cve=None,
        cvss_by_cve={},
        kev=False,
        known_ransomware=False,
        epss=None,
        asset_value="static.example.com",
    )
    assert severity.value == "critical"
    assert score == 9.0


def test_unknown_finding_type_uses_default_base_score() -> None:
    weights = load_weights()
    severity, score = score_finding(
        finding_type="some_new_type_not_in_weights",
        cve=None,
        cvss_by_cve={},
        kev=False,
        known_ransomware=False,
        epss=None,
        asset_value=None,
    )
    assert score == weights["default_base_score"]
    assert severity.value == "low"


def test_kev_multiplier_applied() -> None:
    _, score_no_kev = score_finding(
        finding_type="known_vulnerability",
        cve="CVE-2021-1",
        cvss_by_cve={"CVE-2021-1": 5.0},
        kev=False,
        known_ransomware=False,
        epss=None,
        asset_value=None,
    )
    _, score_kev = score_finding(
        finding_type="known_vulnerability",
        cve="CVE-2021-1",
        cvss_by_cve={"CVE-2021-1": 5.0},
        kev=True,
        known_ransomware=False,
        epss=None,
        asset_value=None,
    )
    assert score_kev == round(score_no_kev * 1.5, 1)


def test_ransomware_multiplier_is_higher_than_plain_kev() -> None:
    _, score_kev = score_finding(
        finding_type="known_vulnerability",
        cve="CVE-2021-1",
        cvss_by_cve={"CVE-2021-1": 5.0},
        kev=True,
        known_ransomware=False,
        epss=None,
        asset_value=None,
    )
    _, score_ransomware = score_finding(
        finding_type="known_vulnerability",
        cve="CVE-2021-1",
        cvss_by_cve={"CVE-2021-1": 5.0},
        kev=True,
        known_ransomware=True,
        epss=None,
        asset_value=None,
    )
    assert score_ransomware > score_kev


def test_epss_increases_score() -> None:
    _, score_no_epss = score_finding(
        finding_type="known_vulnerability",
        cve="CVE-2021-1",
        cvss_by_cve={"CVE-2021-1": 5.0},
        kev=False,
        known_ransomware=False,
        epss=None,
        asset_value=None,
    )
    _, score_high_epss = score_finding(
        finding_type="known_vulnerability",
        cve="CVE-2021-1",
        cvss_by_cve={"CVE-2021-1": 5.0},
        kev=False,
        known_ransomware=False,
        epss=0.9,
        asset_value=None,
    )
    assert score_high_epss > score_no_epss


def test_dev_hostname_increases_exposure_factor() -> None:
    _, score_prod = score_finding(
        finding_type="dmarc_missing",
        cve=None,
        cvss_by_cve={},
        kev=False,
        known_ransomware=False,
        epss=None,
        asset_value="www.example.com",
    )
    _, score_dev = score_finding(
        finding_type="dmarc_missing",
        cve=None,
        cvss_by_cve={},
        kev=False,
        known_ransomware=False,
        epss=None,
        asset_value="dev.example.com",
    )
    assert score_dev > score_prod


def test_cve_uses_real_cvss_over_type_default() -> None:
    _, score_low_cvss = score_finding(
        finding_type="known_vulnerability",
        cve="CVE-2021-1",
        cvss_by_cve={"CVE-2021-1": 2.0},
        kev=False,
        known_ransomware=False,
        epss=None,
        asset_value=None,
    )
    assert score_low_cvss == 2.0  # not the weights.yaml fallback of 5.0


def test_severity_thresholds_map_correctly() -> None:
    weights = load_weights()
    thresholds = weights["severity_thresholds"]
    cases = [
        (thresholds["critical"], "critical"),
        (thresholds["high"], "high"),
        (thresholds["medium"], "medium"),
        (thresholds["low"], "low"),
        (0.1, "info"),
    ]
    for base_score, expected_severity in cases:
        severity, _ = score_finding(
            finding_type="network_info",
            cve="CVE-fake",
            cvss_by_cve={"CVE-fake": base_score},
            kev=False,
            known_ransomware=False,
            epss=None,
            asset_value=None,
        )
        assert severity.value == expected_severity


@respx.mock
async def test_fetch_cvss_scores_parses_nvd_response(tmp_path) -> None:  # type: ignore[no-untyped-def]
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").respond(
        json={
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                        }
                    }
                }
            ]
        }
    )

    async with httpx.AsyncClient() as client:
        scores = await fetch_cvss_scores(
            client,
            ["CVE-2021-44228"],
            cache_path=tmp_path / "cvss.json",
            rate_limit_seconds=0,
        )

    assert scores == {"CVE-2021-44228": 9.8}


@respx.mock
async def test_fetch_cvss_scores_uses_cache_on_second_call(tmp_path) -> None:  # type: ignore[no-untyped-def]
    route = respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").respond(
        json={
            "vulnerabilities": [
                {"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}}}
            ]
        }
    )
    cache_path = tmp_path / "cvss.json"

    async with httpx.AsyncClient() as client:
        await fetch_cvss_scores(client, ["CVE-2021-1"], cache_path=cache_path, rate_limit_seconds=0)
        await fetch_cvss_scores(client, ["CVE-2021-1"], cache_path=cache_path, rate_limit_seconds=0)

    assert route.call_count == 1


@respx.mock
async def test_fetch_cvss_scores_skips_cve_on_http_error(tmp_path) -> None:  # type: ignore[no-untyped-def]
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").respond(status_code=404)

    async with httpx.AsyncClient() as client:
        scores = await fetch_cvss_scores(
            client,
            ["CVE-nonexistent"],
            cache_path=tmp_path / "cvss.json",
            rate_limit_seconds=0,
        )

    assert scores == {}
