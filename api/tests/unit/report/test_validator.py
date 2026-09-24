from __future__ import annotations

from vigia.report.models import ReportDraft, ReportFinding, TopRisk
from vigia.report.validator import EvidenceBase, strip_invalid_items, validate_report, validate_text


def _evidence() -> EvidenceBase:
    return EvidenceBase(
        domain="example.com",
        hostnames={"example.com", "www.example.com", "dev.example.com"},
        ips={"93.184.216.34"},
        cves={"CVE-2021-44228"},
        ports={"443", "22"},
        counts={"typosquat": 105, "subdomains": 2, "findings": 3, "cves": 1},
    )


def test_clean_text_has_no_violations() -> None:
    text = (
        "www.example.com resolves to 93.184.216.34 with port 443 open, affected by CVE-2021-44228."
    )
    assert validate_text(text, _evidence()) == []


def test_invented_domain_is_flagged() -> None:
    violations = validate_text("The attacker could pivot to evil-invented-host.net", _evidence())
    assert any("evil-invented-host.net" in v for v in violations)


def test_invented_ip_is_flagged() -> None:
    violations = validate_text("An open service was found at 10.0.0.99", _evidence())
    assert any("10.0.0.99" in v for v in violations)


def test_invented_cve_is_flagged() -> None:
    violations = validate_text("This is vulnerable to CVE-1999-9999", _evidence())
    assert any("CVE-1999-9999" in v for v in violations)


def test_invented_port_is_flagged() -> None:
    violations = validate_text("An admin panel was found on port 8443", _evidence())
    assert any("8443" in v for v in violations)


def test_subdomain_not_in_evidence_is_flagged() -> None:
    violations = validate_text("staging.example.com appears misconfigured", _evidence())
    assert any("staging.example.com" in v for v in violations)


def test_root_domain_always_allowed() -> None:
    assert validate_text("example.com has a solid DMARC policy.", _evidence()) == []


def test_common_abbreviations_are_not_false_positives() -> None:
    text = "The domain has good posture, e.g. DMARC is set to p=reject."
    assert validate_text(text, _evidence()) == []


def test_validate_report_finds_violations_per_section() -> None:
    draft = ReportDraft(
        executive_summary="Overall posture is reasonable for example.com.",
        top_risks=[TopRisk(title="Risk on evil.net", reason="invented host")],
        findings=[
            ReportFinding(
                title="Clean finding about www.example.com",
                explanation="No issues on www.example.com.",
                impact="none",
                remediation="none",
            ),
            ReportFinding(
                title="Bad finding",
                explanation="Found on totally-made-up.org",
                impact="high",
                remediation="fix it",
            ),
        ],
        positive_observations=["example.com has DMARC configured."],
    )
    violations = validate_report(draft, _evidence())
    assert "top_risks[0]" in violations
    assert "findings[1]" in violations
    assert "findings[0]" not in violations
    assert "executive_summary" not in violations


def test_strip_invalid_items_keeps_only_clean_content() -> None:
    draft = ReportDraft(
        executive_summary="example.com was scanned.",
        top_risks=[
            TopRisk(title="Real risk", reason="www.example.com has no DMARC"),
            TopRisk(title="Fake risk", reason="evil.net is compromised"),
        ],
        findings=[
            ReportFinding(
                title="Real finding", explanation="on www.example.com", impact="x", remediation="y"
            ),
            ReportFinding(
                title="Fake finding", explanation="on fake-host.biz", impact="x", remediation="y"
            ),
        ],
        positive_observations=["example.com has DNSSEC enabled.", "invented.tld looks fine too"],
    )
    cleaned, dropped = strip_invalid_items(draft, _evidence())

    assert len(cleaned.top_risks) == 1
    assert cleaned.top_risks[0].title == "Real risk"
    assert len(cleaned.findings) == 1
    assert cleaned.findings[0].title == "Real finding"
    assert len(cleaned.positive_observations) == 1
    assert "DNSSEC" in cleaned.positive_observations[0]
    assert len(dropped) == 3
    # The final, cleaned report has zero invented entities — the acceptance bar.
    assert validate_report(cleaned, _evidence()) == {}


def test_wrong_typosquat_count_is_flagged() -> None:
    # Real regression: a live report claimed "37 potential look-alike domain names"
    # when the scan's evidence actually had 105 typosquat findings.
    violations = validate_text(
        "A total of 37 potential look-alike domain names were identified.", _evidence()
    )
    assert any("37" in v and "105" in v for v in violations)


def test_correct_typosquat_count_is_not_flagged() -> None:
    violations = validate_text(
        "A total of 105 potential look-alike domains were identified.", _evidence()
    )
    assert violations == []


def test_wrong_subdomain_count_is_flagged() -> None:
    violations = validate_text("The scan found 9 subdomains for example.com.", _evidence())
    assert any("subdomains" in v for v in violations)


def test_unrelated_numbers_are_not_flagged() -> None:
    text = "This is the 3rd time we've seen this pattern in 12 previous engagements."
    assert validate_text(text, _evidence()) == []
