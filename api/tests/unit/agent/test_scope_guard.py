import pytest

from vigia.agent.scope_guard import ScopeGuard, ScopeViolation


def test_root_domain_is_in_scope() -> None:
    guard = ScopeGuard(root_domain="example.com")
    guard.validate("whois_asn", {"resource": "example.com"})


def test_known_subdomain_is_in_scope() -> None:
    guard = ScopeGuard(root_domain="example.com")
    guard.add_subdomain("www.example.com")
    guard.validate("dns_resolve", {"hostname": "www.example.com"})


def test_unseen_but_valid_subdomain_shape_is_in_scope() -> None:
    # Even if not yet recorded, anything that's literally a subdomain of the root
    # is in scope (e.g. the planner guessing a hostname before it's been resolved).
    guard = ScopeGuard(root_domain="example.com")
    guard.validate("dns_resolve", {"hostname": "api.example.com"})


def test_typosquat_domain_is_rejected() -> None:
    guard = ScopeGuard(root_domain="example.com")
    with pytest.raises(ScopeViolation):
        guard.validate("ct_subdomains", {"domain": "examp1e.com"})


def test_unrelated_domain_is_rejected() -> None:
    guard = ScopeGuard(root_domain="example.com")
    with pytest.raises(ScopeViolation):
        guard.validate("whois_asn", {"resource": "evil.com"})


def test_unresolved_ip_is_rejected() -> None:
    guard = ScopeGuard(root_domain="example.com")
    with pytest.raises(ScopeViolation):
        guard.validate("shodan_internetdb", {"ip": "1.2.3.4"})


def test_resolved_ip_is_accepted() -> None:
    guard = ScopeGuard(root_domain="example.com")
    guard.add_ip("93.184.216.34")
    guard.validate("shodan_internetdb", {"ip": "93.184.216.34"})


def test_args_with_no_target_field_pass_through() -> None:
    guard = ScopeGuard(root_domain="example.com")
    guard.validate("kev_epss_enrich", {"cves": ["CVE-2021-44228"]})
