"""Domain-ownership verification: `TXT vigia-verify=<token>` on the root domain.

Per brief section 6.1: active-mode tools are only allowed once this check passes.
Passive mode never needs it. Full active-mode wiring (the tools themselves) is
Phase 7 — this module exists now so the VERIFY state in the agent state machine has
something real to do, and so the guardrail has tests from the phase it's introduced.
"""

from __future__ import annotations

import secrets

import dns.asyncresolver
import dns.exception
import dns.resolver

TOKEN_PREFIX = "vigia-verify="


def generate_token() -> str:
    return TOKEN_PREFIX + secrets.token_hex(16)


async def verify_ownership(domain: str, expected_token: str) -> bool:
    """Check whether `expected_token` (as returned by `generate_token`) is published
    as a TXT record on `domain`'s root. Returns False on any DNS error — ownership
    verification fails closed, never open."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0
    try:
        answer = await resolver.resolve(domain, "TXT")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return False

    for rdata in answer:
        # dnspython returns TXT records as one or more quoted byte-strings; join them.
        value = "".join(
            part.decode() if isinstance(part, bytes) else part for part in rdata.strings
        )
        if value.strip() == expected_token:
            return True
    return False
