"""Scope Guard: the LLM can request tools, but never expand what's in scope.

Per brief section 6.2: only the target domain, its subdomains, and IPs they resolve
to are in scope. New root domains (typosquat matches, off-scope hosts a compromised
or confused planner might try to target) are rejected outright — they can still be
*recorded* as informational findings elsewhere in the pipeline, but no tool is ever
allowed to run against them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Tool input fields that name a target — every tool's Pydantic input model uses one
# of these names for "the thing we're looking at".
TARGET_FIELDS = ("domain", "hostname", "resource", "ip")


class ScopeViolation(Exception):
    """Raised when a tool call targets something outside the scan's scope."""


@dataclass
class ScopeGuard:
    root_domain: str
    known_subdomains: set[str] = field(default_factory=set)
    known_ips: set[str] = field(default_factory=set)

    def add_subdomain(self, hostname: str) -> None:
        self.known_subdomains.add(hostname.lower())

    def add_ip(self, ip: str) -> None:
        self.known_ips.add(ip)

    def _in_domain_scope(self, value: str) -> bool:
        value = value.lower().rstrip(".")
        root = self.root_domain.lower()
        return value == root or value in self.known_subdomains or value.endswith(f".{root}")

    def validate(self, tool_name: str, args: dict[str, object]) -> None:
        """Raise `ScopeViolation` if any target field in `args` is out of scope."""
        for field_name in TARGET_FIELDS:
            if field_name not in args:
                continue
            value = str(args[field_name])
            if field_name == "ip":
                if value not in self.known_ips:
                    raise ScopeViolation(
                        f"{tool_name}: IP {value!r} has not been resolved for "
                        f"{self.root_domain} in this scan — refusing to query it."
                    )
            elif not self._in_domain_scope(value):
                raise ScopeViolation(
                    f"{tool_name}: {value!r} is not {self.root_domain} or one of its "
                    "known subdomains — refusing to expand scope."
                )
