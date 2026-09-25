# Ethics & Scope

Vigía is an External Attack Surface Management (EASM) reconnaissance tool. It exists
to help defenders understand what an attacker could see about infrastructure they
are responsible for — nothing else. This document is the actual policy (Phase 9);
earlier phases carried a placeholder pointing here.

## Permitted use

Vigía may be run **only** against a domain you own, or for which you hold explicit,
current, written authorization to test (a penetration-testing engagement letter, a
bug-bounty program's published scope, or equivalent). This applies to every mode —
passive and active — and every interface: the CLI, the API, and the web GUI.

You are responsible for the domains you submit. Nothing in this tool asks a third
party to confirm you have that authorization; the guardrails below stop Vigía from
doing anything *beyond* what you configured it to target, not from being pointed at
the wrong target in the first place. That judgment call is yours, made before you
type a domain in.

## What Vigía will not do

Out of scope by design, not just by omission:

- **No exploitation.** Every tool is reconnaissance-only — it observes and reports
  (a TLS certificate's expiry date, a missing security header, a dangling CNAME's
  response body) and never attempts to gain access, execute code on a target, or
  exfiltrate data from one.
- **No credential brute-forcing or aggressive fuzzing.** Active mode (Phase 7) makes
  a small, fixed number of read-only requests per discovered host — a GET, a TLS
  handshake, a page render — not a scan of paths, parameters, or credentials.
- **No personal/identity enrichment.** Findings are about infrastructure (hosts,
  certificates, DNS records, published secrets) — Vigía does not attempt to identify,
  profile, or enrich data about the individuals behind a domain.
- **No third-party domains, ever.** The LLM planner can request tools, but every
  request is checked in code (Scope Guard, below) against the one domain the scan
  was started for — including domains the planner itself invents mid-scan (a
  typosquat lookalike, a domain named in a prompt-injection payload). There is no
  code path that expands scope; see `tests/injection/` for the adversarial test
  suite that exercises this directly.

## Guardrails, concretely

| Guardrail | What it does | Where |
|---|---|---|
| **First-run consent** | Every scan — CLI, API, or GUI — is refused until the operator explicitly accepts the notice below. Not a UI-only checkbox: enforced in the scan-creation code path itself. | `api/vigia/ethics.py` |
| **Scope Guard** | Every tool call's target (`domain`/`hostname`/`ip`) is checked against the scan's own root domain and its already-discovered subdomains/IPs before the tool runs. Anything else is rejected before it reaches the network. | `api/vigia/agent/scope_guard.py` |
| **Sanitizer** | Text a tool pulled from the public internet (a WHOIS field, an HTML title, a TXT record) is neutralized — instruction-like phrasing stripped, length capped, wrapped in explicit `<untrusted_data>` delimiters — before it reaches the planner's context, so a compromised/malicious response can't act as a prompt-injection vector. | `api/vigia/agent/sanitizer.py` |
| **Phase/tool allowlist** | The planner can only request tools registered for the scan's *current* phase — there's no tool that lets it "jump ahead" or invoke something out of sequence. | `api/vigia/agent/tool_router.py` |
| **Domain-ownership verification (active mode)** | `http_probe`/`tls_check`/`screenshot` — the only tools that make requests beyond passive OSINT lookups — are unreachable until a `vigia-verify=<token>` DNS TXT record is confirmed on the target's root. Verification fails closed: a DNS error or a missing/wrong record stops the whole scan, never silently degrades to "skip active mode." | `api/vigia/agent/ownership.py` |
| **Immutable audit log** | Every tool call — allowed or rejected, successful or errored — is recorded with its arguments, reasoning, timing, and a hash of the raw output, exportable per scan. | `ToolCall` model, `GET /scans/{id}/audit` |
| **Report entity validation** | The LLM drafts the human-readable report, but every domain/IP/CVE/port/count it mentions is checked against that scan's own stored evidence; anything unverifiable is regenerated or dropped, never shipped as if it were a finding. | `api/vigia/report/validator.py` |

## The first-run notice

This is the literal text every operator must accept before any scan runs
(`api/vigia/ethics.py::ETHICS_NOTICE`):

> Vigía may only be used against domains you own or are explicitly authorized to
> test. Scanning third-party infrastructure without authorization may be illegal. By
> accepting, you confirm you have the right to scan the domains you submit.

## Data handling

- Raw tool output (evidence) is stored gzip-compressed in the database alongside a
  SHA-256 hash — enough to audit exactly what a finding was based on, nothing more
  is collected or retained.
- OSINT source API keys (Censys, GitHub, HIBP) are encrypted at rest
  (`api/vigia/crypto.py`, Fernet, key derived from `VIGIA_SECRET_KEY`) and never
  echoed back by the API once set.
- Nothing here calls out to any third-party analytics or telemetry service; the only
  outbound calls a scan makes are the OSINT sources its own tools query, and (for the
  LLM) your own configured Ollama instance.

## Development practice

This repository's own `CLAUDE.md` binds contributors (human or AI) to the same
rule the tool enforces on its users: real active-mode tool runs and dogfooding only
happen against a domain the developer owns or a declared lab target; automated
tests use mocked responses or short-lived local servers (never a real domain), even
for tools that would otherwise make real network requests.

## Legal disclaimer

Vigía is provided as-is, under the [MIT License](../LICENSE), with no warranty. It
is a reconnaissance tool, not a legal opinion — whether a given scan is authorized
is a determination the operator makes, informed by their own contracts, program
scope, and applicable law. Misuse is the operator's responsibility, not this
project's.
