# Architecture Decision Records

Short ADRs for decisions made autonomously during development, per the project brief's
"choose the reasonable option and document it" rule. Newest first.

## ADR-017: Report Validator also checks claimed counts ("cifras"), keyword-anchored

- **Context:** brief section 7.2 says the Report Validator extracts "domains, IPs,
  CVEs, ports, figures" — the validator initially only checked the first four.
- **Decision:** a real live report generation against a real scan (105 typosquat
  findings for `example.com`) surfaced exactly this gap: the LLM wrote "37 potential
  look-alike domain names" — no invented domain/IP/CVE/port, so the original
  validator passed it, but the number was simply wrong (105, not 37). Added a
  narrow, keyword-anchored count check: a number is only validated when it appears
  near one of a fixed set of countable-noun phrases (`look-alike domain(s)`,
  `subdomain(s)`, `finding(s)`, `vulnerabilit(y/ies)`/`CVE(s)`), each mapped to a
  real count computed from the scan's evidence (`EvidenceBase.counts`). Deliberately
  narrow rather than "flag any number not equal to some count" — that would false-
  positive on ordinary prose ("the 3rd time", severity scores, dates).
- **Consequence:** re-running the same real report generation after this fix
  produced a report with the correct count and no regeneration needed — see the
  regression test `test_wrong_typosquat_count_is_flagged` in
  `tests/unit/report/test_validator.py`, taken directly from the live output.

## ADR-016: PDF export via Playwright (headless Chromium), not WeasyPrint

- **Context:** brief section 7.4 allows either WeasyPrint or Playwright for PDF
  export.
- **Decision:** tried WeasyPrint first (it's the brief's first-listed option) and
  verified live: it failed to import on this Windows dev machine —
  `OSError: cannot load library 'libgobject-2.0-0'` — because it needs system
  GTK/Pango/Cairo libraries that aren't part of a normal Python install. Playwright
  bundles its own Chromium and rendered a real PDF successfully on the same machine
  with no extra setup beyond `playwright install chromium`. Switched to Playwright;
  `api/Dockerfile` and CI now run that install step (Chromium + its Linux system
  deps via `--with-deps`) so the Docker image and CI have the same capability.
- **Consequence:** the PDF exporter renders the same Markdown the `.md` exporter
  produces (wrapped in minimal HTML/CSS), so there's exactly one place report layout
  lives, and the PDF test in `tests/unit/report/test_exporters.py` generates a real
  PDF, not a mock.

## ADR-015: `Finding.known_ransomware` added as a real column, not recomputed

- **Context:** the Risk Engine's `kev_mult` needs 1.8 when a CVE is used in
  ransomware, per brief section 7. Phase 2/3's `kev_epss_enrich` tool already
  computes this (`known_ransomware` in its enrichment payload) but the pipeline and
  orchestrator were only copying `in_kev` and `epss` onto the `Finding` row, silently
  dropping the ransomware flag.
- **Decision:** added `Finding.known_ransomware: bool` (migration
  `964300d982ea_add_finding_known_ransomware`, `server_default=false` so it's safe
  on non-empty tables) and updated both scan paths to persist it. The Risk Engine
  reads it directly from the `Finding` row rather than re-fetching/re-parsing the
  KEV catalog at scoring time.
- **Consequence:** re-running `vigia score <scan_id>` on scans created before this
  migration will show `known_ransomware=False` for all their findings (the flag
  wasn't captured at scan time) — acceptable for a pre-release project; would need a
  backfill (re-run `kev_epss_enrich`) if this mattered for real historical data.

## ADR-014: CVSS scores come from the NVD CVE API, not the brief's tool list

- **Context:** brief section 7's Risk Engine formula uses "CVSS if there's a CVE" as
  the base score, but the brief's tool table (section 4) has no CVSS-lookup tool —
  `shodan_internetdb` and `kev_epss_enrich` supply a CVE id but not its CVSS score.
- **Decision:** added a small NVD CVE API v2.0 lookup
  (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`) inside
  `risk/engine.py`, not as a registered agent tool — it's scoring infrastructure the
  planner never decides to invoke, not an OSINT reconnaissance step. Verified live
  against `CVE-2021-44228`; prefers `cvssMetricV31`, then `V30`, then `V2`. Disk-cached
  per CVE for 7 days (CVSS base scores are essentially immutable once published) and
  rate-limited to ~1 request/6.5s to respect NVD's public (no API key) limit of
  5 requests/30s. A CVE that NVD doesn't have (or a request that fails) falls back to
  `weights.yaml`'s flat `known_vulnerability` base score rather than blocking scoring.
- **Consequence:** scoring a scan with many distinct CVEs is slow (the rate limit
  dominates) — acceptable for a report generated once per scan, not on a hot path.
  An NVD API key (not yet wired up) would raise the limit to 50/30s if this becomes
  a bottleneck.

## ADR-013: model availability check calls `show()` per model, not `list()`

- **Context:** brief section 2 requires checking which Ollama models are installed
  and support tool-calling at startup, falling back to an installed one if the
  configured model is missing.
- **Decision:** verified live against a real local Ollama instance: the installed
  `ollama` Python package's `Client.list()` (`/api/tags`) does **not** surface a
  model's `capabilities` field, even though the raw HTTP endpoint includes it —
  `Client.show()` (`/api/show`) does return it. `check_model_availability()`
  therefore lists installed models, then calls `show()` on each to filter for
  tool-calling support. Confirmed working live: with `qwen3.6:35b` unset locally, it
  correctly fell back to an installed `qwen2.5:14b-instruct`.
- **Consequence:** one extra HTTP round-trip per installed model at scan start —
  negligible for a local Ollama instance with a handful of models.

## ADR-012: deep dive resumes at the phase *after* the one it interrupted

- **Context:** brief section 5 says `deep_dive` "returns to EXPOSURE for that asset"
  but doesn't specify what happens when the planner is done with the deep dive.
- **Decision:** the orchestrator records the phase the deep dive interrupted
  (`deep_dive_return_phase`); the next `advance_phase` call resumes at the phase
  *after* that one, not back at the interrupted phase itself. E.g. a deep dive
  triggered from LEAKS jumps to EXPOSURE, and finishing it resumes at RISK, not back
  at LEAKS. Verified with `test_deep_dive_from_leaks_returns_to_risk_not_back_to_leaks`.
- **Consequence:** a phase is never revisited from scratch because of a deep dive —
  only the specific asset gets the extra EXPOSURE-phase look.

## ADR-011: SEED runs deterministically; no-new-assets early stop is scoped to
  discovery phases only

- **Context:** live testing (real Ollama, real `whois_asn` call against
  `example.com`) surfaced a real bug: SEED's only tool (`whois_asn`) discovers *ASN
  info*, not new *assets*, for a bare domain (it only enriches ASN when given an IP).
  With SEED as an LLM-driven phase, the planner had nothing else to call, re-called
  the same tool, and the "2 consecutive iterations with no new assets" early-stop
  (brief section 5) killed the scan before it reached ENUMERATE.
- **Decision:** two fixes. (1) SEED now runs its tool(s) deterministically and
  auto-advances, like VERIFY/REPORT — it needs no planner judgment. (2) The
  no-new-assets counter only applies in phases whose tools are meant to discover
  assets (ENUMERATE, RESOLVE, EXPOSURE); EMAIL_AND_SPOOFING/LEAKS/RISK tools
  (`email_auth`, `github_leaks`, `hibp_domain`, `kev_epss_enrich`) are findings-only
  by design and would otherwise trip an early stop for entirely expected behavior.
- **Consequence:** caught and fixed before this phase's tests were even written,
  purely from real end-to-end verification — a good example of why rule 6 ("verify
  passively against a real domain") earns its place even for internal logic bugs,
  not just API-shape assumptions.

## ADR-010: `Planner` as a `Protocol`, not a concrete-class dependency

- **Context:** `AgentOrchestrator` needs a planner (real Ollama-backed in
  production, a scripted fake in tests) to decide each step.
- **Decision:** `agent/llm_client.py` defines a `Planner` Protocol (structural
  typing: anything with a matching `async def decide(...)`) instead of requiring
  the concrete `PlannerClient` class. `AgentOrchestrator.__init__` takes
  `planner: Planner`. Test fakes (`FakePlanner`) satisfy it with zero coupling to
  the real Ollama client.
- **Consequence:** orchestrator tests run fully offline and deterministically,
  scripting exact planner decisions per phase, while mypy strict still checks the
  interface shape.

## ADR-009: phase-to-tool mapping and the agent state machine's exact semantics

- **Context:** brief section 5 names the phases (VERIFY → SEED → ENUMERATE →
  RESOLVE → EXPOSURE → EMAIL_AND_SPOOFING → LEAKS → RISK → REPORT → DONE) but not
  which of the 13 passive tools belongs to which phase.
- **Decision:** mapped tools to phases by what they discover (see
  `agent/phases.py::PHASE_TOOLS`), reusing the same phase-name strings the Phase 2
  pipeline already writes to `ToolCall.phase` for audit-log consistency. VERIFY and
  REPORT have no tools yet (ownership verification only matters for active mode —
  Phase 7; the Report Writer is Phase 4) and auto-advance without consuming a
  planner turn. A tool call is rejected before it runs if the planner requests a
  tool outside the current phase's allowlist (`tool_router.invoke`).
- **Consequence:** this mapping (and REPORT's no-op) will need revisiting once
  Phase 4's Report Writer exists — tracked as follow-up, not urgent now.

## ADR-008: ethical-use notice is a `Setting` row, enforced in both scan entrypoints

- **Context:** brief section 6.9 requires a first-run ethical-use notice the operator
  must accept before scanning; the UI checkbox for this is Phase 5/6 scope.
- **Decision:** a single `Setting` row (`ethical_notice_accepted_at`) records
  acceptance; `vigia.ethics.ensure_accepted()` is called at the start of both scan
  entrypoints — the Phase 2 deterministic pipeline (`pipeline.run_passive_scan`) and
  the Phase 3 agent (`orchestrator.run_agent_scan`) — raising
  `EthicsNoticeNotAccepted` if it hasn't been accepted. A `vigia ethics --accept` CLI
  command and (implicitly, via the same check) the `/scans/agent` API endpoint are
  the two ways to hit this gate today.
- **Consequence:** no scan can run — from any entrypoint — until the notice is
  accepted once. The real UI acceptance flow (Phase 5/6) will call the same
  `ethics.accept()` function.

## ADR-007: `dnspython` for `dns_resolve`/`dangling_dns`, `dnsx` left out of the image

- **Context:** brief section 4 allows `dnsx` (ProjectDiscovery Go binary) *or*
  `dnspython` for the `dns_resolve` tool.
- **Decision:** used `dnspython` (`dns.asyncresolver`) for both `dns_resolve` and
  `dangling_dns`'s CNAME-chain walk. It needs no external binary, so local dev and CI
  don't depend on a Docker-only tool, and its async resolver fits the tool wrappers'
  async signatures directly. `dnsx` isn't installed in `api/Dockerfile`.
- **Consequence:** if a later phase needs `dnsx`'s bulk-resolution speed (e.g. the
  agent resolving hundreds of hosts concurrently), it can be added then without
  changing `dns_resolve`'s public contract.

## ADR-006: `email_auth` checks DKIM manually — `checkdmarc` doesn't support it

- **Context:** brief section 4 says `email_auth` uses `checkdmarc` for "SPF, DKIM
  (common selectors) and DMARC".
- **Decision:** verified `checkdmarc==6.0.3` (installed 2026-09-24) live against
  `example.com`: `checkdmarc.check_domains()` returns SPF, DMARC, MX, DNSSEC, MTA-STS,
  BIMI and SMTP-TLS-RPT data, but has **no DKIM support at all** (no `dkim` key in its
  output, no dkim-related function anywhere in the package). `email_auth.py` therefore
  checks a short list of common DKIM selectors (google, selector1/2, k1, mail,
  default, dkim, smtp, mandrill, mailgun, sendgrid, amazonses) directly via DNS TXT
  lookups, and still uses `checkdmarc` for SPF/DMARC as specified.
- **Consequence:** the DKIM check is inherently non-exhaustive (documented in the
  tool's docstring and in its `dkim_not_found` finding text) — an uncommon selector
  won't be found. A real-world test against `example.com` also showed this check can
  surface a *present-but-empty* DKIM record (`v=DKIM1; p=`) as "found", which is
  technically a null/revoked key rather than an active one; refining that distinction
  is left for a later pass since it doesn't affect the pipeline's correctness.

## ADR-005: Phase 2 findings use placeholder severity (INFO/score 0) — no Risk Engine yet

- **Context:** the `Finding` table requires non-nullable `severity`, `score`, and
  `remediation`, but the Risk Engine (CVSS + KEV + EPSS + exposure scoring) is Phase 4
  scope, not Phase 2.
- **Decision:** every `Finding` persisted by the deterministic passive pipeline
  (`vigia/pipeline.py`) is stored with `severity=INFO`, `score=0.0`, and a fixed
  remediation placeholder pointing at Phase 4. KEV membership and EPSS score (from
  `kev_epss_enrich`) *are* already populated on the `Finding` row where a CVE is known,
  since that data doesn't depend on the Risk Engine's scoring formula — only the
  severity/score mapping does.
- **Consequence:** Phase 4 will need a backfill/rescoring pass (or simply re-run scans)
  once `risk/engine.py` exists; until then, findings in the DB and CLI output are
  informational only and should not be read as prioritized.

## ADR-004: `uv` for Python, `pnpm` (via Corepack) for JS

- **Context:** Phase 1 needs a package manager for both the `api/` (Python) and `web/`
  (Node) packages.
- **Decision:** `uv` for Python (fast, lockfile-based, manages the Python interpreter
  itself — useful since the dev machine's default `python` was 3.10 but the project
  targets 3.12). `pnpm` for JS, invoked as `corepack pnpm ...` since a global `pnpm`
  install required admin rights on the dev machine that weren't available; Corepack
  (bundled with Node) runs it without installing anything system-wide.
- **Consequence:** All documented commands use `uv run ...` and `corepack pnpm ...`.

## ADR-003: SQLite (WAL) by default, Postgres optional via `DATABASE_URL`

- **Context:** Brief section 8/1 asks for SQLite by default and optional Postgres.
- **Decision:** `DATABASE_URL` defaults to `sqlite+aiosqlite:///./vigia.db`. Alembic's
  `env.py` derives a sync URL from it (stripping `+aiosqlite`/`+asyncpg`) since Alembic
  migrations run synchronously regardless of the app's async engine. WAL mode itself is
  a SQLite pragma to be set on the engine when this matters operationally (Phase 2+,
  once concurrent writes from the agent loop are a real concern) — not needed for the
  Phase 1 schema-only scope.
- **Consequence:** Switching to Postgres in production is a matter of setting
  `DATABASE_URL=postgresql+asyncpg://...`; no code changes needed for Phase 1's schema.

## ADR-002: Full data model implemented in Phase 1, not incrementally

- **Context:** Brief section 8 defines the complete schema (Scan, Asset, Finding,
  Evidence, ToolCall, Setting, ApiKey). Phase 1's stated scope is "Base" infra only.
- **Decision:** Implement the full schema now, in one Alembic migration, rather than
  adding tables phase-by-phase. The entities are small, stable (defined precisely in
  the brief), and every later phase (tools, agent, risk, report) depends on at least
  one of them — splitting migrations per phase would mean repeatedly reshaping the
  audit (`ToolCall`) and evidence tables instead of building on a settled schema.
- **Consequence:** Later phases may still need additive migrations (e.g. indices found
  useful in practice), but the core shape should not change.

## ADR-001: Default Ollama model tags verified

- **Context:** Brief section 2 requires verifying that `VIGIA_PLANNER_MODEL` (default
  `qwen3.6:35b`) and `VIGIA_EXTRACTOR_MODEL` (default `granite4.1:8b`) exist in the
  Ollama library before using them, and to propose the closest alternative otherwise.
- **Decision:** Checked https://ollama.com/library/qwen3.6/tags and
  https://ollama.com/library/granite4.1/tags on 2026-09-24. Both tags exist
  (`qwen3.6:35b` ≈ 23GB, 256K context; `granite4.1:8b` available across multiple
  quantizations) and both model families advertise tool-calling / structured JSON
  output support, which the agent architecture (section 5) requires. No substitution
  needed.
- **Consequence:** Defaults in `.env.example` and `vigia/config.py` are used as-is.
  This check should be re-run if models are swapped later, since Ollama's library
  changes over time.
