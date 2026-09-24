# Architecture Decision Records

Short ADRs for decisions made autonomously during development, per the project brief's
"choose the reasonable option and document it" rule. Newest first.

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
