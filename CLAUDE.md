# CLAUDE.md — Vigía

Guidance for working in this repo. Kept up to date at the end of every phase.

## What this is

Vigía is an open-source External Attack Surface Management (EASM) OSINT agent: given an
owned/authorized domain, a local LLM (via Ollama) plans and drives passive (and,
once verified, active) reconnaissance, every finding is backed by stored evidence,
risk is scored deterministically (CVSS + CISA KEV + FIRST EPSS), and results are
presented in a web GUI with an asset graph and an exportable report. Full spec: see
the original project brief (not stored in-repo); phase status below.

## Status

**Phase 1 (Base) — done.** Monorepo skeleton, Docker Compose (ollama/api/web), FastAPI
healthcheck, full SQLModel schema + first Alembic migration, Next.js placeholder, CI.

**Phase 2 (Passive tools) — done.** All 13 passive tool wrappers (`api/vigia/tools/`),
`kev_epss_enrich`, and a deterministic pipeline (`api/vigia/pipeline.py`, no LLM)
wired into `vigia scan <domain>` (`--passive` is the only mode so far). Every
finding is stored with placeholder severity/score — see ADR-005; the Risk Engine
lands in Phase 4. `subfinder` and `dnstwist` need a real binary/PATH entry
(`dnstwist` is a pip dependency with a CLI; `subfinder` is built in `api/Dockerfile`
from Go source) — outside Docker, those two tools report a graceful "binary not
found" error rather than failing the scan.

**Phase 3 (Agent) — done.** LLM-driven orchestrator (`api/vigia/agent/orchestrator.py`)
implementing the VERIFY→SEED→ENUMERATE→RESOLVE→EXPOSURE→EMAIL_AND_SPOOFING→LEAKS→
RISK→REPORT→DONE state machine, real `ollama` tool-calling (planner Protocol, model
availability check + fallback — ADR-013), Scope Guard, Sanitizer, deterministic
fallback after 3 invalid planner turns, deep dives, budget/early-stop, SSE events, an
immutable/exportable `ToolCall` audit log, and an ethical-use acceptance gate shared
with the Phase 2 pipeline (ADR-008). Minimal API surface: `POST /scans/agent` (SSE
stream) and `GET /scans/{id}/audit`. `vigia scan <domain> --agent` runs it from the
CLI. Verified live against a real local Ollama instance (not just mocks) — one bug
(SEED phase mapping) was caught and fixed this way, see ADR-011. Prompt-injection
suite: 17 payloads (brief requires ≥15), 0% success, plus 7 structural-enforcement
tests (`api/tests/injection/`).

**Phase 4 (Risk & Report) — done.** Deterministic Risk Engine
(`api/vigia/risk/engine.py` + `weights.yaml`): `score = base × kev_mult × (1+epss) ×
exposure_factor`, base score from real NVD CVSS when a CVE is known (ADR-014) or a
per-finding-type weight otherwise, replacing the Phase 2/3 placeholder severity —
`vigia score <scan_id>`. Report Writer (`report/writer.py`) drafts a report from a
scan's evidence via the planner's structured JSON output; Report Validator
(`report/validator.py`) extracts every domain/IP/CVE/port mentioned and rejects
anything not present in that scan's own evidence — up to 2 regenerations with the
violation fed back, then the offending item (not the whole report) is dropped and
logged. Exporters for Markdown, JSON, and PDF (`report/exporters/`) —
`vigia report <scan_id> --format md|json|pdf`. PDF renders via Playwright/headless
Chromium, not WeasyPrint (which failed to import locally — ADR-016); verified with a
real generated PDF, not a mock.

The REPORT phase in the Phase 3 agent still auto-advances (no-op) rather than
calling the Report Writer inline — wiring that in is a small follow-up, not urgent
since `vigia report` already works standalone against any completed scan.

**Phase 5 (GUI core) — done.** Next.js dark SOC-console UI: dashboard (`/`, recent
scans + top-risk-domains), new scan (`/scans/new`, with the ethical-use notice gate),
live view (`/scans/[id]/live`, real SSE via `EventSource` — phase bar, event
timeline, Stop button), findings (`/scans/[id]/findings`, TanStack Table v8 —
sortable/filterable, row click opens an evidence drawer). New GUI-facing API surface:
`POST /scans`, `GET /scans`, `GET /scans/{id}`, `GET /scans/{id}/findings`,
`GET /scans/{id}/stream` (create-then-subscribe, since browser `EventSource` can't
POST — ADR-021), `DELETE /scans/{id}` (stop), `GET/POST /ethics`, plus CORS. 5
Playwright smoke tests green (`web/tests/e2e/smoke.spec.ts`).

Dogfooded the actual GUI end to end via the `/browse` skill against a real API +
Ollama (not just automated tests) — launched a scan from the form, followed it live,
verified the findings table and evidence drawer, tested Stop. That session surfaced
and fixed two real bugs: (1) SQLite `database is locked` under concurrent requests —
the orchestrator/pipeline held one open transaction for an entire scan instead of
committing per item; fixed with WAL mode + per-item commits (ADR-018). (2) Reloading
a live-scan page for an already-finished scan hung forever waiting for events that
would never come; fixed by checking real status before opening the stream (ADR-020).

**Phase 6 (GUI advanced) — done.** Report viewer (`/scans/[id]/report` — generate via
the planner LLM, view executive summary/top risks/findings/positive observations,
export Markdown/JSON/PDF), asset graph (`/scans/[id]/graph` — `@xyflow/react`,
domain→subdomain→ip/service hierarchy with findings attached to their asset —
ADR-025), audit log (`/scans/[id]/audit` — the existing `ToolCall` trail as a table),
Settings (`/settings` — planner/extractor model + scan budget overrides, encrypted
OSINT API keys, stored in `Setting`/`ApiKey` rather than `.env` edits — ADR-026), and
bilingual ES/EN UI via `next-intl` without `[locale]` routing (a cookie, not the URL,
picks the locale — ADR-028). New API surface: `GET/PUT /settings`,
`GET /scans/{id}/assets`, `POST /scans/{id}/report`, `POST /scans/{id}/report/export`
(reports are drafted fresh on every call, not persisted — ADR-027). Every scan-detail
page now shares a `ScanSubNav`. 12 Playwright smoke tests green, including a
locale-switch check.

**Phase 7 (Active mode) — done.** Three active tools (`vigia/tools/http_probe.py`,
`tls_check.py`, `screenshot.py`) — real network requests to the target host, unlike
every Phase 2 tool. Gated by `agent/phases.py::ACTIVE_PHASE_TOOLS` +
`tool_router.invoke`'s `active_enabled` flag (ADR-033), which only
`AgentOrchestrator._active_enabled()` ever sets `True`, and only once the VERIFY
phase confirms domain ownership via `agent/ownership.py`'s `vigia-verify=<token>` TXT
record check (already stubbed in Phase 3). Verification fails closed: a wrong/missing
token stops the whole scan (`Scan.status = FAILED`), not just the active tools
(ADR-032). `http_probe` also confirms `dangling_dns` (Phase 2) takeover *candidates*
via `fingerprints/takeover_signatures.yaml` response-body signatures, independent of
the CNAME match (ADR-031) — `dangling_dns_confirmed` findings are the direct result.
`tls_check` flags expired/expiring/self-signed/hostname-mismatched certs and weak
negotiated TLS versions (ADR-030); `screenshot` captures a full-page PNG via
Playwright — already a dependency (ADR-029) — and flags common exposed-admin-panel
page titles. New surface: `POST /scans` takes `mode: "passive"|"active"` and returns
`verification_token` for active mode; `vigia verify <domain>` (CLI) prints a fresh
token statelessly; `vigia scan <domain> --agent --active --token <token>` runs an
active scan from the CLI. GUI: `/scans/new` has a passive/active mode toggle that
shows the TXT record to publish before continuing to the live view. Verified live
against the real API + a real (unowned) domain that ownership verification correctly
fails closed for — active *tools* themselves are tested only against local
mocks/servers, never a real domain (brief rule 6). 160 backend tests green (up from
139), 13 Playwright smoke tests green.

**Phase 8 (Evaluation) — done.** Benchmark lab (`api/vigia/eval/`, data/results
under `eval/`): 5 synthetic scenarios with known ground truth (`eval/ground_truth/`,
kept in sync with `scenarios.py` by a dedicated test), run against a **real** planner
LLM + real orchestrator/risk/report-writer code, with every OSINT tool call scripted
so nothing ever touches a real domain (ADR-034). `vigia eval run` (needs Ollama, not
run in CI — see `eval/README.md`) scores precision/recall/F1 over `Finding.type` per
scenario plus a live Report Writer hallucination check. Running it for real against
`qwen2.5:14b-instruct` immediately surfaced a genuine bug: the orchestrator's
no-new-assets early-stop was aborting the *entire* scan (not just the stalled phase),
silently skipping unrelated later phases — fixed (ADR-035) and covered by a
dedicated orchestrator test, since a scripted-planner test would never have hit it.
170 backend tests green (up from 160).

**Phase 9 (Polish & docs) — done.** README.md/README.es.md rewritten for a real
reader landing on the repo (badges, a Quickstart, a Mermaid architecture diagram,
a guardrails/ethics summary, a highlights list) rather than the Phase 1 skeleton;
`docs/ethics.md` replaced its Phase-1-through-8 placeholder with the actual policy
— permitted use, what Vigía won't do, a guardrail-to-code table, the literal
first-run consent text, data handling, and the legal disclaimer. Fixed a real
`docker compose up` gap found while writing the Quickstart: the API container never
ran `alembic upgrade head` on start, so a fresh stack booted against an unmigrated
database (`/health` reported healthy anyway — its check is a bare `SELECT 1`) and
every real request 500'd; `api/Dockerfile`'s `CMD` now runs the migration before
`uvicorn` starts.

## Commands

### Backend (`api/`)

```bash
cd api
uv sync --extra dev          # install deps (Python 3.12, managed by uv)
uv run pytest                # run tests
uv run ruff check .          # lint
uv run mypy .                # strict type-check
uv run alembic upgrade head  # apply migrations
uv run alembic revision --autogenerate -m "..."   # new migration
uv run uvicorn vigia.api.main:app --reload        # run the API locally
uv run vigia scan <domain>          # deterministic passive pipeline, no LLM (Phase 2)
uv run vigia scan <domain> --agent  # LLM-driven agent (Phase 3); needs Ollama running
                                     #  and OLLAMA_HOST/VIGIA_PLANNER_MODEL configured
                                     #  (or pass --model to override for one scan)
uv run vigia ethics --accept        # required once before any scan will run
uv run vigia verify <domain>        # print a fresh vigia-verify=<token> to publish as
                                     #  a TXT record before an active scan (Phase 7)
uv run vigia scan <domain> --agent --active --token <token>  # active scan; needs
                                     #  --agent and a token from `vigia verify` first
uv run vigia score <scan_id>        # (re)score findings with the Risk Engine (Phase 4)
uv run vigia report <scan_id> --format md|json|pdf --out <path>  # generate a report
uv run vigia eval list              # list benchmark lab scenarios (Phase 8)
uv run vigia eval run               # run the benchmark lab; needs Ollama, writes
                                     #  a results JSON under eval/results/
```

### Frontend (`web/`)

`pnpm` isn't installed globally on the dev machine (no admin rights); it's invoked
through Corepack (bundled with Node ≥ 16.9), which is a normal way to run pnpm and
works identically in CI:

```bash
cd web
corepack pnpm install
corepack pnpm run dev         # dev server
corepack pnpm run build       # production build (also type-checks)
corepack pnpm run lint        # ESLint
corepack pnpm run typecheck   # tsc --noEmit (run `build` at least once first —
                               #  it generates Next.js's ambient route types)
corepack pnpm run format      # Prettier --write
corepack pnpm run format:check
corepack pnpm run test:e2e    # Playwright smoke tests (builds+serves the app itself
                               #  unless a dev/prod server is already on :3000)
```

### Everything together

```bash
cp .env.example .env   # then edit as needed
docker compose up      # ollama + api + web
# GPU (NVIDIA) host:
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up
```

## Conventions

- Code, identifiers, and comments: English. UI copy: bilingual ES/EN via `next-intl`
  (`web/messages/{en,es}.json` — add new keys to both). Main docs in English;
  `README.es.md` mirrors `README.md` in Spanish.
- Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, ...).
- Backend: `ruff` + `mypy --strict` must be clean; tests live in `api/tests/{unit,
  integration,injection,fixtures}`.
- Frontend: TypeScript strict, ESLint + Prettier clean.
- Non-trivial or irreversible technical decisions made without asking are logged as
  short ADRs in `docs/decisions.md`.
- Never run active scans against real domains during development — tests use mocked
  responses; only passive checks against `example.com` (or an explicitly provided lab
  domain) are allowed for real.

## Architecture (summary)

See `docs/architecture.md` for the full diagram and per-phase detail. In short: the
LLM (via Ollama) *decides and drafts*; deterministic Python code *executes, normalizes,
scores, and validates*. The LLM never runs arbitrary commands or builds tool arguments
outside a fixed Pydantic schema.

## Repository layout

```
vigia/
├── api/            FastAPI backend (vigia/ package: agent, tools, risk, report, db, api)
│                   tools/ has 13 passive wrappers + kev_epss_enrich (Phase 2) plus
│                   3 active wrappers (http_probe/tls_check/screenshot, Phase 7);
│                   pipeline.py is the deterministic `vigia scan` pipeline;
│                   agent/ is the Phase 3 LLM orchestrator (see agent/orchestrator.py)
│                   and Phase 7's ownership.py (TXT-record verification);
│                   risk/ + report/ are the Phase 4 Risk Engine and Report Writer;
│                   settings_store.py + crypto.py back the Phase 6 Settings page;
│                   eval/ is the Phase 8 benchmark harness (lab.py/scenarios.py/
│                   runner.py) — its ground truth/results data lives in ../eval/
├── web/             Next.js frontend — app/ has the Phase 5 routes (dashboard,
│                   scans/new, scans/[id]/live, scans/[id]/findings) plus the
│                   Phase 6 routes (scans/[id]/report, scans/[id]/graph,
│                   scans/[id]/audit, settings); lib/api.ts is the API client;
│                   i18n/ + messages/ are the next-intl setup (ADR-028);
│                   tests/e2e/ is the Playwright suite
├── eval/            Benchmark lab data (Phase 8): ground_truth/*.json (kept in
│                   sync with api/vigia/eval/scenarios.py by a test), results/
│                   (gitignored — local `vigia eval run` output), README.md
├── docs/            architecture.md, ethics.md, decisions.md (ADRs)
├── docker-compose.yml / docker-compose.gpu.yml
└── .env.example
```

## Decisions taken

See `docs/decisions.md` for the running ADR log (package managers, DB defaults, model
verification, schema scope, etc.).
