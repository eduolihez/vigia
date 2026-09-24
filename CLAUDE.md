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

No risk engine, report, or real GUI yet — those land in Phases 4–6. Report Writer/
Validator don't exist, so the REPORT phase auto-advances (no-op) for now; findings
still carry Phase 2's placeholder severity (ADR-005).

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
```

### Everything together

```bash
cp .env.example .env   # then edit as needed
docker compose up      # ollama + api + web
# GPU (NVIDIA) host:
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up
```

## Conventions

- Code, identifiers, and comments: English. UI copy: bilingual ES/EN (Phase 6+, via
  next-intl). Main docs in English; `README.es.md` mirrors `README.md` in Spanish.
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
│                   tools/ has 13 passive wrappers + kev_epss_enrich (Phase 2);
│                   pipeline.py is the deterministic `vigia scan` pipeline;
│                   agent/ is the Phase 3 LLM orchestrator (see agent/orchestrator.py)
├── web/             Next.js frontend
├── eval/            Benchmark lab, ground truth, results (Phase 8)
├── docs/            architecture.md, ethics.md, decisions.md (ADRs)
├── docker-compose.yml / docker-compose.gpu.yml
└── .env.example
```

## Decisions taken

See `docs/decisions.md` for the running ADR log (package managers, DB defaults, model
verification, schema scope, etc.).
