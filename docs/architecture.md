# Architecture

> Skeleton — filled in as each phase lands. See the root `CLAUDE.md` for the current
> phase status and `docs/decisions.md` for the reasoning behind specific choices.

## Overview

```
web (Next.js)  ──SSE/REST──►  api (FastAPI)
                                ├─ agent/orchestrator   state-machine loop        [Phase 3]
                                ├─ agent/scope_guard     allowlist + ownership     [Phase 3]
                                ├─ agent/tool_router     schemas, rate limits      [Phase 3]
                                ├─ agent/sanitizer       untrusted OSINT data      [Phase 3]
                                ├─ tools/*               one wrapper per source    [Phase 2]
                                ├─ risk/engine           CVSS + KEV + EPSS         [Phase 4]
                                ├─ report/writer         LLM → draft report        [Phase 4]
                                ├─ report/validator      entity/evidence check     [Phase 4]
                                └─ db/                   models + repositories     [Phase 1]
                              ollama (planner + extractor)
```

## Phase 1 (current)

- `api/`: FastAPI app with a single `/health` endpoint, SQLModel schema for all core
  entities (`Scan`, `Asset`, `Finding`, `Evidence`, `ToolCall`, `Setting`, `ApiKey`),
  Alembic migrations.
- `web/`: Next.js (App Router, TypeScript strict, Tailwind) placeholder page + health
  route. No real UI yet.
- `docker-compose.yml`: `ollama`, `api`, `web` services.

Data model, agent design and risk/report design will be documented here in detail as
Phases 3–4 implement them.
