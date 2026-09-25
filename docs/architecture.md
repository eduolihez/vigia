# Architecture

> See the root `CLAUDE.md` for current phase status and `docs/decisions.md` for the
> reasoning behind specific choices (ADRs).

## Overview

```
web (Next.js)  ──SSE/REST──►  api (FastAPI)
                                ├─ agent/orchestrator   state-machine loop        [Phase 3]
                                ├─ agent/scope_guard     allowlist enforcement     [Phase 3]
                                ├─ agent/sanitizer       untrusted OSINT data      [Phase 3]
                                ├─ agent/tool_router      phase allowlist + exec   [Phase 3]
                                ├─ agent/llm_client       Ollama chat/tool-calling [Phase 3]
                                ├─ tools/*               one wrapper per source    [Phase 2/7]
                                ├─ pipeline.py            deterministic passive    [Phase 2]
                                ├─ agent/ownership.py     TXT-record verification  [Phase 7]
                                ├─ risk/engine            CVSS + KEV + EPSS        [Phase 4]
                                ├─ report/writer          LLM → draft report       [Phase 4]
                                ├─ report/validator       entity/evidence check    [Phase 4]
                                ├─ report/exporters/      Markdown, JSON, PDF      [Phase 4]
                                ├─ ethics.py               first-run notice gate   [Phase 3]
                                ├─ settings_store.py       runtime overrides       [Phase 6]
                                ├─ crypto.py               API-key encryption      [Phase 6]
                                └─ db/                    models + migrations     [Phase 1]
                              ollama (planner model; extractor unused so far)
```

Design principle throughout: the LLM (planner, via Ollama) **decides and drafts** —
which tool to call next, when a phase is done, what a report should say. Everything
else — validating that decision, executing it, persisting evidence, scoring risk,
checking a report's claims against real evidence — is deterministic Python. The LLM
never runs arbitrary commands and never builds tool arguments outside a fixed
Pydantic schema.

## Data flow, end to end (current state)

1. **`vigia scan <domain>`** (deterministic, `pipeline.py`) or **`vigia scan
   <domain> --agent`** (LLM-driven, `agent/orchestrator.py`) creates a `Scan` row
   and runs passive tools, persisting `Asset`, `Finding` (placeholder severity),
   `Evidence`, and `ToolCall` (audit) rows as it goes. The agent path also emits
   `AgentEvent`s (SSE-ready) at each step.
2. **`vigia score <scan_id>`** (`risk/engine.py`) re-scores every `Finding` for that
   scan in place: `score = base × kev_mult × (1+epss) × exposure_factor`, with real
   CVSS from NVD when a CVE is known.
3. **`vigia report <scan_id> --format md|json|pdf`** (`report/writer.py` +
   `validator.py` + `exporters/`) drafts a report from the scan's evidence via the
   planner's structured JSON output, validates every domain/IP/CVE/port/count it
   claims against that evidence (regenerating or dropping anything invented), and
   exports it.

None of these three steps require the others to have just run — each reads whatever
state exists in the DB for that `scan_id`. A typical flow is scan → score → report,
but re-running `score` or `report` on an already-scored/reported scan is always safe
(idempotent overwrite, not additive).

## Phase-by-phase notes

- **Phase 1:** FastAPI skeleton, full SQLModel schema (`Scan`, `Asset`, `Finding`,
  `Evidence`, `ToolCall`, `Setting`, `ApiKey`) implemented up front (ADR-002) rather
  than incrementally, since every later phase needed at least one of these tables.
- **Phase 2:** 13 passive tool wrappers behind a common `ToolResult`/`ToolSpec`
  contract (`tools/base.py`), run in a fixed order by `pipeline.py`.
- **Phase 3:** `agent/orchestrator.py` drives the VERIFY→SEED→ENUMERATE→RESOLVE→
  EXPOSURE→EMAIL_AND_SPOOFING→LEAKS→RISK→REPORT→DONE state machine (`agent/
  phases.py::PHASE_TOOLS` maps phases to allowed tools — ADR-009). `scope_guard.py`
  and `sanitizer.py` are the two guardrails tested directly by the prompt-injection
  suite (`tests/injection/`); `tool_router.py` is the single chokepoint every tool
  call passes through (phase allowlist, then Scope Guard, then execution).
- **Phase 4:** `risk/engine.py` is a pure scoring function (`score_finding`) plus a
  thin DB-updating wrapper (`score_scan_findings`); `report/validator.py`'s
  `EvidenceBase` is built fresh from the scan's `Asset`/`Finding` rows each time a
  report is validated, so it can never drift from what's actually in the database.
- **Phase 5:** the GUI's own scan-creation flow (`POST /scans` then
  `GET /scans/{id}/stream`) is create-then-subscribe rather than one-shot streaming
  like `POST /scans/agent` — a browser `EventSource` can only `GET` (ADR-021).
- **Phase 6:** `settings_store.py::build_effective_config()` is the seam between the
  Settings page and everything that already reads a plain `Settings` object
  (`tool_router.py`, `pipeline.py`, `resolve_planner`) — it returns a `Settings`
  copy with `Setting`-table overrides and decrypted `ApiKey` values applied, so
  none of that code needed to change (ADR-026). Reports stay generate-on-demand
  over the API too, same as the Phase 4 CLI (ADR-027).
- **Phase 7:** `agent/phases.py::ACTIVE_PHASE_TOOLS` + `tool_router.invoke`'s
  `active_enabled` flag are the single reachability gate for `http_probe`/
  `tls_check`/`screenshot` — only `AgentOrchestrator._active_enabled()` ever passes
  `True`, and only once VERIFY confirms ownership via `agent/ownership.py`
  (ADR-033). VERIFY failure stops the whole scan (`Scan.status = FAILED`), not just
  the active tools (ADR-032). `http_probe` also upgrades a Phase 2 `dangling_dns`
  *candidate* into a confirmed `dangling_dns_confirmed` finding by checking the live
  response body against `fingerprints/takeover_signatures.yaml`, independent of the
  original CNAME match (ADR-031).

## Not yet built

- **Report Writer isn't wired into the agent's REPORT phase** — it auto-advances
  (no-op) for now; `vigia report` (and `POST /scans/{id}/report`) work standalone
  against any completed scan.
- **`eval/` benchmarking harness** (Phase 8) and the polished README/docs pass
  (Phase 9) haven't started.
