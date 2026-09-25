# Vigía benchmark lab (Phase 8)

A small set of synthetic scan scenarios with known ground truth, used to measure
the agent's actual OSINT quality end to end: real planner LLM (Ollama), real
`AgentOrchestrator`/Risk Engine/Report Writer code — but every OSINT tool call is
scripted rather than a real network request, so this never touches a real domain
(brief rule 6). The code lives in `api/vigia/eval/`; this directory holds the
human-readable ground truth and the results this harness produces.

## Layout

- `ground_truth/*.json` — one file per scenario (`api/vigia/eval/scenarios.py`),
  listing its target domain, mode, and the `Finding.type` values a correctly
  behaving agent should end up surfacing. Kept in sync with `scenarios.py`
  automatically — `api/tests/unit/eval/test_ground_truth_sync.py` fails in CI if
  they drift apart, so treat a failure there as "update the JSON, or you changed the
  scenario and meant to."
- `results/*.json` — one file per `vigia eval run`, gitignored (these are local
  measurements, not something to commit) except where a result is deliberately kept
  as a historical reference.

## Running it

Needs a running Ollama instance (same requirement as `vigia scan --agent`) — not run
in CI for the same reason.

```bash
cd api
uv run vigia eval list              # see the available scenarios
uv run vigia eval run               # run all of them, write a results JSON
uv run vigia eval run --scenario dangling-dns
uv run vigia eval run --model qwen2.5:14b-instruct
```

## What's measured

For each scenario:

- **Precision / recall / F1** over `Finding.type` — did the agent's real tool
  selection (via `tool_router`, scripted at the tool-implementation boundary) end up
  persisting the expected finding types, nothing more and nothing less? A "clean"
  scenario with zero expected findings scores a perfect 1.0 only if the agent didn't
  hallucinate a finding that isn't there — this is as much an over-reporting check as
  an under-reporting one.
- **Step count / duration** — a rough efficiency signal (a planner that needs 40
  steps to reach the same result as one that needs 12 is worse, even at equal
  accuracy).
- **Report Writer `dropped_items`** — every scenario also runs a real Report Writer
  pass against the scan's own evidence; a dropped item means the LLM's draft
  mentioned something the deterministic Report Validator (brief section 7.3) rejected
  as unverifiable. Across many scenario runs this is a live hallucination-rate signal,
  not just the synthetic-evidence unit tests in `api/tests/unit/report/test_writer.py`.

## Scenarios

| Scenario | Mode | Exercises |
|---|---|---|
| `clean` | passive | No false positives on a well-configured domain |
| `email-misconfig` | passive | SPF/DMARC detection (`email_auth`) |
| `dangling-dns` | passive | Subdomain-takeover *candidate* detection (`dangling_dns`) |
| `kev-exposure` | passive | KEV/EPSS enrichment pathway (`shodan_internetdb` → `kev_epss_enrich`) |
| `confirmed-takeover` | active | Phase 7 end to end: ownership verification (synthetically short-circuited — see below) → `http_probe` confirms the `dangling-dns` candidate |

`confirmed-takeover` needs `Scan.verified` to become `True`, which normally requires
a real DNS TXT lookup — but that would need a real domain (brief rule 6 again), so
the harness patches `agent.ownership.verify_ownership` to a synthetic always-true
stand-in for the duration of that one scenario run
(`vigia.eval.runner._patched_ownership_verification`), the same technique
`api/tests/integration/test_orchestrator.py`'s active-mode tests already use. The
*tool* being benchmarked (`http_probe`) is still exercised for real, through the
real `active_enabled` gate (ADR-033) — only the DNS check itself is short-circuited.

## Offline tests vs. live runs

`api/tests/integration/test_eval_runner.py` verifies the harness's own mechanics
(scripted tools get invoked, scoring is wired to real persisted findings, the report
pass runs) with a scripted planner — no live Ollama, runs in CI. Getting real
benchmark *numbers* needs `vigia eval run` against a real model, run manually.
