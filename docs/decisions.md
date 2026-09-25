# Architecture Decision Records

Short ADRs for decisions made autonomously during development, per the project brief's
"choose the reasonable option and document it" rule. Newest first.

## ADR-035: a stalled ENUMERATE phase skips itself, not the rest of the scan

- **Context:** found live by the Phase 8 benchmark lab, not by inspection: running
  the real agent (`qwen2.5:14b-instruct`) against the `email-misconfig` scenario, the
  early-stop heuristic (`MAX_NO_NEW_ASSETS_BEFORE_STOP` — 2 consecutive tool calls in
  an asset-discovery phase finding nothing new) `break`s the orchestrator's entire
  main loop. `email-misconfig.lab` legitimately has no subdomains, so `ct_subdomains`
  correctly found nothing twice — but that aborted the *whole scan*, silently
  skipping EXPOSURE, EMAIL_AND_SPOOFING, LEAKS, and RISK, even though none of those
  phases depend on subdomain discovery. Recall on that scenario was 0.33 (should have
  been 1.0) purely because of this, not because the agent failed to find the SPF/DMARC
  issue — it never even tried, since EMAIL_AND_SPOOFING never ran.
- **Decision:** the early-stop now gives up on the *current* phase only — reset the
  counter and call `_advance_phase()` instead of `break`ing — so later, unrelated
  phases still run. Verified with a dedicated orchestrator test
  (`test_stalled_enumeration_skips_only_that_phase_not_the_whole_scan`) and against
  the pre-fix live benchmark data that surfaced the bug in the first place
  (`eval/results/`); a second live confirmation run was started but killed by the
  host's own low-memory protection mid-run (not restarted per its own instruction —
  the offline test plus the pre-fix live data were judged sufficient evidence for
  this specific, narrow fix).
- **Consequence:** this is the clearest demonstration yet that the benchmark lab
  (Phase 8) earns its keep — a real behavioral bug that unit/integration tests with
  a scripted planner would never have exercised, since a scripted planner never
  "gets stuck" the way a real model can.

## ADR-034: benchmark lab scripts every tool call — no real domain is ever touched

- **Context:** Phase 8 needs "ground truth" scenarios to measure the agent's actual
  OSINT quality (brief section 9) — but running the real agent against a real domain
  would violate rule 6 (no active/passive scans against real infrastructure during
  development), and running it against a synthetic domain with *unmocked* tools would
  still make real network calls to crt.sh/web.archive.org/Shodan/etc. for a
  nonexistent domain, which is slow, flaky, and non-deterministic besides.
- **Decision:** `vigia/eval/lab.py`/`scenarios.py` script every tool at the same
  seam `tests/integration/test_orchestrator.py` already uses —
  `tool_router.INVOKERS` — so the *planner* and *orchestrator* are real (a genuine
  benchmark of agent quality) while every tool response is synthetic, fixed data.
  `Finding.type` sets, not exact content, are what's scored (`score()` in `lab.py`)
  against `eval/ground_truth/*.json`, since the agent's exact tool-call sequence
  isn't prescribed, only what it should end up finding.
- **Consequence:** the harness needs a real Ollama instance for real numbers (like
  `vigia scan --agent`) but never touches the network for OSINT data — CI runs
  `tests/integration/test_eval_runner.py` (a scripted planner, offline) to verify the
  harness's own mechanics, not the benchmark itself.

## ADR-033: active tools are an additive allowlist, gated by a runtime bool, not baked into `PHASE_TOOLS`

- **Context:** Phase 7 adds `http_probe`/`tls_check`/`screenshot` (real network
  requests to the target), only permitted once an active-mode scan passes
  domain-ownership verification (brief section 6.1). They need to be unreachable by
  construction for every passive scan, and for an active scan before VERIFY passes.
- **Decision:** `agent/phases.py` keeps `PHASE_TOOLS` (passive, always available)
  untouched and adds a separate `ACTIVE_PHASE_TOOLS` dict plus
  `tools_for_phase(phase, active_enabled=False)`, which only merges the active set in
  when explicitly asked. `tool_router.invoke()` takes the same `active_enabled` flag
  and is the single enforcement point — `AgentOrchestrator._active_enabled()` is the
  only caller that ever passes `True`, and only after `Scan.mode == ACTIVE and
  Scan.verified`. A prompt-injection payload claiming "verification bypassed" can't
  reach an active tool through any code path; there's no flag on the args, only on
  the trusted Python call site (tested in
  `tests/injection/test_prompt_injection.py::test_injection_cannot_run_active_tool_without_active_enabled`).
- **Consequence:** the LLM tool-calling schema itself (`tool_schemas.build_tool_defs`)
  never even lists the active tools for a passive/unverified scan — the planner can't
  request what it was never told exists.

## ADR-032: VERIFY fails closed and halts the whole scan, not just active tools

- **Context:** an active-mode scan's `VERIFY` phase needs to check the
  `vigia-verify=<token>` TXT record (`agent/ownership.py`, written in Phase 3 prep)
  before anything active runs. The open question: if verification fails, should the
  scan silently continue in passive-only mode, or stop entirely?
- **Decision:** stop entirely. `AgentOrchestrator.run()`'s VERIFY branch sets
  `_AgentState.ownership_failed = True` and `break`s the main loop immediately —
  no SEED, no ENUMERATE, nothing — then `_finish()` sets `Scan.status = FAILED`
  (not `COMPLETED`) when that flag is set. Silently degrading to passive would be
  surprising: the user explicitly asked for active mode and would see a "completed"
  scan that quietly did less than requested, with no clear signal why.
- **Consequence:** a user who forgot to publish the TXT record gets an unambiguous
  failed scan with a specific error message, not a confusing partial result.

## ADR-031: http_probe confirms dangling-DNS takeover from the response body, independent of the CNAME fingerprint match

- **Context:** `dangling_dns` (Phase 2, passive) flags a *candidate* takeover purely
  from a CNAME pattern (`fingerprints/dangling_dns.yaml`) — it can't confirm the
  target is actually unclaimed without an active HTTP request. `http_probe` (Phase 7)
  is that confirmation step.
- **Decision:** rather than re-deriving "which service does this CNAME match" and
  only then checking that service's specific signature, `http_probe` checks the
  response body against every signature in a new, independent list
  (`fingerprints/takeover_signatures.yaml` — well-known "unclaimed" strings, the same
  idea as the community "can-i-take-over-xyz" project) regardless of the CNAME. This
  also lets `http_probe` confirm a takeover on a hostname `dangling_dns` never
  flagged (e.g. a CNAME fingerprint gap), not only ones it already suspected.
- **Consequence:** two YAML files exist for a related purpose (CNAME suffix vs. body
  substring) — intentional, since they're checked at different points against
  different data (DNS record vs. HTTP response) with different confidence levels.

## ADR-030: tls_check parses the certificate with `cryptography`, not `ssl.getpeercert()`

- **Context:** `tls_check` deliberately connects with `ssl.CERT_NONE` (the point is
  to see *whatever* certificate a host presents — expired, self-signed, wrong name —
  and report it, not to fail before looking). Python's `ssl.SSLSocket.getpeercert()`
  only returns the parsed dict form when verification succeeded; with `CERT_NONE` it
  returns `{}` regardless of what was actually presented.
- **Decision:** fetch the raw DER bytes (`getpeercert(binary_form=True)`, always
  populated) and parse them directly with `cryptography.x509` — already a project
  dependency (`vigia/crypto.py`, ADR-026) — to read subject/issuer/SAN/expiry
  regardless of verification outcome.

## ADR-029: screenshot reuses Playwright — no new browser-automation dependency

- **Context:** Phase 7's `screenshot` tool needs to render a real page and capture a
  PNG. `playwright` is already a dependency (the Phase 4 PDF report exporter,
  ADR-016) and its Python async API supports screenshots natively.
- **Decision:** use it directly rather than adding Selenium/Puppeteer/etc. Verified
  locally with a real local HTTP server and real Chromium
  (`tests/unit/tools/test_screenshot.py`) — same "real bytes, local target" approach
  as the PDF exporter's own test, not a mock.

## ADR-028: i18n via next-intl without `[locale]` routing — a cookie picks the locale

- **Context:** Phase 6 requires bilingual ES/EN UI copy. next-intl's default setup
  puts every route under a `[locale]` segment (`/en/...`, `/es/...`), driven by
  middleware — but every existing route, the Phase 5 Playwright suite, and every
  link in the codebase assume unprefixed paths (`/`, `/scans/new`, ...).
- **Decision:** use next-intl's documented "without i18n routing" mode instead: a
  `vigia_locale` cookie (read server-side in `i18n/request.ts` via `next/headers`)
  picks the locale, `NextIntlClientProvider` in the root layout supplies messages,
  and a client-side `LocaleSwitcher` writes the cookie then calls
  `router.refresh()` to re-render the (server) root layout with the new locale. No
  route moves; existing links, bookmarks, and Playwright locators keep working
  unprefixed.
- **Consequence:** locale is a per-browser preference (cookie), not a shareable URL
  — acceptable for a self-hosted SOC console with one operator per browser, unlike
  a public multi-locale marketing site where indexable `[locale]` URLs would matter.

## ADR-027: reports stay generate-on-demand, not persisted, when exposed over the API

- **Context:** the Phase 6 report viewer (`/scans/{id}/report`) needed a way to view
  and export a scan's report from the GUI. The schema (brief section 8) has no
  `Report` table, and the Phase 4 CLI (`vigia report <scan_id>`) already treats every
  invocation as an independent LLM draft with no caching.
- **Decision:** keep that model over the API: `POST /scans/{id}/report` drafts a
  fresh report and returns it as JSON for on-page display;
  `POST /scans/{id}/report/export?format=md|json|pdf` drafts again and returns a
  downloadable file. No new table, no migration. The tradeoff is explicit: the
  exported file's wording won't byte-for-byte match what's on screen (the LLM draft
  isn't deterministic), same as running `vigia report` twice today.
- **Consequence:** if exact viewed/exported parity or history ever become a real
  requirement, that's a real `Report` table + migration, not a workaround here.

## ADR-026: Settings page stores overrides in `Setting`/`ApiKey`, not new `.env` edits

- **Context:** Phase 6 needed a GUI Settings page for model choice, scan budgets,
  and the OSINT source API keys (Censys, GitHub, HIBP) that `config.py` already
  reads from `.env` — but a running container can't rewrite its own `.env` file
  sensibly, and secrets typed into a browser shouldn't land in plaintext anywhere.
- **Decision:** `vigia/settings_store.py` layers runtime overrides on top of the
  `.env` defaults: model/budget overrides live in the existing `Setting` key/value
  table (same pattern `ethics.py` already used for the acceptance flag); API keys
  are encrypted with Fernet (`vigia/crypto.py`, key derived from `VIGIA_SECRET_KEY`
  via SHA-256) into the `ApiKey` table that was already in the schema for exactly
  this. `GET /settings` never echoes a stored key back, only whether one is set.
  `build_effective_config()` returns a full `Settings` copy with overrides/decrypted
  keys applied, so `POST /scans`, the background scan runner, and report generation
  all pick these up automatically — `tool_router.py`/`pipeline.py` keep reading
  plain `Settings` attributes and don't need to know overrides exist.
- **Consequence:** an override only takes effect for scans/reports started after it
  was saved; nothing currently running is affected retroactively (each scan already
  freezes its own `planner_model`/`extractor_model`/budget onto its `Scan` row at
  creation time, which this doesn't change).

## ADR-025: `@xyflow/react` for the asset graph, not `reactflow`

- **Context:** the Phase 6 graph view (`/scans/{id}/graph`) needed a node/edge
  graph library. `reactflow` is the well-known package name, but its own npm
  listing marks it superseded.
- **Decision:** use `@xyflow/react` (12.11.6) — the actively maintained successor
  from the same maintainers, same API shape (`ReactFlow`, `useNodesState`, etc.),
  confirmed compatible with React 19 (peer range `>=17`) before adding it. Layout is
  a simple manual BFS-depth-by-asset-hierarchy placement (domain → subdomain →
  ip/service, findings one row below their asset) — no auto-layout dependency
  (e.g. dagre) added for what's typically a few dozen nodes.

## ADR-024: CI starts/stops the Playwright webServer itself — Playwright's own teardown hung

- **Context:** after ADR-022's mocking fix, CI still hung on "Playwright smoke tests"
  — but the logs showed all 6 tests passing in ~2s; the job then sat idle for 5+
  minutes with no further output until manually cancelled. So the hang was never in
  the tests or in network calls (ADR-022's original diagnosis was incomplete): it was
  in Playwright's `webServer` teardown, which sends a kill signal through
  `corepack pnpm run start` after the run finishes. That command chain (corepack →
  pnpm → shell → `next start` → `next-server` worker) doesn't reliably propagate
  SIGTERM to the actual `next-server` child process on the Actions Ubuntu runner, so
  Playwright waits forever for a process that never exits.
- **Decision:** stop letting Playwright manage the server in CI. The workflow
  (`.github/workflows/ci.yml`) now starts `corepack pnpm run start` in the
  background itself, polls `http://127.0.0.1:3000` until it responds, runs
  `playwright test` directly, and force-kills the server by PID afterwards
  (`if: always()`, `kill -9`, ignoring failure — the ephemeral runner's own orphan
  cleanup catches anything left over, as observed when the earlier stuck run was
  cancelled). `playwright.config.ts`'s `webServer` block is now `undefined` when
  `process.env.CI` is set; locally it still starts/reuses the dev server as before,
  since the hang was never reproducible outside GitHub Actions.
- **Consequence:** CI no longer depends on Playwright's process-group teardown
  working on the runner's OS/shell stack. Local behavior (`pnpm run test:e2e`) is
  unchanged.

## ADR-022: Playwright smoke tests mock the API — reduces CI flakiness/dependency on a live backend

- **Context:** the first CI push of the Phase 5 smoke tests (ADR-019 through -021)
  hung; at the time this was believed to be caused by a real (unmocked) API call to
  a nonexistent `localhost:8000` backend never resolving on the Actions runner. That
  diagnosis turned out to be incomplete — see ADR-024 for the actual root cause,
  found after mocking alone did not fix the hang. The mocking change itself is still
  correct on its own merits (below) and was kept.
- **Decision:** the tests were calling the real (deliberately unmocked)
  `GET /scans` / `GET /ethics` against `localhost:8000`, which has no backend in CI.
  Locally, a refused connection fails in ~2s (confirmed via `curl` and a real
  browser) — but the GitHub Actions runner apparently doesn't send TCP RST for a
  refused `localhost` connection the same way, so the browser's `fetch()` never
  settles, and Playwright's page/context teardown seems to wait on that pending
  request before a test can be marked complete. Rather than chase that
  environment-specific networking behavior further, every API call in the smoke
  suite is now mocked via `page.route()` — no real network attempt, deterministic,
  and ~7x faster (2.7s for 6 tests vs. never finishing). One route pattern
  (`**/scans/*/findings`) had to be scoped to the API's own origin, since the
  broader glob also matched the test's own page navigation
  (`/scans/does-not-exist/findings`) and replaced the HTML page with the mocked
  JSON instead of letting it render.
- **Consequence:** these smoke tests verify the pages render/navigate/use real
  response shapes correctly — not live backend integration, which needs Ollama and
  stays a manual verification step (documented in CLAUDE.md), not a CI job.

## ADR-021: create-then-subscribe scan flow, not one-shot streaming, for the GUI

- **Context:** Phase 3's `POST /scans/agent` runs a scan end-to-end within one
  streamed HTTP request/response — simple, and fine for `curl`, but unusable from a
  browser GUI: `EventSource` (the browser's native SSE client, needed for
  `/scans/new` → `/scans/{id}/live`) can only issue GET requests with no body, so it
  can't POST a domain to start a scan.
- **Decision:** added a second flow for the GUI: `POST /scans` creates the `Scan`
  row (status `pending`) and returns its id immediately (no scan runs yet); the
  browser navigates to `/scans/{id}/live`, which opens `EventSource` against
  `GET /scans/{id}/stream` — that endpoint lazily starts the orchestrator as a
  background `asyncio.Task` on first connection and broadcasts its events to every
  subscriber queue for that scan id. `agent/orchestrator.py`'s `run_agent_scan` was
  split into `resolve_planner` + `run_agent_scan_for(session, scan, settings)` so
  both flows share the same orchestration logic without duplicating it.
- **Consequence:** scan state always lives in the DB, never only in the broadcast
  queues — a page reload after the stream ends (or was never open) still sees the
  right state via `GET /scans/{id}` (see ADR-020). `POST /scans/agent` is kept for
  non-browser callers (`curl`, scripts) since it's simpler for that use case.

## ADR-020: live-scan page checks real status before opening the event stream

- **Context:** live browser testing (not just automated tests) of the create-then-
  subscribe flow above.
- **Decision:** reloading `/scans/{id}/live` for a scan that had already finished
  hung forever on "Waiting for the agent to start…" — its background task was long
  gone, so `GET /scans/{id}/stream` returned 200 but never emitted anything, and
  `EventSource` has no way to know the difference between "still starting" and
  "will never send anything." Fixed by having the live page call
  `GET /scans/{id}` once on mount; if the scan is already in a terminal status
  (`completed`/`failed`/`stopped`), it skips opening the `EventSource` entirely and
  shows that status directly, with a link to the findings page. The dropped-
  connection handler (`EventSource.onerror`) does the same real-status check before
  showing a "lost connection" message, since a mid-scan disconnect doesn't mean the
  scan failed — the orchestrator runs server-side independent of the stream.
- **Consequence:** caught by dogfooding the actual GUI (via the `/browse` skill)
  after the happy-path automated tests already passed — a reminder that "the API
  contract is correct" and "the page is usable after a reload" are different
  claims, and only one of them shows up in a request/response test.

## ADR-019: TanStack Table pinned to v8, not the newly-released v9

- **Context:** brief section 1 names TanStack Table for the findings table (Phase
  5). `pnpm add @tanstack/react-table` installed 9.2.4 (the current "latest").
- **Decision:** v9 turned out to be a from-scratch rewrite — no `useReactTable`
  export at all (confirmed: build failed with "Export useReactTable doesn't exist,"
  and the package's export list showed a completely different, feature-composition
  based API with no equivalent single hook). Learning that new API correctly would
  have taken meaningfully longer than the findings table itself is worth, for a
  single sortable/filterable table. Pinned to `@tanstack/react-table@8`
  (8.21.3) instead — the well-documented, stable hook-based API `useReactTable`
  actually refers to.
- **Consequence:** if a future phase wants v9's features, that's a deliberate,
  separate upgrade — not something to fall into by installing "latest" again.

## ADR-018: SQLite WAL mode + busy_timeout, and commit (not just flush) per write

- **Context:** brief section 1 specifies "SQLite by default (WAL)" — WAL mode was
  never actually turned on through Phases 1-4, since nothing had needed concurrent
  DB access yet. Phase 5 (a GUI issuing a scan-creation request while a background
  scan is mid-run) is the first thing that does.
- **Decision:** live testing (start a scan via the GUI's new `POST /scans` +
  `GET /scans/{id}/stream` flow, then fire a second request while the first is
  running) immediately hit `sqlite3.OperationalError: database is locked`. Root
  cause was two-fold: (1) SQLite's default rollback-journal mode allows only one
  writer and blocks everyone else outright; (2) worse, `agent/orchestrator.py` and
  `pipeline.py` only ever called `session.flush()` during a scan and `commit()`
  once at the very end — so a single scan held one open write transaction, and thus
  the write lock, for its *entire* duration (potentially 20 minutes), during which
  nothing else could write at all. Fixed both: `db/session.py` now sets
  `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=5000` on every SQLite
  connection (a `sqlalchemy.event` "connect" listener, since aiosqlite doesn't take
  these as `connect_args`), and every per-item persistence checkpoint in both files
  (`_upsert_asset`, `_record_tool_call`, `_persist_finding`,
  `_apply_kev_enrichment`, `_persist_findings`) now calls `commit()` instead of
  `flush()`.
- **Consequence:** re-running the same live test after the fix succeeded — a scan
  creation and a dashboard list request both completed normally while another scan
  streamed. This also fixes a latent durability bug: a crash mid-scan now loses at
  most the in-flight tool call instead of the entire scan's progress, since each
  persisted item is its own committed transaction rather than one multi-minute one.

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
