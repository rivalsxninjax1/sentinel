# Changelog

All notable changes to this project are documented here.
Format loosely follows Keep a Changelog; versions are pre-1.0 during phased development.

## [0.4.0] - Phase 4 - Ollama Intelligence
### Added
- `app/llm/provider.py` — `LLMProvider` ABC: `complete_structured(prompt, schema) ->
  T | None`, `check_availability() -> bool`. Provider-agnostic by design (per
  docs/architecture.md §8); Ollama is the first and only implementation.
- `app/llm/ollama_provider.py` — `OllamaProvider`: calls Ollama's `/api/generate`
  with `format: "json"`, validates the result against the requested Pydantic schema,
  makes one bounded repair attempt (re-prompts with the validation failure) before
  giving up and returning `None`. Accepts an injectable `httpx` transport for testing
  without a real Ollama instance.
- `app/llm/schemas.py` — `EndpointClassification` (endpoint, parameter,
  classification, risk_score 0-10, recommended_tests, reason), with `classification`
  and `recommended_tests` constrained to fixed enums (`ParameterSemantic`,
  `RecommendedTest`) so the model can't recommend a test class SENTINEL doesn't
  recognize.
- `app/intelligence/reasoning.py` — `SecurityReasoningEngine`: the sole caller of
  `LLMProvider`. Every path — no provider configured, provider unreachable, provider
  returns `None`, provider raises — collapses to
  `ClassificationOutcome(classification=None, source="fallback")`. There is no path
  by which unvalidated or missing AI output reaches anything else.
- `app/storage/models.py`, `repository.py` — `Classification` table +
  `IntelligenceRepository` (records both AI and fallback outcomes, so it's always
  possible to audit how much of a scan's prioritization was actually AI-assisted).
- CLI: `sentinel scan classify <scan_id>` — classifies every discovered
  endpoint/parameter (capped by `--max-items`, default 200), persists results,
  advances the scan DISCOVERY -> INTELLIGENCE. Does this even when Ollama is
  completely unreachable — advisory AI failure never blocks scan progress.
- `docs/ollama.md` filled in properly (was a Phase 0 stub).
- Tests: `test_llm_schemas.py`, `test_ollama_provider.py` (mocked transport, covers
  success/repair/give-up/schema-mismatch/availability paths), `test_reasoning.py`,
  extended `test_attack_surface_repository.py` and `test_cli_smoke.py` (the latter
  seeds a scan directly via the repository layer, points config at an unreachable
  port, and asserts `scan classify` still exits 0, reports fallback, and advances the
  scan to INTELLIGENCE) — 18 new tests (82 total, all passing).

### Notes
- Classification results aren't consumed by anything yet — no test-triggering logic
  exists until tool adapters do (Phase 5+). This phase only proves the AI reasoning
  pipeline is safe and observable end to end; wiring recommendations into actual test
  execution is explicitly future work, not an oversight.
- I could not run this against a real local Ollama instance in my sandbox (no network
  access to install/run Ollama here), so `OllamaProvider` is verified via
  `httpx.MockTransport` against Ollama's documented API shape rather than a live
  instance — worth a real run with `ollama serve` + a pulled model on your Mac before
  fully trusting the live path.

## [0.3.0] - Phase 3 - JavaScript Intelligence
### Added
- `app/intelligence/javascript.py` — `extract_from_js()`: regex-based extraction of
  API routes, GraphQL endpoints, WebSocket endpoints, and source-map references
  (`//# sourceMappingURL=...`) from JS source text. Ignores cross-origin absolute
  URLs (not routes of the app being tested).
- `app/crawler/html_parser.py`, `models.py` — `PageExtraction` now also captures
  external `<script src>` URLs and inline `<script>` contents.
- `app/crawler/browser.py` — `BrowserEngine` (Playwright-based dynamic discovery):
  navigates a seed URL in headless Chromium, records every network request the page
  issues while its JS runs, classifies each against `ScopeEngine` before reporting.
  Optional dependency — `is_available()` reports False and callers skip gracefully if
  Playwright (or its browser binaries) aren't installed; this is unit-tested via
  monkeypatching since real browser launch needs binaries not installable in CI/this
  sandbox.
- `app/storage/models.py`, `repository.py` — `JavaScriptAsset` table (URL,
  has_source_map, source_map_url) + `AttackSurfaceRepository.add_javascript_asset()`
  (dedup by host+url).
- CLI: `sentinel scan discover-js <scan_id>` — re-crawls seed URLs, fetches every
  discovered script (in-scope only), extracts routes/GraphQL/WebSocket endpoints and
  source-map refs, persists them as `Endpoint`s with `source="javascript"`, runs
  browser discovery if available (`source="browser"`). Requires the scan to be in
  DISCOVERY; does not advance the lifecycle (JS/browser discovery is an additional
  discovery substep, not a new stage — Phase 4 owns the DISCOVERY -> INTELLIGENCE
  transition).
- `pyproject.toml` — new `browser` optional-dependency group (`playwright`), kept out
  of the base install since it pulls in a full browser binary.
- Tests: `test_javascript.py`, `test_browser.py`, expanded `test_html_parser.py` and
  `test_attack_surface_repository.py` — 15 new tests (64 total, all passing).

### Notes
- `discover-js` re-crawls the seed URLs rather than reusing `scan crawl`'s results,
  since page HTML isn't currently persisted between commands. This duplicates some
  HTTP work; a raw-page cache/queue table is a reasonable future optimization but
  isn't needed for correctness (every request still goes through
  scope+rate-limit-enforced `SentinelHTTPClient`), so it's deferred rather than
  gold-plated now.
- **Known architecture gap, documented explicitly rather than hidden:** Playwright's
  browser issues its own network requests outside `SentinelHTTPClient`, so SENTINEL's
  `RateLimiter` does not pace them. Every request is still scope-checked before being
  reported, but the browser can fire requests faster than our rate limit would allow
  before SENTINEL can react. `docs/architecture.md` §28 already flagged "browser when
  necessary" as the guiding principle — this is the concrete tradeoff that implies.
  Acceptable for Phase 3 (opt-in, few seed URLs); worth revisiting if browser
  discovery scope grows in a later phase.
- JS regex extraction has expected false negatives for obfuscated/dynamically-built
  URLs (e.g. `"/api/" + id`) — this is why browser-based discovery exists as a
  complement, not a replacement.

## [0.2.0] - Phase 2 - Reconnaissance
### Added
- `app/discovery/url_normalizer.py` — canonical URL form (scheme/host case, default
  ports, sorted query params, trailing slash, dropped fragment) for crawl dedup.
- `app/crawler/models.py`, `html_parser.py` — BeautifulSoup-based extraction of links,
  forms (method/action/fields), and query parameters from a page.
- `app/crawler/crawler.py` — `Crawler`: BFS traversal bounded by `max_crawl_depth` and
  `max_pages`, using `SentinelHTTPClient` (so scope + rate limiting apply to every
  request automatically), skips/continues past out-of-scope links.
- `app/intelligence/technology.py` — deterministic technology fingerprinting from
  response headers, cookies, and body markers (Server/X-Powered-By headers, framework
  session-cookie names, WordPress/Drupal/React body markers, `<meta name=generator>`),
  each detection carries a confidence level.
- `app/storage/models.py` — added `Host`, `Endpoint`, `Parameter`, `Form`,
  `Technology` tables (the attack-surface subset of docs/architecture.md §8).
- `app/storage/repository.py` — `AttackSurfaceRepository` (get-or-create + dedup for
  hosts/endpoints/parameters/forms/technologies).
- `app/core/http_client.py` — `SentinelHTTPClient` now accepts an injectable
  `transport` (used by tests via `httpx.MockTransport`; scope/rate-limit enforcement
  is unaffected either way).
- `app/config/settings.py` — added `target.seed_urls` (validated as absolute URLs).
- CLI: `sentinel scan crawl <scan_id>` — runs the crawler against `target.seed_urls`,
  persists the attack surface, advances the scan RECON -> DISCOVERY.
- Tests: `test_url_normalizer.py`, `test_html_parser.py`, `test_technology.py`,
  `test_crawler.py` (mocked HTTP transport, verifies scope enforcement + form/tech
  extraction end-to-end), `test_attack_surface_repository.py` — 25 new tests
  (49 total, all passing).

### Notes
- Traditional (non-JS-executing) crawling only, per plan — SPA/JS-driven discovery is
  Phase 3.
- `httpx`/`Katana` CLI adapters are intentionally *not* integrated yet: the
  `SecurityToolAdapter` interface they should implement doesn't exist until Phase 5.
  Phase 2's crawler instead uses SENTINEL's own scope-and-rate-limit-enforcing HTTP
  client, which is fully testable without external binaries and will happily coexist
  with the httpx/Katana adapters once Phase 5 lands (both feed the same
  `AttackSurfaceRepository`).
- Technology fingerprinting is a small explicit signature set, not a Wappalyzer
  replacement — see `docs/scanners.md` (unchanged this phase, filled in properly at
  Phase 6+).

## [0.1.0] - Phase 1 - Core Foundation
### Added
- `app/config/settings.py` — `SentinelConfig` (Pydantic Settings): YAML + env-var
  loading, refuses an empty scope allow-list at load time.
- `app/core/logging.py` — structlog setup with automatic secret-key redaction.
- `app/scope/engine.py` — `ScopeEngine`: exact-host / wildcard-subdomain / URL-prefix
  allow+deny rules, `deny` always wins, `enforce()` raises `ScopeViolation`.
- `app/core/rate_limiter.py` — `RateLimiter`: RPS pacing, concurrency cap, global
  request budget (`RequestBudgetExceeded`), single `throttle()` context manager.
- `app/core/http_client.py` — `SentinelHTTPClient`: httpx wrapper that forces every
  request through `ScopeEngine.enforce()` and `RateLimiter.throttle()`.
- `app/storage/models.py`, `db.py`, `repository.py` — SQLAlchemy async models
  (`Target`, `Scan` — Phase 1 subset only), SQLite engine/session helpers, repository
  layer.
- `app/core/lifecycle.py` — `ScanLifecycle` state machine
  (CREATED → SCOPE_VALIDATED → ... → COMPLETE, plus STOPPED from any state).
- `app/cli/main.py` — Typer CLI: `sentinel init-db`, `sentinel scan create`,
  `sentinel scan status`.
- Tests: `test_scope_engine.py`, `test_rate_limiter.py`, `test_lifecycle.py`,
  `test_settings.py`, `test_cli_smoke.py` — 24 tests, all passing.
- Dependencies pinned in `pyproject.toml`.

### Notes
- `scan create` only validates config-level scope and advances to
  `SCOPE_VALIDATED` — no recon/discovery logic exists yet (Phase 2).
- Only `Target` and `Scan` tables exist; the remaining entities from
  `docs/architecture.md` §8 are added when the phases that populate them land.

## [0.0.1] - Phase 0 - Architecture
### Added
- Repository skeleton (`app/`, `tests/`, `lab/`, `docs/`, `configs/`, `scripts/`,
  `.github/workflows/`, `.vscode/`).
- `docs/architecture.md` — system architecture, threat model, DB design, scan lifecycle,
  scan modes, tool integration strategy, Ollama architecture.
- `docs/setup.md`, `docs/development.md`, `docs/tools.md`, `docs/ollama.md`,
  `docs/scanners.md`, `docs/testing.md`, `docs/lab.md`, `docs/github-workflow.md` (stubs
  to be filled in as their respective phases land).
- `pyproject.toml` project metadata (dependencies unpinned — Phase 1).
- `CONTRIBUTING.md`, `SECURITY.md`, `.gitignore`, `LICENSE` placeholder.
- `.github/workflows/ci.yml` placeholder (lint/type-check/test, no live scanning).
- `.vscode/` debug/task scaffolding.

### Notes
- No scanning logic, tool adapters, database, or LLM integration exist yet — by design.
