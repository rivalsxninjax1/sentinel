# Changelog

All notable changes to this project are documented here.
Format loosely follows Keep a Changelog; versions are pre-1.0 during phased development.

## [0.7.0] - Phase 7 - Advanced Detection
### Added
- Eight new scanners, each `DeterministicScanner`:
  - `ssrf.py` (active, parameter-level) — cloud-metadata/internal-service probes,
    reflected-response signature match. **Explicitly cannot catch blind SSRF**
    without real OOB infrastructure (docs/architecture.md §27, not built) — this
    limitation is stated in the module docstring and in every finding's metadata
    (`known_gap`), not just in docs.
  - `ssti.py` (active, parameter-level) — 5 template-engine-syntax probes
    (`{{7*7}}`/`${7*7}`/`<%= 7*7 %>`/`#{7*7}`/`*{7*7}`), requires the *evaluated*
    result to appear (and the literal payload to NOT appear) to avoid confusing
    evaluation with mere reflection.
  - `idor_candidate.py` (safe, parameter-level) — **honestly limited**: flags
    object-identifier-shaped parameter names as informational candidates only.
    Explicitly does not perform real IDOR/BOLA testing, which needs a multi-identity
    `AuthenticationContext` system (docs/architecture.md §25-26) that doesn't exist
    in any phase built so far — documented as the single biggest gap in current
    coverage rather than glossed over.
  - `cors.py` (safe, host-level) — spoofed-Origin reflection check, severity scales
    with `Access-Control-Allow-Credentials`.
  - `jwt_weakness.py` (safe, host-level) — passive JWT discovery + structural
    analysis: `alg: none` detection, HS256 signature verification against ~10
    well-known weak secrets (legitimate local HMAC check, never forges/replays a
    token against the server), missing `exp` claim.
  - `csrf.py` (safe, form-level — new orchestration category) — anti-CSRF token
    field-name check for state-changing forms, SameSite cookie attribute check.
  - `file_upload.py` (active, form-level) — only on upload-hinting forms; uploads a
    benign marker file with a double extension, fetches it back, checks
    Content-Type for signs of server-side execution. **Never uploads executable
    content of any kind**, and the test file is **not automatically cleaned up** —
    flagged in every finding's metadata (`cleanup_required`) and in docs/scanners.md.
  - `xxe.py` (active, form-level) — local-file-read XXE payload as raw POST/PUT body
    to form-bearing endpoints, traversal-indicator signature match (same technique
    as Phase 6's `path_traversal`).
- `app/scanners/base.py` — `ScanTarget` extended with optional `form_fields` for the
  three new form-aware scanners.
- `app/core/test_orchestrator.py` — new `run_form_level()` method and category;
  host-level set grew to include `cors`/`jwt_weakness`; `ssrf` gated by a
  URL-hinting parameter-name heuristic (mirrors `open_redirect`'s existing pattern).
- `app/scanners/registry.py` — all 14 scanners now registered.
- CLI: `sentinel scan test` now also runs the form-level pass against every
  discovered form.
- `docs/scanners.md` — full coverage table extended, with explicit, prominent
  "not automatically detectable" callouts for blind SSRF, real IDOR/BOLA, JWT
  forgery/replay, and file-upload exploitation — matching docs/architecture.md §13's
  required "automatically detectable vs. requires X" distinction.
- Tests: one file per new scanner (`test_ssrf_scanner.py`, `test_ssti_scanner.py`,
  `test_idor_candidate_scanner.py`, `test_cors_scanner.py`,
  `test_jwt_weakness_scanner.py` — including real HMAC-SHA256 verification against
  fabricated tokens, not just string matching — `test_csrf_scanner.py`,
  `test_file_upload_scanner.py`, `test_xxe_scanner.py`), rewritten
  `test_test_orchestrator.py` (updated counts for the expanded registry, new
  form-level dispatch coverage), extended `test_cli_smoke.py` (the existing
  unreachable-target `scan test` smoke test now also seeds a form, exercising the
  new form-level pass's graceful-failure path) — 38 new/updated tests (198 total,
  all passing).

### Notes
- **IDOR/BOLA is the phase's most important documented limitation, not an
  afterthought**: `idor_candidate` is explicitly informational-only. Building real
  IDOR/BOLA detection requires the `AuthenticationContext` multi-identity system
  from docs/architecture.md §26, which no phase has built yet — that's reasonable
  future work, not something to fake with a heavier-sounding scanner name.
- SSRF detection is reflection-based only; blind SSRF requires the OOB system from
  §27, also not built yet. Both gaps are stated in code (module docstrings, finding
  metadata) as well as docs — the goal is that nobody downstream mistakes a
  candidate finding for a confirmed one just because the docs weren't in front of
  them.
- File upload testing leaves a benign test file on the target if the form actually
  accepts uploads — no automated cleanup exists. Worth being aware of before running
  `scan test` in ACTIVE mode against a target where you can't easily remove
  `sentinel_test.jpg.php` yourself afterward.
- Same "no live target in my sandbox" caveat as Phase 6: every new scanner is
  verified against realistic simulated responses (fabricated JWTs with real HMAC
  signatures, simulated CORS/upload/XXE response shapes) via `httpx.MockTransport`,
  not a real vulnerable application.

## [0.6.0] - Phase 6 - Detection
### Added
- `app/scanners/base.py` — `DeterministicScanner` interface + `mode_allows()` (single
  source of truth for PASSIVE < SAFE < ACTIVE gating).
- `app/scanners/util.py` — `inject_query_param()`, shared by every parameter-level
  scanner instead of six slightly-different implementations.
- Six scanners, each `DeterministicScanner`:
  - `security_headers.py` — passive; missing CSP/X-Frame-Options/
    X-Content-Type-Options/HSTS/Referrer-Policy + Server/X-Powered-By banner
    disclosure. Confidence `high` (absence of a header is a fact, not a guess).
  - `information_exposure.py` — safe; fixed list of ~9 sensitive paths
    (`.git/HEAD`, `.env`, backup files), explicitly never flags
    `.well-known/security.txt` (a benign/expected file).
  - `open_redirect.py` — safe; single request per candidate parameter with an
    external test domain, checks `Location` header.
  - `reflected_xss.py` — safe; unique-marker raw-reflection heuristic. Explicitly
    documented as the "cheap first pass," complementing (not replacing) the
    context-aware `xsstrike` tool adapter from Phase 5.
  - `path_traversal.py` — active; `../../etc/passwd`-style payloads,
    `root:x:0:0` indicator match.
  - `sqli_error_based.py` — active; single-quote injection + known DB
    error-signature grep. Complements the `sqlmap` tool adapter for real
    boolean/time/UNION-based coverage.
- `app/scanners/registry.py` — `build_default_scanners()`.
- `app/core/test_orchestrator.py` — `TestOrchestrator`: the sole authority on
  whether a scanner runs, gated by scan mode; runs host-level scanners once per
  host, parameter-level scanners once per parameter (with a redirect-name heuristic
  additionally gating `open_redirect`); isolates and records scanner exceptions
  without aborting the run. No code path from `app/llm/`/`app/intelligence/` into
  this file — matches the same AI-advisory-only boundary from Phase 4.
- `app/storage/models.py` — `Test`, `Finding`, `Evidence` tables (the remaining
  entities from docs/architecture.md §8's schema, populated for the first time).
  `Finding.confidence` is never set to `"confirmed"` anywhere in this phase — reserved
  for Phase 9's Verification Engine.
- `app/storage/repository.py` — `FindingsRepository`
  (`create_test`/`create_finding_from_normalized`/`list_findings_for_scan`/
  `list_evidence_for_finding`). `create_finding_from_normalized` accepts the same
  `NormalizedFinding` shape tool adapters (Phase 5) already produce — scanners and
  tool adapters write to the same table through the same method.
- CLI: `sentinel scan test <scan_id>` — runs the full orchestration pass across every
  host/endpoint/parameter (capped by `--max-parameters`, default 200), persists
  results, advances INTELLIGENCE -> PRIORITIZED -> TESTING.
- `docs/scanners.md` filled in properly (was a Phase 0 stub) — full coverage table,
  explicit "not automatically detectable" list, confidence discipline explanation.
- Tests: `test_scanners_base.py`, `test_scanners_util.py`, one test file per scanner
  (mocked `SentinelHTTPClient` via `httpx.MockTransport` — same proven pattern from
  Phases 2-3), `test_test_orchestrator.py` (mode-gating, redirect-heuristic gating,
  exception isolation), extended `test_attack_surface_repository.py` and
  `test_cli_smoke.py` (full `scan test` run against an intentionally-unreachable
  target, proving every scanner's error handling and the full
  orchestration-through-lifecycle-transition pipeline work even with zero successful
  HTTP responses) — 34 new tests (160 total, all passing).
- `pyproject.toml` — `python_classes` restricted in pytest config so pytest doesn't
  try (and fail) to collect application classes named `Test*` (e.g.
  `TestOrchestrator`, the `Test` ORM model) as test classes.

### Notes
- `Classification` rows from Phase 4 (AI-recommended tests) are not yet read by
  `TestOrchestrator` — it runs its fixed scanner set against every parameter, subject
  to mode. Using AI recommendations to prioritize/narrow that set is reasonable
  future work, not required for "detection exists and works."
- Host-level findings (`security_headers`, `information_exposure`) are attached to a
  synthetic `/` GET endpoint (`source="scanner"`) since `Test`/`Finding` both require
  a real `endpoint_id` and these scanners aren't tied to one specific discovered
  endpoint.
- Same scheme-reconstruction limitation already flagged in Phase 3's discover-js:
  `scan test` derives scheme from `target.seed_urls[0]`, not per-host — fine for the
  common single-scheme case, a real limitation for mixed-scheme targets.
- I have no live target to test scanners against for real true/false positive rates
  in my sandbox — every scanner is verified against realistic *simulated* responses
  via `httpx.MockTransport` (e.g. an app that echoes a query param unescaped, an app
  that returns a MySQL error string), not a real vulnerable application. The `lab/`
  directory (mandatory per docs/architecture.md §41) still doesn't exist — building
  it against these six scanners would be a natural next step whenever you want real
  regression coverage rather than simulated coverage.

## [0.5.0] - Phase 5 - Tool Orchestration
### Added
- `app/tools/base.py` — `SecurityToolAdapter` ABC: `run()` provides shared,
  non-overridable lifecycle plumbing (scope enforcement -> availability check ->
  config validation -> command build -> timeout-bound subprocess execution -> parse
  -> normalize). No adapter can skip the scope check — it happens once, centrally.
- `app/tools/process.py` — injectable `ProcessRunner` + `default_process_runner`
  (real `asyncio.create_subprocess_exec`, timeout-bound, raises `ToolTimeoutError`).
- `app/tools/models.py` — `NormalizedFinding`, the one shape every adapter's output
  collapses to.
- `app/tools/registry.py` — `ToolRegistry` + `build_default_registry()`
  (availability/version report, no execution).
- Six adapters, each `SecurityToolAdapter` subclass:
  - `httpx.py` — ProjectDiscovery httpx (JSON-lines probing). **Discovered and
    documented a real naming collision**: the Python `httpx` package installs its own
    CLI script also named `httpx`, which can shadow the Go binary on PATH. Fails
    safely (zero findings, not garbage), and `sentinel tools list` now actively warns
    about it — see docs/tools.md.
  - `nuclei.py` — template-based scanning, severity-restricted to info/low in SAFE
    mode, requires SAFE or ACTIVE (never PASSIVE).
  - `ffuf.py` — content discovery/fuzzing, requires an explicit wordlist path (never
    auto-selected) and SAFE/ACTIVE mode.
  - `katana.py` — supplementary crawler, JSON-lines parsing.
  - `xsstrike.py` — XSS testing; no stable JSON output mode exists, so parsing is an
    explicitly-documented line-heuristic, requires ACTIVE mode, findings marked
    `confidence: low` in metadata pending Phase 9 verification.
  - `sqlmap.py` — SQL injection detection; same line-heuristic caveat as XSStrike,
    requires ACTIVE mode, and `build_command()` is hard-documented to never include
    `--dump`/`--os-shell`/`--os-pwn`/`--sql-shell` (enforced by a dedicated test that
    asserts these flags are absent from every built command).
- CLI: `sentinel tools list` — availability + version report for all six adapters,
  runs nothing.
- Tests: `test_tools_process.py` (real subprocess execution, no mocking — timeout
  path included), `test_tools_base.py` (full lifecycle incl. scope/availability/
  config-error/timeout paths via a test-only fake adapter), `test_tools_registry.py`,
  and one test file per adapter (build_command flag correctness, parse/normalize
  against realistic sample output, and a full `run()` happy path via injected runner
  + monkeypatched `shutil.which`) — 44 new tests (126 total, all passing).

### Notes
- **Real bug caught during this phase, not simulated:** running `sentinel tools list`
  in the dev environment surfaced the httpx naming collision described above — kept
  as a permanent documented gotcha in docs/tools.md rather than a one-off fix, since
  anyone with the Python httpx package installed (which SENTINEL itself depends on)
  can hit this.
- Adapters are NOT wired into scan execution yet — nothing currently decides *when*
  to run one based on a scan's Phase 4 classifications. That orchestration/decision
  logic is Phase 6+, deliberately deferred (see docs/tools.md's closing note).
- I have no real installations of nuclei/ffuf/katana/XSStrike/sqlmap in this sandbox
  (no network access to fetch them here), so `build_command`/`parse`/`normalize` are
  verified against each tool's documented output format and an injected fake process
  runner, not a live binary. `httpx` was the one adapter I could partially
  cross-check against a real installed binary — and that check is exactly what
  surfaced the naming collision. Worth running `sentinel tools list` on your Mac with
  real tools installed before trusting the live paths for the other five.

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
