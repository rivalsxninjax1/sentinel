# SENTINEL Architecture — Phase 0

## 1. Purpose

SENTINEL is an AI-assisted, context-aware orchestration platform for **authorized** web
application security testing. It does not "scan and guess." It builds a structured model
of an application's attack surface, reasons about which vulnerability classes are worth
testing, delegates actual testing to specialized (mostly external, mature) security tools,
verifies every candidate finding against evidence, and produces a report that clearly
separates confirmed findings from speculation.

SENTINEL is an **orchestrator and verifier**, not a reimplementation of XSStrike, sqlmap,
Nuclei, ffuf, Katana, or httpx.

## 2. Threat Model (of SENTINEL itself)

SENTINEL is a security tool, which means it is itself a thing that needs a threat model.

| Risk | Mitigation |
|---|---|
| Scope engine bypassed by a misconfigured tool adapter | All outbound requests — from SENTINEL's own HTTP client *and* every external tool — are routed through the Scope Engine's `is_in_scope()` check before execution. Adapters cannot issue requests directly. |
| LLM (Ollama) issues an arbitrary command / becomes a confused deputy | Ollama never gets shell access, never gets tool execution capability. It only ever returns structured JSON recommendations validated against a Pydantic schema. The orchestrator decides what, if anything, happens with that recommendation. |
| Malformed/hallucinated LLM output triggers a real test | All LLM output is schema-validated (Pydantic). Invalid output is rejected, optionally repaired via a constrained retry, and falls back to deterministic default behavior (i.e., no test, or lowest-priority test) rather than ever being passed through uninterpreted. |
| Destructive testing (data modification/deletion) happens automatically | ACTIVE mode still excludes destructive actions in v1. IDOR verification reads objects; it never writes/deletes them. Any test class capable of state modification requires a separate, explicit, currently-unimplemented "destructive" mode that does not exist in Phase 0–N of this roadmap. |
| Credentials leak into logs, DB, or reports | Structured logging redacts known secret-shaped fields. Credentials live in env vars / local secret store, never in source, never serialized into scan artifacts verbatim (only reference IDs to the auth context are stored). |
| Runaway scans hit unintended hosts / unbounded request volume | Global + per-tool rate limiter, max request budget, max crawl depth, explicit target scope allow-list validated at multiple layers (crawler, tool adapter, HTTP client). |
| Findings overstate certainty (false positives reported as confirmed vulns) | Verification Engine + Confidence Engine + False Positive Engine are mandatory pipeline stages between "tool says X" and "finding record created." Nothing reaches "CONFIRMED" without corroborating evidence. |
| Tool binaries incompatible with Apple Silicon / silently wrong architecture used | `ToolAdapter.is_available()` and `.version()` perform explicit arch checks; unavailable tools degrade gracefully (skipped + logged), never silently swapped for an incompatible binary. |

## 3. High-Level Architecture

```
                    SENTINEL
                       │
              ┌────────┴────────┐
              │ Scope & Policy  │  (Scope Engine, Rate Limiter, Scan Mode)
              └────────┬────────┘
                       ↓
                Reconnaissance        (Discovery, Crawler, Katana/httpx adapters)
                       ↓
              Attack-Surface Graph    (Target/Host/Endpoint/Parameter/... store)
                       ↓
               Parameter Analysis     (Parameter Intelligence)
                       ↓
              Technology Detection
                       ↓
                Local Ollama          (classification + prioritization, structured output only)
                       ↓
             Intelligent Priorities   (StructuredPlan — orchestrator decides what actually runs)
                       ↓
       ┌───────────────┼────────────────┐
       ↓               ↓                ↓
    XSStrike        sqlmap           Nuclei         ffuf / Katana / httpx
       └───────────────┼────────────────┘
                       ↓
                Response Analysis / Normalizer
                       ↓
                 Verification Engine
                       ↓
                False Positive Reduction Engine
                       ↓
                  Correlation Engine
                       ↓
                Risk / Confidence Scoring
                       ↓
                   Findings (DB)
                       ↓
               Professional Report (HTML/MD/JSON)
```

Ollama sits *beside* the pipeline as an advisory reasoning layer at two points: recon
classification and pre-test prioritization. It never sits *in* the execution path of a
tool invocation. See §7.

## 4. Repository Structure

```
sentinel/
├── app/
│   ├── cli/              # CLI entrypoints (Typer/Click) — thin, delegates to core
│   ├── core/              # scan lifecycle, orchestrator, config loading, domain models
│   ├── config/            # settings schema + loader (YAML + env)
│   ├── scope/              # ScopeEngine — the one thing everything must pass through
│   ├── discovery/          # non-crawling discovery: robots.txt, sitemap, OpenAPI, etc.
│   ├── crawler/            # traditional + headless crawling orchestration
│   ├── intelligence/       # parameter/endpoint/tech classification (deterministic + AI-assisted)
│   ├── llm/                # LLMProvider abstraction, OllamaProvider, schemas
│   ├── tools/               # SecurityToolAdapter implementations (nuclei, sqlmap, xsstrike, ffuf, katana, httpx)
│   ├── scanners/            # deterministic custom test logic not covered by external tools
│   ├── analysis/            # response/differential/reflection/timing analysis
│   ├── verification/        # Verification Engine, confidence levels
│   ├── correlation/         # multi-engine evidence correlation
│   ├── reporting/           # HTML/Markdown/JSON report generation
│   └── storage/             # repository layer (SQLite now, Postgres-ready)
├── tests/                   # unit + integration tests
├── lab/                     # local vulnerable lab (Docker), used for regression tests
├── docs/
├── configs/                 # example YAML configs, wordlists refs, nuclei template sets
├── scripts/                 # dev/setup scripts (tool installation checks, etc.)
├── .github/workflows/       # CI (lint, type-check, unit tests — NOT live scanning)
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── .gitignore
└── LICENSE
```

## 5. Technology Choices (Phase 0 decisions)

| Concern | Choice | Rationale |
|---|---|---|
| Language | Python 3.11+ | type hints, async, broad security-tooling ecosystem |
| CLI | Typer | thin wrapper over Click, good type-hint integration |
| Data validation | Pydantic v2 | required for LLM structured-output validation, config schema, DB DTOs |
| HTTP client | `httpx` (the Python library, distinct from ProjectDiscovery's `httpx` binary — naming collision noted explicitly in `docs/tools.md`) | async-capable, well-maintained |
| DB (Phase 1) | SQLite via SQLAlchemy 2.0 (async) | zero-install for local use; repository layer abstracts persistence so Postgres can be swapped in later without touching callers |
| Browser automation | Playwright (Python) | best-maintained headless browser automation option, ARM64 support |
| Config | YAML + environment variable overlay via Pydantic Settings | human-editable + secret-friendly |
| Logging | `structlog` | structured, redaction-friendly |
| Testing | `pytest`, `pytest-asyncio` | standard |
| Packaging | `pyproject.toml` (PEP 621), `uv` or `pip` installable | modern standard |

## 6. Tool Integration Strategy

Every external tool is wrapped by a `SecurityToolAdapter` (interface defined in Phase 5,
stubbed as an ABC in Phase 1). No adapter may issue a request that has not first passed
`ScopeEngine.check(target)`. Concretely:

```
ScopeEngine
    ↓ (only in-scope targets pass)
ToolAdapter.prepare(context)   # builds tool invocation, still scope-bound
    ↓
ToolAdapter.run(context)       # subprocess/async call, rate-limited, timeout-bound
    ↓
raw output
    ↓
ToolAdapter.parse(output)      # tool-specific parsing
    ↓
ToolAdapter.normalize(results) # → common Finding-candidate schema
```

Tools planned for integration (adapters, not reimplementations): ProjectDiscovery `httpx`,
ProjectDiscovery `Katana`, `ffuf`, `XSStrike`, `sqlmap`, `Nuclei`. Each will get a license
check recorded in `docs/tools.md` before integration (Phase 5), per rule #47 of the
governing spec.

## 7. Ollama / AI Architecture

```
LLMProvider (ABC)
    └── OllamaProvider
```

- Config-driven model/host/temperature (`configs/*.yaml`, see `docs/ollama.md` — created Phase 4).
- All calls request structured JSON; a Pydantic model validates the response.
- Invalid JSON → reject → bounded repair attempt → fallback to deterministic default
  (e.g., "no AI-recommended tests" rather than guessing).
- AI output is a *recommendation* (`StructuredPlan`), never a direct trigger. The
  orchestrator (Phase 1 core + Phase 5 tool registry) is the sole authority on what
  actually executes, and re-checks scope/policy/rate-limits regardless of what the AI
  suggested.
- Ollama is used in exactly two roles in this roadmap: (a) recon/classification
  reasoning, (b) test prioritization / correlation reasoning. It is explicitly *not* used
  as a substitute for deterministic detection logic.

## 8. Database Design (Phase 1 target schema, SQLite)

Core tables (see §9 of the governing spec for the full entity list — this is the initial
normalized shape; exact columns finalized in Phase 1):

```
scans(id, target_id, mode[passive|safe|active], status, started_at, finished_at,
      stopped_reason, config_snapshot_json)

targets(id, name, scope_definition_json, created_at)

hosts(id, target_id, hostname, ip_addresses_json)

endpoints(id, host_id, path, method, source[crawl|js|openapi|manual], first_seen_scan_id)

parameters(id, endpoint_id, name, location[query|body|json|header|cookie|path],
           observed_value, inferred_type, likely_semantics, content_type)

forms(id, endpoint_id, method, action, fields_json)

technologies(id, host_id, name, version, confidence, source)

authentication_contexts(id, target_id, label[anonymous|user_a|user_b|admin],
                         secret_ref)   -- secret_ref points to env/secret store, never the secret itself

tool_runs(id, scan_id, tool_name, tool_version, started_at, finished_at, params_json, status)

tests(id, scan_id, endpoint_id, parameter_id, vulnerability_class, tool_run_id, status)

findings(id, scan_id, test_id, title, vulnerability_class, cwe, cvss,
         confidence[info|low|medium|high|confirmed], severity, description, remediation)

evidence(id, finding_id, kind[request|response|dom|diff|ai_reasoning], content_ref, created_at)
```

The repository layer (`app/storage/`) exposes async CRUD + query interfaces per entity so
the SQLAlchemy engine can be swapped for Postgres later without touching calling code.

## 9. Scan Lifecycle (state machine, Phase 1)

```
CREATED → SCOPE_VALIDATED → RECON → DISCOVERY → INTELLIGENCE → PRIORITIZED
        → TESTING → VERIFYING → CORRELATING → REPORTING → COMPLETE
                                                     ↘ STOPPED (scope violation / limit / error / cancel)
```

Scan state is persisted after every stage transition so a scan can resume from the last
completed stage rather than restarting (Phase 1 stub, full resumability by Phase 2/9).

## 10. Scan Modes

- **PASSIVE** — recon/discovery only, zero intrusive requests.
- **SAFE** — controlled, low-risk active tests (default for "active" tool checks marked
  safe by the adapter).
- **ACTIVE** — fuller test surface, requires explicit `--i-am-authorized` style flag plus
  a scope confirmation step. No destructive sub-mode exists in this roadmap.

## 11. Non-Negotiable Constraints Carried Into Every Phase

These are restated here because they drive every later architectural decision, not just
the AI or tool layers:

1. Scope is enforced at the lowest possible layer (HTTP client + every adapter), not just
   at the orchestrator.
2. No destructive testing is implemented, period, in this roadmap.
3. Credentials never appear in source, logs, or plaintext scan artifacts.
4. AI output is always schema-validated before it can influence behavior.
5. Tool output is always normalized and passed through Verification before becoming a
   "Finding."
6. Confirmed vulnerability status requires corroborating evidence, not a single tool's
   opinion.
7. New tools/scanners must be addable without modifying core/db/cli/reporting/AI layers.

## 12. What Phase 0 Deliberately Does Not Do

- No scanning logic.
- No LLM calls.
- No tool adapters implemented (interface only, stubbed as an ABC for forward reference).
- No CLI commands beyond a placeholder.
- No database migrations yet — schema above is a design target for Phase 1.

## 13. Next Phase

**Phase 1 — Core Foundation**: Python project scaffolding (`pyproject.toml`, package
layout finalized), configuration loader, CLI skeleton, structured logging, the real
`ScopeEngine` implementation, async HTTP client wrapper, rate limiter, SQLite database +
SQLAlchemy models for the schema above, scan lifecycle state machine, and a first
functional test suite (scope engine tests, rate limiter tests, scan lifecycle tests).
