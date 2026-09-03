# Detection Engine Coverage

## Deterministic scanners (Phase 6)

Every scanner implements `DeterministicScanner` (`app/scanners/base.py`) and uses
SENTINEL's own `SentinelHTTPClient` — no external binary, no subprocess. Scope and
rate limiting are already enforced by the HTTP client itself.

| Scanner | Vulnerability class | Required mode | Detection method | Confidence |
|---|---|---|---|---|
| `security_headers` | `security_headers` | passive | Missing CSP/X-Frame-Options/X-Content-Type-Options/HSTS/Referrer-Policy; Server/X-Powered-By disclosure | high (absence is a fact) |
| `information_exposure` | `information_exposure` | safe | Fixed list of ~9 sensitive paths (`.git/HEAD`, `.env`, backup files, etc.), flags 200+non-empty | low |
| `open_redirect` | `open_redirect` | safe | Injects an external test domain into redirect-hinting or explicitly-tested parameters, checks `Location` header | low |
| `reflected_xss` | `xss` | safe | Injects a unique HTML-syntax marker, checks for unescaped reflection in response body | low |
| `path_traversal` | `path_traversal` | active | Injects `../../../etc/passwd`-style payloads, checks for `root:x:0:0` indicators | low |
| `sqli_error_based` | `sqli` | active | Injects a single quote, checks for known DB error-message signatures (MySQL/Postgres/SQLite/Oracle/MSSQL) | low |

**Explicitly NOT automatically detectable by these scanners** (per
docs/architecture.md §13's required distinction):
- Stored/DOM XSS (reflected only — see `xsstrike` tool adapter, Phase 5, for
  context-aware and DOM analysis)
- Blind/boolean/time-based/UNION SQLi (error-based only — see `sqlmap` tool adapter
  for real coverage)
- Anything requiring authenticated context or multiple identities (IDOR/BOLA —
  Phase 7)
- SSRF, SSTI, XXE, CSRF, CORS misconfiguration, JWT weaknesses (Phase 7)
- Anything requiring browser execution beyond raw-string reflection (Phase 3's
  `BrowserEngine` exists but isn't wired into detection yet)

## Why deterministic scanners exist alongside tool adapters

Per docs/architecture.md §46: "does a mature maintained tool already solve most of
this problem? If yes, integrate it; if no, implement a focused deterministic
scanner." The Phase 6 scanners are intentionally the *cheap first pass* — a single
request, a simple heuristic, no external dependency:

- `reflected_xss` (raw-reflection only) complements `xsstrike` (context-aware,
  encoding-aware, DOM-aware) — see app/tools/xsstrike.py.
- `sqli_error_based` (single quote + error grep) complements `sqlmap` (full
  boolean/time/UNION-based detection) — see app/tools/sqlmap.py.

Neither pair is redundant: the deterministic scanner runs in SAFE mode with zero
external dependencies, and the tool adapter runs in ACTIVE mode when you actually
have the binary installed and want deeper coverage.

## Confidence discipline

No scanner or adapter in SENTINEL is currently permitted to write `confidence:
"confirmed"` — every `Finding` record's confidence is `info`, `low`, `medium`, or
`high`, capturing how directly a metric was observed (e.g. a missing header is
`high` confidence because its absence is directly observable; a reflected marker is
`low` confidence because it doesn't prove exploitability). "Confirmed" is reserved
for Phase 9's Verification Engine, which doesn't exist yet — see
docs/architecture.md §22.

## Test orchestration (`app/core/test_orchestrator.py`)

`TestOrchestrator` is the sole authority on whether a scanner actually runs. It:
- gates every scanner by `mode_allows(scan_mode, scanner.required_mode)` — a scan
  configured as PASSIVE will only ever run `security_headers`.
- runs host-level scanners (`security_headers`, `information_exposure`) once per
  discovered host, against the host root.
- runs parameter-level scanners once per discovered parameter, with `open_redirect`
  additionally gated by a redirect-parameter-name heuristic (`url`, `redirect`,
  `next`, `return`, `dest`, `continue`, `target`) so it doesn't fire on every
  parameter regardless of relevance.
- isolates scanner exceptions — one scanner's bug is logged and recorded, never
  aborts the rest of the run.

**Not yet wired**: `Classification` rows from Phase 4 (AI-recommended tests) aren't
read by the orchestrator yet. The orchestrator currently runs its fixed scanner set
against every parameter (subject to mode); using AI recommendations to prioritize or
narrow that set is reasonable future work, not required for Phase 6's "detection
exists and works" goal.
