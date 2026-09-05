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
| `ssrf` | `ssrf` | active | Injects cloud-metadata/internal-service URLs into URL-hinting parameters, checks for reflected metadata-response signatures | low |
| `ssti` | `ssti` | active | Injects `{{7*7}}`-style expressions across 5 template-engine syntaxes, checks that the *evaluated* result (49) appears, not the literal payload | low |
| `idor_candidate` | `idor_bola` | safe | Flags object-identifier-shaped parameter names (id/user_id/order_id/uuid/etc.) — **informational only, not real IDOR testing** (see below) | info |
| `cors` | `cors` | safe | Sends a spoofed Origin header, checks whether it's reflected in Access-Control-Allow-Origin (severity scales with Access-Control-Allow-Credentials) | high |
| `jwt_weakness` | `jwt` | safe | Passively finds JWT-shaped tokens in response body/cookies, decodes header+payload without verifying signature server-side, flags `alg: none`, HS256 signed with a common weak secret (verified via local HMAC, never replayed), missing `exp` | high (structural facts) / info (weak-secret match is a fact once matched) |
| `csrf` | `csrf` | safe | For POST/PUT/DELETE/PATCH forms: checks for an anti-CSRF token field by name; checks Set-Cookie for missing/permissive SameSite | low-medium |
| `file_upload` | `unsafe_file_upload` | active | Only on upload-hinting forms: uploads a benign file with a double extension (`.jpg.php`), fetches it back, checks whether Content-Type suggests server-side execution | low-critical |
| `xxe` | `xxe` | active | Sends a local-file-read XXE payload as the raw POST/PUT body to endpoints known to accept a form body, checks for a traversal-indicator signature | critical (rare hit) |

**Explicitly NOT automatically detectable by these scanners** (per
docs/architecture.md §13's required distinction):
- Stored/DOM XSS (reflected only — see `xsstrike` tool adapter, Phase 5, for
  context-aware and DOM analysis)
- Blind/boolean/time-based/UNION SQLi (error-based only — see `sqlmap` tool adapter
  for real coverage)
- **Real IDOR/BOLA** — `idor_candidate` only flags parameter *names* that look like
  object identifiers. Confirming actual broken object-level authorization requires
  comparing access across multiple authenticated identities (anonymous/USER_A/
  USER_B/ADMIN — docs/architecture.md §25), which needs an `AuthenticationContext`
  system SENTINEL does not have yet (§26). This is the single biggest, most
  deliberately-flagged gap in current coverage — don't mistake an `idor_candidate`
  finding for a confirmed vulnerability, it is a to-do marker.
- **Blind SSRF** — `ssrf` only catches cases where the fetched internal resource's
  content is reflected back in the response. A target that fetches a URL but never
  shows you anything (blind SSRF) needs a real out-of-band callback/correlation
  server (docs/architecture.md §27), which doesn't exist yet.
- **JWT signature forgery/replay** — `jwt_weakness` verifies signatures against known
  weak secrets locally (a legitimate, well-established check) but never forges a
  token and replays it against the application to confirm the server actually
  accepts it. An `alg: none` finding means "the token's own header says this,"
  not "the server was confirmed to accept an unsigned token."
- **File upload exploitation** — `file_upload` never uploads executable content of
  any kind, only a benign marker file, and never attempts to trigger execution. A
  finding means "content-type handling looks permissive," not "code execution was
  achieved." **The uploaded test file is not automatically cleaned up** — if this
  scanner runs against a real target, check for and manually remove
  `sentinel_test.jpg.php` afterward.
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
- runs host-level scanners (`security_headers`, `information_exposure`, `cors`,
  `jwt_weakness`) once per discovered host, against the host root.
- runs parameter-level scanners once per discovered parameter, with `open_redirect`
  gated by a redirect-parameter-name heuristic (`url`, `redirect`, `next`, `return`,
  `dest`, `continue`, `target`) and `ssrf` gated by a similar URL-hinting heuristic
  (`url`, `uri`, `link`, `src`, `path`, `target`, `endpoint`, `callback`, `webhook`,
  `fetch`) so they don't fire on every parameter regardless of relevance.
- runs form-level scanners (`csrf`, `file_upload`, `xxe`) once per discovered form,
  passing the form's field names and method — these need the whole form's structure,
  not a single parameter.
- isolates scanner exceptions — one scanner's bug is logged and recorded, never
  aborts the rest of the run.

**Not yet wired**: `Classification` rows from Phase 4 (AI-recommended tests) aren't
read by the orchestrator yet. The orchestrator currently runs its fixed scanner set
against every parameter (subject to mode); using AI recommendations to prioritize or
narrow that set is reasonable future work, not required for Phase 6's "detection
exists and works" goal.
