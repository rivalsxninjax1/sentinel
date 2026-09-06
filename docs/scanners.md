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
| `identity_authorization` | `idor_bola` | active | **Real cross-identity testing** (requires 2+ configured `auth_contexts`): fetches the same URL as every configured identity, flags if all get 200 with similar bodies | low |
| `graphql_introspection` | `graphql_introspection` | safe | Sends a minimal introspection query to any endpoint with "graphql" in its URL, flags if the schema is returned | high |
| `websocket_auth` | `websocket_authorization` | safe | Attempts a WS handshake with no credentials on `ws://`/`wss://` endpoints, flags if accepted (optional dependency: `websockets`) | low |
| `http_method_enum` | `http_method_enumeration` | safe | Sends OPTIONS only (never PUT/DELETE/PATCH), flags notable methods in the Allow header | high (Allow header content is a fact) |
| `mass_assignment_candidate` | `mass_assignment` | active | Submits a form plus one extra `role=admin` field never part of the discovered form, flags if reflected back | low |

**Explicitly NOT automatically detectable by these scanners** (per
docs/architecture.md §13's required distinction):
- Stored/DOM XSS (reflected only — see `xsstrike` tool adapter, Phase 5, for
  context-aware and DOM analysis)
- Blind/boolean/time-based/UNION SQLi (error-based only — see `sqlmap` tool adapter
  for real coverage)
- **Real IDOR/BOLA — now conditionally available (Phase 8):** if the scan config
  declares 2+ `target.auth_contexts` (see docs/architecture.md §25/§26 and
  `app/core/auth_context.py`), `identity_authorization` performs genuine
  cross-identity comparison: fetching the same URL as each configured identity and
  flagging when every identity receives indistinguishable 200 responses. Without
  auth contexts configured (the default), only `idor_candidate`'s
  name-heuristic-only flagging runs, exactly as in Phase 7. Even with identities
  configured, this still doesn't confirm true object ownership — see
  `identity_authorization`'s module docstring for the exact limitation. It is a
  meaningfully stronger signal than Phase 7's placeholder, not a complete IDOR
  testing framework.
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
- runs form-level scanners (`csrf`, `file_upload`, `xxe`, `mass_assignment_candidate`)
  once per discovered form, passing the form's field names and method — these need
  the whole form's structure, not a single parameter.
- runs endpoint-level scanners (`graphql_introspection`, `websocket_auth`,
  `http_method_enum` — Phase 8) once per discovered endpoint, needing just a URL and
  method with no specific parameter or form. Each self-gates on URL shape (GraphQL
  introspection only fires on URLs containing "graphql"; WebSocket auth only on
  `ws://`/`wss://` URLs).
- isolates scanner exceptions — one scanner's bug is logged and recorded, never
  aborts the rest of the run.

## Multi-identity authorization testing (Phase 8)

`target.auth_contexts` (see `configs/example.yaml`) declares named identities for
cross-identity IDOR/BOLA testing. Each entry names an environment variable —
**never the credential value itself** — that must hold a real header value or cookie
value at scan time:

```yaml
target:
  auth_contexts:
    - label: user_a
      kind: header
      name: Authorization
      env_var: SENTINEL_AUTH_USER_A
    - label: user_b
      kind: header
      name: Authorization
      env_var: SENTINEL_AUTH_USER_B
```

```bash
export SENTINEL_AUTH_USER_A="Bearer eyJ..."
export SENTINEL_AUTH_USER_B="Bearer eyJ..."
sentinel scan test <scan_id> --config configs/example.yaml
```

If an environment variable isn't set at scan time, `identity_authorization` treats
that identity as unavailable (logs and skips it) rather than failing the scan — the
same graceful-degradation pattern used for Ollama (Phase 4) and Playwright
(Phase 3). With fewer than 2 available identities, the scanner returns no findings,
identical to having no `auth_contexts` configured at all.

**Not yet wired**: `Classification` rows from Phase 4 (AI-recommended tests) aren't
read by the orchestrator yet. The orchestrator currently runs its fixed scanner set
against every parameter (subject to mode); using AI recommendations to prioritize or
narrow that set is reasonable future work, not required for Phase 6's "detection
exists and works" goal.
