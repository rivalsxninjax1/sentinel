# Verification & Correlation (Phase 9)

## Why this phase exists

Every scanner and tool adapter built in Phases 5-8 produces *candidates* — a
`Finding` row with a scanner-assigned `confidence` (`info`/`low`/`medium`/`high`,
never `confirmed`) but no cross-checking against a baseline and no awareness of
what other scanners found on the same endpoint. Phase 9 adds the two components
docs/architecture.md §21-24 describe as sitting between "a scanner said something"
and "this is worth reporting as high-confidence": the **Verification Engine**
(baseline/differential analysis, per finding) and the **Correlation Engine**
(cross-source agreement/conflict, per endpoint+vulnerability-class group).

## Verification Engine (`app/verification/engine.py`)

For each `Finding`, one of three things happens:

1. **Objective/factual classes** (`security_headers`, `information_exposure`,
   `cors`, `http_method_enumeration`) — the evidence already IS the observation
   (a header is missing, or it isn't; an Allow header lists PUT, or it doesn't).
   No baseline request is needed. Marked `verified` immediately, confidence
   unchanged.

2. **Reflection/injection classes with a known signature** (`xss`, `ssti`, `sqli`,
   `path_traversal`, `xxe`, `ssrf`) — a **baseline request** is made: the same
   endpoint, but with the payload-bearing parameter removed (for XXE, a plain GET
   instead of resending the XXE payload). The exact same signature check the
   original scanner used is re-applied to the baseline response:
   - Baseline **also** matches → the app returns this content regardless of any
     payload → `false_positive`. Confidence is left unchanged (not downgraded
     further — the label itself carries the meaning).
   - Baseline does **not** match → the original finding survives a differential
     check → `verified`, confidence upgraded exactly one step
     (`low`→`medium`→`high`, capped — see below).
   - Baseline request itself fails (network error, scope violation) →
     `needs_manual_review` (fails closed, never guesses).

3. **Everything else** (`idor_bola`, `mass_assignment`, `unsafe_file_upload`,
   `jwt`, `websocket_authorization`, `graphql_introspection`, `csrf`) — SENTINEL
   has no automated way to confirm real-world impact for these. Marked
   `needs_manual_review`, confidence unchanged. This is not a lesser engine
   feature — it's an honest admission matching docs/architecture.md §13's
   required "requires manual verification" category.

### The hard cap: confidence never reaches "confirmed"

`app/verification/engine.py`'s `_upgrade()` can raise confidence by at most one
step per finding, and the ceiling is hard-coded to `"high"` —
`_MAX_AUTOMATED_CONFIDENCE = "high"`. No code path anywhere in SENTINEL (scanners,
verification, or correlation) sets a `Finding.confidence` or a `Correlation.
combined_confidence` to `"confirmed"`. Per docs/architecture.md §22: *"Only strong
evidence should become a confirmed vulnerability."* SENTINEL's position, as of
Phase 9, is that a differential baseline check plus multi-source agreement is
strong corroborating evidence, but confirming a vulnerability is a human
sign-off action this codebase does not perform automatically. If a
manual-confirmation workflow is added in a later phase, it should be the only
thing allowed to write `"confirmed"`.

## Correlation Engine (`app/verification/correlation.py`)

Groups `Finding`s by `(endpoint_id, vulnerability_class)`. A group only produces
a `Correlation` record if it has **2+ findings from 2+ distinct scanner/tool
names** — the same scanner reporting the same thing twice is not independent
corroboration (docs/architecture.md §24's own example combines three genuinely
different sources: XSStrike, a custom reflection analyzer, and browser
verification).

| Group composition | `status` | `combined_confidence` |
|---|---|---|
| All findings `verified` | `agreement` | `high` |
| Mix of `verified` and `false_positive` | `conflicting_evidence` | `low` |
| Anything else (e.g. multiple `needs_manual_review`) | `insufficient_correlation` | highest individual confidence in the group |

**Correlation never mutates the underlying `Finding` rows.** Each finding's own
`confidence`/`verification_status` (set by the Verification Engine) is left
exactly as determined — Correlation is a separate, additive read-model
(`Correlation` table) for an aggregate view, not a second opinion that silently
overwrites the first. This is a deliberate design choice: it means a viewer can
always see both "what did source X individually conclude" and "what's the
aggregate picture across sources" without one hiding the other.

## Running it

```bash
sentinel scan verify <scan_id> --config configs/example.yaml
```

Requires the scan to be in `TESTING` (i.e., after `scan test`). Advances
`TESTING` → `VERIFYING` → `CORRELATING`. Reporting (Phase 10) picks up from
`CORRELATING`.

## What Phase 9 does NOT do

- Does not perform timing-based blind-injection verification (docs/architecture.md
  §23 lists "timing analysis" as a differential technique; only response-content
  differential analysis is implemented here).
- Does not do DOM-based differential analysis (would need the Phase 3
  `BrowserEngine`, not wired in here).
- Does not compare across authentication states beyond what
  `identity_authorization` (Phase 8) already does at scan-time — there's no
  separate "authentication comparison" verification pass distinct from that
  scanner.
- Does not re-run tool adapters (Nuclei/sqlmap/XSStrike/etc.) as part of
  verification — only re-examines the deterministic scanners' own signatures
  against a baseline. Tool-adapter findings (Phase 5) still get a
  `verification_status` (falling into the "everything else" →
  `needs_manual_review` bucket, since their `vulnerability_class` values
  currently aren't in `_BASELINE_CHECKS`), but aren't differentially re-tested.
