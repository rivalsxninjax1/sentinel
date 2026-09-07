# Reporting (Phase 10)

## Pipeline

```
Finding rows (Phase 6-9, with verification_status + confidence set)
        ↓
ReportBuilder.build(scan_id)     app/reporting/builder.py
        ↓
ReportData                       app/reporting/models.py
        ↓
   ┌────┴────┬─────────┐
json_renderer  markdown_renderer  html_renderer
```

All three renderers consume exactly the same `ReportData` object built once by
`ReportBuilder` — there is no separate data-gathering path per format, so the
three outputs can never show different numbers for the same scan.

## Disposition mapping (`app/reporting/disposition.py`)

Per docs/architecture.md §40, every report must distinguish: **Confirmed | Likely
| Potential | Informational | Requires Manual Verification**. SENTINEL derives
this from the `(verification_status, confidence)` pair Phase 9 already computed:

| verification_status | confidence | disposition |
|---|---|---|
| `false_positive` | any | **excluded from the main report** (see below) |
| `needs_manual_review` or `unverified` | any | Requires Manual Verification |
| `verified` | `info` | Informational |
| `verified` | `low` or `medium` | Potential |
| `verified` | `high` | Likely |
| `verified` | `confirmed` | Confirmed — **unreachable in this codebase**, see below |

### Why "Confirmed" never actually appears

No scanner, tool adapter, `VerificationEngine`, or `CorrelationEngine` anywhere in
SENTINEL ever sets a `Finding.confidence` to `"confirmed"` —
`app/verification/engine.py`'s upgrade path is hard-capped at `"high"`. The
`"confirmed"` row in the table above exists so the mapping function is total (every
possible confidence value has a defined disposition), not because SENTINEL
currently produces it. If a future phase adds an explicit human sign-off workflow,
that workflow should be the only code path allowed to write `"confirmed"`.

## False positives are excluded, not just downgraded

`ReportBuilder` never puts a `verification_status == "false_positive"` finding into
`ReportData.findings`. They go into `excluded_false_positives` instead, and every
renderer shows them in a clearly-labeled appendix ("audit-trail transparency only,
not as vulnerabilities") rather than mixing them into the main findings list at any
disposition level. This matches the non-negotiable rule against reporting
speculative results as findings.

## CWE / impact / remediation (`app/reporting/knowledge_base.py`)

A static dictionary mapping each `vulnerability_class` string SENTINEL's scanners
produce to a CWE ID, a generic impact statement, and generic remediation guidance.
`tests/test_knowledge_base.py::test_every_scanner_vulnerability_class_has_a_knowledge_base_entry`
greps every scanner file for its `vulnerability_class` value and asserts the
knowledge base covers all of them — a new scanner with no matching entry fails CI,
not silently ships with blank CWE/remediation fields.

This text is deliberately generic (SENTINEL doesn't know your application's
specific architecture) — it supplements, never replaces, the finding's own
`description`/`evidence` fields.

## Approximate CVSS

`approximate_cvss()` maps `severity` to a single rough base-score number
(critical→9.0, high→7.5, medium→5.4, low→3.1, info→none). **This is explicitly not
a real CVSS vector calculation** — a genuine CVSS score requires attack-vector,
attack-complexity, privileges-required, user-interaction, scope, and impact
sub-metrics that depend on specifics SENTINEL doesn't determine. Every renderer
labels this field "Approximate CVSS (severity-based estimate)", never bare "CVSS
Score", so nobody mistakes it for a rigorous calculation.

## HTML output security

Every string in an HTML report that originates from the *scanned target*
(reflected finding titles, `matched_endpoint`, `description`, `evidence`) is
target-controlled, potentially hostile data — a malicious target could shape its
responses specifically to inject markup into a report a human will later open.
`app/reporting/renderers/html_renderer.py` runs every such value through
`html.escape()` before writing it into the document; only SENTINEL's own static
labels are written unescaped. `tests/test_report_renderers.py` includes dedicated
tests injecting `<script>`/`<img onerror=...>` payloads into titles, evidence, and
even the target name, asserting they never appear unescaped in the output.

## Running it

```bash
sentinel scan report <scan_id> --config configs/example.yaml --format all --output-dir reports
```

Requires the scan to be in `CORRELATING` (i.e., after `scan verify`). Writes
`reports/<scan_id>/report.{json,md,html}` (or just one, with `--format
json|markdown|html`). Advances `CORRELATING` → `REPORTING` → `COMPLETE` — **this is
the final lifecycle stage**; a scan that reaches `COMPLETE` has gone through the
entire recon → discovery → intelligence → testing → verification → reporting
pipeline.

## What Phase 10 does NOT do

- No PDF output (HTML can be printed to PDF by a browser; a dedicated PDF renderer
  is reasonable future work, not required by the roadmap for this phase).
- No cross-scan comparison/trend reporting (scan history comparison and regression
  detection are explicitly Phase 12 territory per the roadmap).
- No report re-generation/caching — every `scan report` run rebuilds `ReportData`
  from scratch from the current database state.
