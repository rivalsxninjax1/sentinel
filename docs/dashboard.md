# Dashboard (Phase 11)

## What it is

A local, read-only web UI over the scan database — scan status, attack surface
(hosts/endpoints/parameters/technologies), findings (reusing Phase 10's report
renderer), and AI reasoning (Phase 4's classifications). Per
docs/architecture.md §11's roadmap entry, this is the human-facing view of
everything the CLI has already produced — it does not run scans, does not trigger
scanners, and does not write to the database anywhere.

```bash
pip install -e ".[dashboard]"
sentinel dashboard --config configs/example.yaml
# -> SENTINEL dashboard running at http://127.0.0.1:8000
```

## Routes

| Route | Shows |
|---|---|
| `GET /` | Every scan: target, mode, status, start time, link to detail |
| `GET /scans/{scan_id}` | Overview: attack-surface counts, findings-by-disposition counts, AI classification counts, links to sub-pages |
| `GET /scans/{scan_id}/findings` | Full findings report — **literally calls `app.reporting.builder.ReportBuilder` + `html_renderer.render()` from Phase 10**, not a separate reimplementation |
| `GET /scans/{scan_id}/attack-surface` | Every host, its technologies, and every endpoint with its parameters |
| `GET /scans/{scan_id}/classifications` | Every AI classification (Phase 4): endpoint, parameter, classification, risk score, recommended tests, reasoning, source (ai/fallback) |

## Why FastAPI/Jinja2 are optional dependencies

Same pattern as Playwright (Phase 3) and `websockets` (Phase 8):
`app/dashboard/app.py` wraps the imports in a try/except and exposes
`is_available()`; `create_dashboard_app()` raises a clear `DashboardUnavailable`
(caught by the CLI, printed as a `pip install` hint) rather than crashing with a
bare `ImportError` if the `dashboard` extra isn't installed. The base SENTINEL
install stays lightweight for anyone who only needs the CLI/scanning pipeline.

## Security posture — read this before running it anywhere but your own machine

**There is no authentication on this server.** Anyone who can reach the bound
host/port can view every scan's findings, including reflected content from the
target application. The CLI:

- binds to `127.0.0.1` by default,
- prints an explicit warning to stderr if you pass `--host` set to anything else
  (it does not refuse — the operator may have a legitimate reason, e.g. an
  already-firewalled internal network — but it will not let you do so silently).

Do not bind this to `0.0.0.0` or otherwise expose it beyond localhost without
adding an authentication layer first. That is explicitly out of scope for this
phase; if the dashboard needs to be shared with a team, adding auth (even HTTP
basic auth in front via a reverse proxy) should happen before wider deployment,
not be assumed unnecessary because "it's just a dashboard."

## Escaping discipline

Everything the dashboard displays that originates from the *scanned target*
(endpoint paths, parameter names, technology names/versions, AI classification
reasoning text which may itself quote target content) is potentially hostile —
exactly the same threat model as Phase 10's HTML report. `app/dashboard/templates.py`
uses a Jinja2 `Environment(autoescape=True)`, so every `{{ variable }}`
interpolation is HTML-escaped automatically, rather than relying on manually
remembering to call `html.escape()` at each call site the way Phase 10's static
renderer does.

**One real bug this caught during development:** the outer page layout
(`render_page()`) initially re-escaped the already-escaped output of each page's
own sub-template, corrupting entities like `&lt;` into `&amp;lt;` instead of
displaying them correctly. Fixed by wrapping the pre-rendered, already-safe body
in `markupsafe.Markup()` before handing it to the outer layout template — Jinja2
autoescaping only escapes strings it doesn't already consider safe, and
`Markup()` is exactly how you tell it "this is already-escaped, trusted output,
don't touch it again." `tests/test_dashboard.py`'s hostile-endpoint-path test
caught this the first time it ran (the raw payload wasn't in the output, but
neither was the expected escaped form — it was double-escaped) — kept as a
permanent regression test.

The `/findings` route sidesteps this whole question by directly returning Phase
10's `html_renderer.render(report)` output as its own complete page (not wrapped
in the dashboard's layout) — reusing already-tested manual-escaping logic rather
than re-implementing findings display with a second escaping mechanism.

## What Phase 11 does NOT do

- No authentication/authorization (see above).
- No live/streaming updates while a scan is running — every page is a fresh query
  against the current database state at request time, not a websocket-pushed live
  view. Refresh the page to see new data.
- No tool-run history table (Phase 5's adapters aren't wired into scan execution
  yet, so there's nothing scan-specific to show beyond what `Test`/`Finding`
  already capture from deterministic scanners).
- No JS-asset listing on the attack-surface page (Phase 3 only added
  `add_javascript_asset` with get-or-create dedup, no `list_javascript_assets_for_host`
  query yet) — noted as a small gap rather than silently omitted.
