# External Tool Integration

## Adapter interface

Every external tool is wrapped by a `SecurityToolAdapter` (`app/tools/base.py`).
`run()` is the only method orchestration code calls, and it always does, in order:

```
scope.enforce(target_url)   -> ScopeViolation if out of scope, raised immediately
is_available()               -> ToolUnavailable if binary not on PATH
validate_config(context)     -> ToolConfigError if e.g. mode is wrong for this tool
version()
build_command(context)
<subprocess execution, timeout-bound>
parse(raw_output)
normalize(parsed, context, version) -> list[NormalizedFinding]
```

No adapter can skip the scope check — it happens in the shared `run()` implementation,
not per-adapter, so a new adapter can't accidentally omit it.

## Registered adapters

| Tool | Adapter | Requires mode | Output parsing | License note |
|---|---|---|---|---|
| ProjectDiscovery `httpx` | `app/tools/httpx.py` | any | JSON lines | ⚠️ see naming collision below |
| ProjectDiscovery `nuclei` | `app/tools/nuclei.py` | safe/active | JSON lines | check license before enabling `-active` template categories |
| `ffuf` | `app/tools/ffuf.py` | safe/active | single JSON object | requires `context.extra["wordlist"]` — SENTINEL never auto-selects one |
| ProjectDiscovery `katana` | `app/tools/katana.py` | any | JSON lines | complements, doesn't replace, SENTINEL's own crawler |
| `XSStrike` | `app/tools/xsstrike.py` | active only | line-heuristic (no stable JSON mode) | findings are low-confidence until Phase 9 verification |
| `sqlmap` | `app/tools/sqlmap.py` | active only | line-heuristic | **never** add `--dump`/`--os-shell`/`--os-pwn`/`--sql-shell` — enforced by review, not code, so double-check any future edits to `build_command()` |

Run `sentinel tools list` to see live availability + version for every registered
adapter without running any of them.

## ⚠️ Naming collision: `httpx` (binary) vs `httpx` (Python package)

**Confirmed during Phase 5 testing, not hypothetical:** the Python `httpx` library
(used throughout the rest of SENTINEL as an HTTP client) installs its own `httpx` CLI
script. If it's on PATH ahead of ProjectDiscovery's Go binary of the same name,
`HttpxAdapter.is_available()` (a simple `shutil.which` check) will report "available"
against the *wrong* binary.

This fails safely, not silently-wrong: the adapter will invoke flags
(`-json -silent -rate-limit ...`) the Python package's CLI doesn't understand, get no
parseable JSON lines back, and `normalize()` will just return zero findings — it does
not produce garbage results. `sentinel tools list` also actively flags this case (available
but no version detected) with a specific warning message pointing here.

**Fix on your machine:** confirm which `httpx` resolves first:
```bash
which httpx
httpx -version   # ProjectDiscovery's binary prints a version banner; the Python CLI errors
```
If it's the wrong one, either uninstall/rename the Python package's script, or install
ProjectDiscovery's httpx to a location earlier in PATH, or (cleanest) rename
ProjectDiscovery's binary — e.g. `httpx-pd` — and point SENTINEL config at that name
once tool binary paths become configurable (currently hardcoded as `binary_name` per
adapter; making this configurable is a reasonable Phase 6+ follow-up if this bites
people in practice).

## License check (before enabling any adapter for real use)

Per the governing spec's rule #47 — check before integrating, not after:

```
Tool:              <name>
License:           <license + link>
Redistribution:    <notes>
Version pinned:    <version>
Apple Silicon:     <native / Docker fallback>
Scope enforcement: enforced centrally in SecurityToolAdapter.run() — not per-adapter
```

Fill this in per tool once you've actually installed and decided to use it; not
populated yet since none of these binaries are installed in the dev/CI environment
this was built in.

## Rate limiting for external tools

SENTINEL's own `RateLimiter` (app/core/rate_limiter.py) paces SENTINEL's own HTTP
client. It cannot intercept requests an external binary issues internally. Instead,
every adapter's `build_command()` derives that tool's own native rate-limit flag
(`-rate-limit`, `-rate`, etc.) from `context.requests_per_second`. This is the same
"native flags, not interception" tradeoff already documented for Playwright in
docs/architecture.md (Phase 3) — consistent, not a new gap.

## Not yet wired into scan execution

Phase 5 delivers the adapter interface, registry, and six working adapters — it does
NOT decide when a scan should actually invoke one. That decision (reading a scan's
`Classification` recommendations from Phase 4 and deciding which adapters to run,
subject to scan mode) is Phase 6+ orchestration logic, deliberately not built yet per
the "don't jump ahead" rule.
