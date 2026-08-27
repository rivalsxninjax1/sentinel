# External Tool Integration

No tool adapters are implemented yet (Phase 5). This document will track, per tool:
license, redistribution/commercial restrictions, version pinning strategy, Apple Silicon
support, and the adapter's scope-enforcement points.

Planned adapters: `httpx` (ProjectDiscovery), `Katana`, `ffuf`, `XSStrike`, `sqlmap`,
`Nuclei`.

> Naming note: ProjectDiscovery's `httpx` (Go CLI) is unrelated to the Python `httpx`
> HTTP client library SENTINEL uses internally. Both are referenced elsewhere in this
> project; adapter code will always refer to the CLI tool as `httpx_cli` internally to
> avoid ambiguity.

Each adapter entry (added as implemented) will contain:

```
Tool:            <name>
License:         <license + link>
Redistribution:  <notes>
Version pinned:  <version>
Apple Silicon:   <native / Docker fallback>
Scope enforcement: <where ScopeEngine.check() is invoked in this adapter>
```
