# Setup (macOS / Apple Silicon)

This document will grow as tools are integrated in later phases. Phase 0 content only
covers the baseline Python environment.

## Requirements

- macOS on Apple Silicon
- Python 3.11+ (`brew install python@3.11` or `pyenv`)
- Git
- Docker Desktop (for the lab, introduced in Phase 41/lab work — not needed for Phase 0/1)
- Ollama (`brew install ollama`) — not required until Phase 4

## Phase 0/1 environment

```bash
git clone <this-repo>
cd sentinel
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

(`pyproject.toml`'s `[dev]` extras and actual dependency pins land in Phase 1.)

## Apple Silicon notes

External security tools (Nuclei, ffuf, Katana, httpx, XSStrike, sqlmap) are integrated in
Phase 5. Each adapter's `is_available()` will explicitly detect architecture and refuse to
silently run an incompatible (e.g., x86_64-only via Rosetta without the user's knowledge)
binary. Where a tool lacks a native ARM64 build, the adapter will report it as unavailable
and `docs/tools.md` will document the Docker-based fallback.
