# Changelog

All notable changes to this project are documented here.
Format loosely follows Keep a Changelog; versions are pre-1.0 during phased development.

## [0.0.1] - Phase 0 - Architecture
### Added
- Repository skeleton (`app/`, `tests/`, `lab/`, `docs/`, `configs/`, `scripts/`,
  `.github/workflows/`, `.vscode/`).
- `docs/architecture.md` — system architecture, threat model, DB design, scan lifecycle,
  scan modes, tool integration strategy, Ollama architecture.
- `docs/setup.md`, `docs/development.md`, `docs/tools.md`, `docs/ollama.md`,
  `docs/scanners.md`, `docs/testing.md`, `docs/lab.md`, `docs/github-workflow.md` (stubs
  to be filled in as their respective phases land).
- `pyproject.toml` project metadata (dependencies unpinned — Phase 1).
- `CONTRIBUTING.md`, `SECURITY.md`, `.gitignore`, `LICENSE` placeholder.
- `.github/workflows/ci.yml` placeholder (lint/type-check/test, no live scanning).
- `.vscode/` debug/task scaffolding.

### Notes
- No scanning logic, tool adapters, database, or LLM integration exist yet — by design.
