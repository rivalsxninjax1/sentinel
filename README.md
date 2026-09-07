# SENTINEL

**AI-Assisted Context-Aware Web Application Security Testing and Vulnerability
Verification Platform.**

SENTINEL orchestrates specialized security tools (XSStrike, sqlmap, Nuclei, ffuf,
Katana, httpx) against **explicitly authorized** targets, uses a local Ollama model for
recon reasoning and test prioritization (never for unsupervised execution), and runs
every candidate finding through a verification and false-positive-reduction pipeline
before it's reported. See `docs/architecture.md` for the full design.

> ⚠️ **Authorized use only.** SENTINEL is built for bug bounty programs where the target
> is explicitly in scope, authorized penetration tests, applications you own, and local
> vulnerable labs / CTFs. It is not designed for, and must not be used for, scanning
> arbitrary internet targets without authorization.

## Status

Phase 0 — Architecture. No scanning functionality exists yet. See `CHANGELOG.md` and
`docs/architecture.md` §13 for the current phase and what's next.

## Project layout

See `docs/architecture.md` §4 for the full repository structure and rationale.

## Documentation

- `docs/architecture.md` — system architecture, threat model, DB design, scan lifecycle
- `docs/setup.md` — environment setup (macOS / Apple Silicon)
- `docs/development.md` — phase-by-phase development workflow
- `docs/tools.md` — external tool adapters, licensing notes
- `docs/ollama.md` — local AI reasoning layer
- `docs/scanners.md` — deterministic detection engine coverage and limitations
- `docs/verification.md` — verification engine, correlation engine, confidence cap
- `docs/testing.md` — test strategy, lab-based regression testing
- `docs/lab.md` — local vulnerable lab setup
- `docs/github-workflow.md` — commit/branch/checkpoint conventions

## License

See `LICENSE`.
