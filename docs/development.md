# Development Workflow

## Phase discipline

SENTINEL is built phase-by-phase (see the roadmap below). Each phase must be functional
and tested before the next one starts. No phase jumps ahead into later functionality.

## Roadmap

| Phase | Name | Status |
|---|---|---|
| 0 | Architecture | ✅ |
| 1 | Core Foundation | ✅ |
| 2 | Recon | ✅ |
| 3 | JavaScript Intelligence | ✅ |
| 4 | Ollama Intelligence | ✅ |
| 5 | Tool Orchestration | ⏳ next |
| 6 | Detection (XSS, SQLi, path traversal, open redirect, headers, info exposure) | not started |
| 7 | Advanced Detection (SSRF, SSTI, XXE, upload, CSRF, CORS, IDOR/BOLA, JWT) | not started |
| 8 | API Security (REST, GraphQL, WebSockets, authZ matrix) | not started |
| 9 | Verification & Correlation | not started |
| 10 | Reporting | not started |
| 11 | Dashboard | not started |
| 12 | Research / Advanced Intelligence | not started |

## Per-phase checklist

1. Inspect current implementation and dependencies before changing anything.
2. Run existing tests before making changes.
3. Make the smallest reasonable change to reach the phase goal.
4. Run tests again.
5. Update relevant `docs/*.md`.
6. Update `CHANGELOG.md` and bump version if applicable.
7. Commit using conventional commit style (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`).
8. Push only after tests pass.
9. Produce a phase-completion summary (goal, implemented, files changed, tests, known
   limitations, git checkpoint, next phase).

## Commands (`continue` / `fix` / `major change`)

- **"continue"** — inspect current project state, resume from the latest completed
  phase.
- **"fix"** — targeted fix only; do not touch unrelated code.
- **"major change"** — analyze architectural consequences first, explain impact, update
  architecture doc + tests + changelog, then implement.
