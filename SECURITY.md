# Security Policy — SENTINEL

SENTINEL is a security testing tool. Using it against systems you do not own or do not
have explicit written authorization to test is out of scope for this project and may be
illegal in your jurisdiction. Nothing in this repository is intended to enable
unauthorized access to computer systems.

## Handling of this tool's own vulnerabilities

If you find a security issue in SENTINEL itself (e.g., a scope-bypass bug, credential
leakage, an unsafe default), please open an issue marked `security` or contact the
maintainer directly rather than filing a public exploit write-up, given the tool's
sensitive purpose.

## Design commitments (see docs/architecture.md §2, §11)

- Scope enforcement at multiple layers, not a single checkpoint.
- No destructive testing modes exist in the current roadmap.
- Credentials are never stored in source or logged in plaintext.
- AI (Ollama) output never directly triggers a test; it is a validated recommendation
  only.
