# Testing Strategy

- Unit tests for all deterministic logic (scope engine, rate limiter, normalizers,
  confidence engine).
- Integration tests against the local vulnerable lab (`lab/`, Phase-appropriate).
- Every confirmed vulnerability class gets a regression test once implemented
  (`test_xss_reflection`, `test_idor_cross_user`, `test_false_positive_xss`, etc. — see
  governing spec §42).
- CI (`.github/workflows/`) runs lint + type-check + unit tests only — it does not run
  live scans against anything.
