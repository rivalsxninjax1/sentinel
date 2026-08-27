# Contributing

This is a phased personal/team security research project. If contributing:

1. Read `docs/architecture.md` and `docs/development.md` first.
2. Follow the phase roadmap — don't implement functionality from a later phase.
3. Every change needs tests where testable.
4. Use conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`).
5. Never commit credentials, real target data, or scan results against non-owned,
   non-authorized targets.
6. Any new external tool integration must document its license in `docs/tools.md`
   before code lands (see governing spec rule §47).
