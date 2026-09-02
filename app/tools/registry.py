"""ToolRegistry — central lookup for every registered SecurityToolAdapter.

Per docs/architecture.md §45 (extensibility): adding a new tool means creating
`app/tools/newtool.py` implementing SecurityToolAdapter and registering it in
`build_default_registry()` — nothing in core/db/cli/reporting/AI needs to change.
"""

from __future__ import annotations

from app.tools.base import SecurityToolAdapter


class ToolRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, SecurityToolAdapter] = {}

    def register(self, adapter: SecurityToolAdapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> SecurityToolAdapter | None:
        return self._adapters.get(name)

    def all(self) -> list[SecurityToolAdapter]:
        return list(self._adapters.values())

    async def availability_report(self) -> dict[str, dict]:
        report: dict[str, dict] = {}
        for adapter in self._adapters.values():
            available = adapter.is_available()
            version = await adapter.version() if available else None
            report[adapter.name] = {"available": available, "version": version}
        return report


def build_default_registry() -> ToolRegistry:
    """Registers every adapter SENTINEL ships. Imports are local to this function to
    avoid import cycles and so callers that only need one adapter aren't forced to
    import all six."""
    from app.tools.ffuf import FfufAdapter
    from app.tools.httpx import HttpxAdapter
    from app.tools.katana import KatanaAdapter
    from app.tools.nuclei import NucleiAdapter
    from app.tools.sqlmap import SqlmapAdapter
    from app.tools.xsstrike import XSStrikeAdapter

    registry = ToolRegistry()
    for adapter_cls in (
        HttpxAdapter,
        NucleiAdapter,
        FfufAdapter,
        KatanaAdapter,
        XSStrikeAdapter,
        SqlmapAdapter,
    ):
        registry.register(adapter_cls())
    return registry
