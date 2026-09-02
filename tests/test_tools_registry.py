import pytest

from app.tools.base import SecurityToolAdapter, ToolExecutionContext
from app.tools.registry import ToolRegistry, build_default_registry


class _FakeAvailableAdapter(SecurityToolAdapter):
    name = "fake-available"
    binary_name = "fake-available-binary"

    def is_available(self) -> bool:
        return True

    async def version(self) -> str | None:
        return "9.9.9"

    def build_command(self, context: ToolExecutionContext) -> list[str]:
        return []

    def parse(self, raw_output: str) -> list[dict]:
        return []

    def normalize(self, parsed, context, tool_version):
        return []


class _FakeUnavailableAdapter(SecurityToolAdapter):
    name = "fake-unavailable"
    binary_name = "fake-unavailable-binary"

    def is_available(self) -> bool:
        return False

    async def version(self) -> str | None:
        return None

    def build_command(self, context: ToolExecutionContext) -> list[str]:
        return []

    def parse(self, raw_output: str) -> list[dict]:
        return []

    def normalize(self, parsed, context, tool_version):
        return []


def test_register_and_get():
    registry = ToolRegistry()
    adapter = _FakeAvailableAdapter()
    registry.register(adapter)
    assert registry.get("fake-available") is adapter
    assert registry.get("nonexistent") is None


def test_all_returns_every_registered_adapter():
    registry = ToolRegistry()
    registry.register(_FakeAvailableAdapter())
    registry.register(_FakeUnavailableAdapter())
    assert {a.name for a in registry.all()} == {"fake-available", "fake-unavailable"}


@pytest.mark.asyncio
async def test_availability_report():
    registry = ToolRegistry()
    registry.register(_FakeAvailableAdapter())
    registry.register(_FakeUnavailableAdapter())

    report = await registry.availability_report()

    assert report["fake-available"] == {"available": True, "version": "9.9.9"}
    assert report["fake-unavailable"] == {"available": False, "version": None}


def test_build_default_registry_registers_all_six_adapters():
    registry = build_default_registry()
    names = {a.name for a in registry.all()}
    assert names == {"httpx", "nuclei", "ffuf", "katana", "xsstrike", "sqlmap"}
