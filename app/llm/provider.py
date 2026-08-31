"""LLMProvider — abstraction over the local AI reasoning backend.

Per docs/architecture.md §8: SENTINEL doesn't hardcode a single Ollama model or even
Ollama itself. Every provider implements `complete_structured()`, which either returns
a validated instance of the requested Pydantic schema or `None` — never a raw string,
never a partially-validated object. `None` means "no usable AI output"; callers (see
app/intelligence/reasoning.py) treat that identically to "AI not configured at all."
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMProvider(ABC):
    @abstractmethod
    async def complete_structured(self, prompt: str, schema: type[T]) -> T | None:
        """Ask the model to produce output matching `schema`. Returns a validated
        instance, or None if the model is unreachable or never produced anything that
        validates (after any internal repair/retry attempts)."""
        raise NotImplementedError

    @abstractmethod
    async def check_availability(self) -> bool:
        """Cheap reachability check, used so callers can decide once whether to
        attempt AI reasoning at all, rather than paying a timeout per call."""
        raise NotImplementedError
