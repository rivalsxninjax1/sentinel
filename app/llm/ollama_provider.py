"""OllamaProvider — talks to a local Ollama instance over HTTP.

Uses Ollama's `format: "json"` request mode (constrained JSON generation) as the first
line of defense, then independently validates the result against the requested
Pydantic schema before ever returning it — `format: "json"` guarantees *parseable*
JSON, not schema-conformant JSON, so validation still has to happen here regardless.

Per docs/architecture.md §7: invalid output is rejected, then retried once with the
validation error fed back to the model (a bounded "repair" attempt), and if that also
fails, `complete_structured()` returns None — the caller falls back to deterministic
behavior. There is no path where malformed AI output reaches anything else in the
system.
"""

from __future__ import annotations

import json
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from app.core.logging import get_logger
from app.llm.provider import LLMProvider

logger = get_logger(__name__)

T = TypeVar("T", bound=BaseModel)


class OllamaProvider(LLMProvider):
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3",
        temperature: float = 0.0,
        timeout: float = 30.0,
        max_repair_attempts: int = 1,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """`transport` is exposed only so tests can inject an `httpx.MockTransport`
        instead of requiring a real running Ollama instance."""
        self._model = model
        self._temperature = temperature
        self._max_repair_attempts = max_repair_attempts
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout, transport=transport)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def check_availability(self) -> bool:
        try:
            response = await self._client.get("/api/tags")
            return response.status_code == 200
        except httpx.HTTPError as exc:
            logger.info("ollama_unavailable", error=str(exc))
            return False

    async def complete_structured(self, prompt: str, schema: type[T]) -> T | None:
        schema_json = schema.model_json_schema()
        instruction = (
            f"{prompt}\n\n"
            "Respond ONLY with a single valid JSON object matching this JSON Schema. "
            "No prose, no markdown code fences, no explanation before or after the JSON.\n"
            f"Schema:\n{json.dumps(schema_json)}"
        )

        last_raw: str | None = None
        for attempt in range(self._max_repair_attempts + 1):
            try:
                raw = await self._generate(instruction)
            except httpx.HTTPError as exc:
                logger.warning("ollama_request_failed", error=str(exc), attempt=attempt)
                return None

            last_raw = raw
            parsed = self._try_parse(raw, schema)
            if parsed is not None:
                return parsed

            logger.info("ollama_invalid_output", attempt=attempt, raw_preview=raw[:200])
            instruction = (
                f"{prompt}\n\n"
                "Your previous response was not valid JSON matching the required schema. "
                "Respond ONLY with a single valid JSON object matching this JSON Schema. "
                "No prose, no markdown code fences.\n"
                f"Schema:\n{json.dumps(schema_json)}\n\n"
                f"Your previous invalid response was:\n{raw}"
            )

        logger.warning("ollama_gave_up", raw_preview=(last_raw or "")[:200])
        return None

    async def _generate(self, prompt: str) -> str:
        response = await self._client.post(
            "/api/generate",
            json={
                "model": self._model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": self._temperature},
            },
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response", "")

    @staticmethod
    def _try_parse(raw: str, schema: type[T]) -> T | None:
        cleaned = raw.strip()
        # Defensive cleanup: format="json" should prevent markdown fences, but don't
        # rely on that from every model.
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            return None

        try:
            return schema.model_validate(data)
        except ValidationError:
            return None
