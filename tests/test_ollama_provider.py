import json

import httpx
import pytest

from app.llm.ollama_provider import OllamaProvider
from app.llm.schemas import EndpointClassification

_VALID_RESPONSE = {
    "endpoint": "/api/users/{id}",
    "parameter": "id",
    "classification": "identifier",
    "risk_score": 8,
    "recommended_tests": ["bola", "authorization"],
    "reason": "Object identifier in an authenticated endpoint.",
}


def _ollama_response_wrapping(payload: dict | str) -> dict:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return {"model": "test-model", "response": text, "done": True}


@pytest.mark.asyncio
async def test_successful_structured_completion():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/generate"
        body = json.loads(request.content)
        assert body["format"] == "json"
        return httpx.Response(200, json=_ollama_response_wrapping(_VALID_RESPONSE))

    provider = OllamaProvider(transport=httpx.MockTransport(handler))
    result = await provider.complete_structured("classify this", EndpointClassification)
    await provider.aclose()

    assert result is not None
    assert result.endpoint == "/api/users/{id}"
    assert result.risk_score == 8


@pytest.mark.asyncio
async def test_invalid_json_then_valid_on_repair_attempt():
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(200, json=_ollama_response_wrapping("not valid json at all"))
        return httpx.Response(200, json=_ollama_response_wrapping(_VALID_RESPONSE))

    provider = OllamaProvider(transport=httpx.MockTransport(handler), max_repair_attempts=1)
    result = await provider.complete_structured("classify this", EndpointClassification)
    await provider.aclose()

    assert call_count == 2
    assert result is not None
    assert result.endpoint == "/api/users/{id}"


@pytest.mark.asyncio
async def test_gives_up_after_max_repair_attempts_and_returns_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ollama_response_wrapping("still not json"))

    provider = OllamaProvider(transport=httpx.MockTransport(handler), max_repair_attempts=1)
    result = await provider.complete_structured("classify this", EndpointClassification)
    await provider.aclose()

    assert result is None


@pytest.mark.asyncio
async def test_valid_json_but_schema_mismatch_returns_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ollama_response_wrapping({"unexpected": "shape"}))

    provider = OllamaProvider(transport=httpx.MockTransport(handler), max_repair_attempts=0)
    result = await provider.complete_structured("classify this", EndpointClassification)
    await provider.aclose()

    assert result is None


@pytest.mark.asyncio
async def test_strips_markdown_fences_defensively():
    fenced = "```json\n" + json.dumps(_VALID_RESPONSE) + "\n```"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ollama_response_wrapping(fenced))

    provider = OllamaProvider(transport=httpx.MockTransport(handler))
    result = await provider.complete_structured("classify this", EndpointClassification)
    await provider.aclose()

    assert result is not None
    assert result.classification.value == "identifier"


@pytest.mark.asyncio
async def test_check_availability_true_on_200():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": []})

    provider = OllamaProvider(transport=httpx.MockTransport(handler))
    assert await provider.check_availability() is True
    await provider.aclose()


@pytest.mark.asyncio
async def test_check_availability_false_on_connection_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    provider = OllamaProvider(transport=httpx.MockTransport(handler))
    assert await provider.check_availability() is False
    await provider.aclose()


@pytest.mark.asyncio
async def test_http_error_during_generation_returns_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    provider = OllamaProvider(transport=httpx.MockTransport(handler))
    result = await provider.complete_structured("classify this", EndpointClassification)
    await provider.aclose()

    assert result is None
