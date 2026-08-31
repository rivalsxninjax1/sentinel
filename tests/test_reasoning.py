import pytest

from app.intelligence.reasoning import SecurityReasoningEngine
from app.llm.provider import LLMProvider
from app.llm.schemas import EndpointClassification


class _StubProvider(LLMProvider):
    def __init__(self, result: EndpointClassification | None = None, raise_error: bool = False):
        self._result = result
        self._raise_error = raise_error

    async def complete_structured(self, prompt, schema):
        if self._raise_error:
            raise RuntimeError("boom")
        return self._result

    async def check_availability(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_no_provider_returns_fallback():
    engine = SecurityReasoningEngine(provider=None)
    outcome = await engine.classify_endpoint_parameter("/api/users/{id}", "GET", "id", "path")
    assert outcome.source == "fallback"
    assert outcome.classification is None
    assert engine.ai_enabled is False


@pytest.mark.asyncio
async def test_provider_success_returns_ai_outcome():
    classification = EndpointClassification(
        endpoint="/api/users/{id}",
        parameter="id",
        classification="identifier",
        risk_score=9,
        recommended_tests=["bola"],
        reason="Object identifier",
    )
    engine = SecurityReasoningEngine(provider=_StubProvider(result=classification))
    outcome = await engine.classify_endpoint_parameter("/api/users/{id}", "GET", "id", "path")
    assert outcome.source == "ai"
    assert outcome.classification is not None
    assert outcome.classification.risk_score == 9
    assert engine.ai_enabled is True


@pytest.mark.asyncio
async def test_provider_returning_none_falls_back():
    engine = SecurityReasoningEngine(provider=_StubProvider(result=None))
    outcome = await engine.classify_endpoint_parameter("/api/users/{id}", "GET")
    assert outcome.source == "fallback"
    assert outcome.classification is None


@pytest.mark.asyncio
async def test_provider_exception_falls_back_without_raising():
    engine = SecurityReasoningEngine(provider=_StubProvider(raise_error=True))
    outcome = await engine.classify_endpoint_parameter("/api/users/{id}", "GET")
    assert outcome.source == "fallback"
    assert outcome.classification is None
