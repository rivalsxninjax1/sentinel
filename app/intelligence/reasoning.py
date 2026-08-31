"""SecurityReasoningEngine — the only thing in SENTINEL allowed to ask an LLM for a
security opinion, and the boundary that guarantees that opinion is either a validated
`EndpointClassification` or nothing at all.

Per docs/architecture.md §7/§44: the AI's output is a recommendation, never a direct
trigger, and a missing/unreachable/misconfigured LLM must never block deterministic
scan progress — it just means no AI-prioritized recommendations get added, and every
consumer of this engine already has to handle that (`source="fallback"`) as a normal,
expected outcome, not an error path.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.logging import get_logger
from app.llm.provider import LLMProvider
from app.llm.schemas import EndpointClassification

logger = get_logger(__name__)


@dataclass
class ClassificationOutcome:
    classification: EndpointClassification | None
    source: str  # "ai" | "fallback"


def build_classification_prompt(
    endpoint_path: str,
    method: str,
    parameter_name: str | None,
    parameter_location: str | None,
    technologies: list[str] | None = None,
) -> str:
    lines = [
        "You are a web application security researcher performing reconnaissance "
        "analysis on an authorized target. Classify the following discovered "
        "endpoint/parameter and recommend which vulnerability classes are worth "
        "testing. Do not claim a vulnerability exists — you are prioritizing what a "
        "human/automated tester should look at next, not confirming any finding.",
        "",
        f"Method: {method}",
        f"Endpoint: {endpoint_path}",
    ]
    if parameter_name:
        lines.append(f"Parameter: {parameter_name} (location: {parameter_location or 'unknown'})")
    else:
        lines.append("Parameter: none (endpoint-level classification)")
    if technologies:
        lines.append(f"Known technologies on this host: {', '.join(technologies)}")
    return "\n".join(lines)


class SecurityReasoningEngine:
    def __init__(self, provider: LLMProvider | None) -> None:
        self._provider = provider

    @property
    def ai_enabled(self) -> bool:
        return self._provider is not None

    async def classify_endpoint_parameter(
        self,
        endpoint_path: str,
        method: str,
        parameter_name: str | None = None,
        parameter_location: str | None = None,
        technologies: list[str] | None = None,
    ) -> ClassificationOutcome:
        if self._provider is None:
            return ClassificationOutcome(classification=None, source="fallback")

        prompt = build_classification_prompt(
            endpoint_path, method, parameter_name, parameter_location, technologies
        )

        try:
            result = await self._provider.complete_structured(prompt, EndpointClassification)
        except Exception as exc:  # defensive: provider bugs must not crash the scan
            logger.warning(
                "llm_classification_failed", endpoint=endpoint_path, error=str(exc)
            )
            return ClassificationOutcome(classification=None, source="fallback")

        if result is None:
            return ClassificationOutcome(classification=None, source="fallback")

        return ClassificationOutcome(classification=result, source="ai")
