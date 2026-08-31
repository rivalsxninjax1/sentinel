"""Structured-output schemas for every LLM interaction.

Per docs/architecture.md §7: Ollama never returns free-form text that SENTINEL acts
on. Every response is validated against one of these Pydantic models; anything that
doesn't validate is treated as no recommendation at all (see
app/intelligence/reasoning.py), never passed through partially or "best-effort"
parsed.

Enums constrain the vocabulary the model can use — this is deliberate: it keeps
`recommended_tests` mapped onto vulnerability classes SENTINEL actually knows how to
test for (see docs/architecture.md §13), rather than letting the model invent
categories downstream code doesn't understand.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ParameterSemantic(str, Enum):
    """Likely role of a parameter — see docs/architecture.md §12. Classification is
    informational and does NOT imply a vulnerability."""

    IDENTIFIER = "identifier"
    SEARCH = "search"
    FILTER = "filter"
    REDIRECT = "redirect"
    URL = "url"
    FILE = "file"
    PATH = "path"
    FILENAME = "filename"
    TEMPLATE = "template"
    COMMAND = "command"
    QUERY = "query"
    ROLE = "role"
    PERMISSION = "permission"
    PRICE = "price"
    QUANTITY = "quantity"
    TOKEN = "token"
    CALLBACK = "callback"
    UNKNOWN = "unknown"


class RecommendedTest(str, Enum):
    """Vulnerability classes the deterministic engines (Phase 6+) know how to test
    for. The AI recommends from this fixed vocabulary; it cannot invent new test
    types the orchestrator wouldn't recognize."""

    BOLA = "bola"
    IDOR = "idor"
    AUTHORIZATION = "authorization"
    SSRF = "ssrf"
    XXE = "xxe"
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    PATH_TRAVERSAL = "path_traversal"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    CORS = "cors"
    JWT = "jwt"
    COMMAND_INJECTION = "command_injection"
    INFORMATION_EXPOSURE = "information_exposure"
    NONE = "none"


class EndpointClassification(BaseModel):
    """One endpoint/parameter classification + test recommendation.

    Mirrors the example in docs/architecture.md §7 exactly (endpoint, parameter,
    classification, risk_score, recommended_tests, reason).
    """

    endpoint: str
    parameter: str | None = None
    classification: ParameterSemantic
    risk_score: int = Field(ge=0, le=10)
    recommended_tests: list[RecommendedTest] = Field(default_factory=list)
    reason: str
