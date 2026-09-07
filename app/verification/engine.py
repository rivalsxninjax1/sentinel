"""VerificationEngine — the boundary between "a scanner produced a candidate" and
"this candidate survived a differential/baseline check" (docs/architecture.md
§22-23).

For reflection/injection-based vulnerability classes (xss, ssti, sqli,
path_traversal, xxe, ssrf), the same signature the original scanner matched on is
re-checked against a BASELINE request — the same endpoint with the payload-bearing
parameter removed (or, for XXE, a plain GET instead of the XXE payload). If the
baseline response ALSO matches the signature, the original "finding" was really just
something the application always returns regardless of any payload — a false
positive, not a vulnerability. This is exactly the differential analysis described
in docs/architecture.md §23's example:

    Tool A says possible XSS
    Custom analyzer says input reflected
    Response analyzer says HTML encoded
    -> NOT CONFIRMED

For objective/factual vulnerability classes (a missing security header, an Allow
header's declared methods, a CORS reflection you can literally see in the response
you already have), there's no payload to differentially test against — the evidence
IS the observation. These are marked "verified" without a baseline check.

For everything else (IDOR candidates, mass assignment, file upload, JWT structural
findings, CSRF, GraphQL introspection, WebSocket auth), SENTINEL doesn't have an
automated way to confirm impact — these are marked "needs_manual_review", never
silently upgraded or downgraded.

HARD CAP, matching docs/architecture.md §22 ("only strong evidence should become a
confirmed vulnerability"): this engine NEVER sets confidence to "confirmed". The
maximum confidence any automated process in SENTINEL can assign is "high". Marking
something "confirmed" is reserved for an explicit human sign-off step that doesn't
exist in this codebase yet — SENTINEL will not claim more certainty than it has
actually earned.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.core.http_client import SentinelHTTPClient
from app.core.logging import get_logger
from app.scanners.util import strip_query_param
from app.scope.engine import ScopeViolation

logger = get_logger(__name__)

_CONFIDENCE_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "confirmed": 4}
_MAX_AUTOMATED_CONFIDENCE = "high"

# Objective/factual: the evidence IS the observation, no payload to differentially
# re-test against.
_OBJECTIVE_CLASSES = {
    "security_headers",
    "information_exposure",
    "cors",
    "http_method_enumeration",
}

# Everything else not in _BASELINE_CHECKS below falls back to "needs_manual_review"
# automatically — this set exists only for documentation/clarity, not logic.
_MANUAL_REVIEW_CLASSES = {
    "idor_bola",
    "mass_assignment",
    "unsafe_file_upload",
    "jwt",
    "websocket_authorization",
    "graphql_introspection",
    "csrf",
}


def _xss_baseline_matches(text: str) -> bool:
    from app.scanners.reflected_xss import _PAYLOAD

    return _PAYLOAD in text


def _ssti_baseline_matches(text: str) -> bool:
    from app.scanners.ssti import _EXPECTED_RESULT

    return _EXPECTED_RESULT in text


def _sqli_baseline_matches(text: str) -> bool:
    from app.scanners.sqli_error_based import _SQL_ERROR_SIGNATURES

    lowered = text.lower()
    return any(sig in lowered for sig in _SQL_ERROR_SIGNATURES)


def _traversal_baseline_matches(text: str) -> bool:
    from app.scanners.util import TRAVERSAL_INDICATORS

    lowered = text.lower()
    return any(indicator in lowered for indicator in TRAVERSAL_INDICATORS)


def _ssrf_baseline_matches(text: str) -> bool:
    from app.scanners.ssrf import _SSRF_PROBES

    lowered = text.lower()
    for _, signatures in _SSRF_PROBES:
        if any(sig.lower() in lowered for sig in signatures):
            return True
    return False


_BASELINE_CHECKS = {
    "xss": _xss_baseline_matches,
    "ssti": _ssti_baseline_matches,
    "sqli": _sqli_baseline_matches,
    "path_traversal": _traversal_baseline_matches,
    "xxe": _traversal_baseline_matches,
    "ssrf": _ssrf_baseline_matches,
}


@dataclass
class VerificationOutcome:
    verification_status: str  # "verified" | "false_positive" | "needs_manual_review"
    confidence: str


class VerificationEngine:
    def __init__(self, http_client: SentinelHTTPClient) -> None:
        self._http_client = http_client

    async def verify(
        self,
        vulnerability_class: str,
        matched_endpoint: str,
        current_confidence: str,
        metadata: dict,
    ) -> VerificationOutcome:
        if vulnerability_class in _OBJECTIVE_CLASSES:
            return VerificationOutcome("verified", current_confidence)

        checker = _BASELINE_CHECKS.get(vulnerability_class)
        if checker is None:
            return VerificationOutcome("needs_manual_review", current_confidence)

        baseline_url = self._build_baseline_url(vulnerability_class, matched_endpoint, metadata)
        try:
            response = await self._http_client.get(baseline_url)
        except (httpx.HTTPError, ScopeViolation) as exc:
            logger.info("baseline_fetch_failed", url=baseline_url, error=str(exc))
            return VerificationOutcome("needs_manual_review", current_confidence)

        if checker(response.text):
            # The signature is present even WITHOUT the payload — false positive.
            return VerificationOutcome("false_positive", current_confidence)

        return VerificationOutcome("verified", self._upgrade(current_confidence))

    @staticmethod
    def _build_baseline_url(vulnerability_class: str, matched_endpoint: str, metadata: dict) -> str:
        if vulnerability_class == "xxe":
            # XXE's payload is a raw POST body, not a query parameter — the stored
            # matched_endpoint is already the clean URL. Baseline is a plain GET to
            # the same URL (a different method than the original POST, but this
            # only needs to prove the traversal signature isn't just always
            # present on this endpoint regardless of any request).
            return matched_endpoint
        parameter = metadata.get("parameter")
        if not parameter:
            return matched_endpoint
        return strip_query_param(matched_endpoint, parameter)

    @staticmethod
    def _upgrade(confidence: str) -> str:
        current_rank = _CONFIDENCE_RANK.get(confidence, 0)
        target_rank = min(current_rank + 1, _CONFIDENCE_RANK[_MAX_AUTOMATED_CONFIDENCE])
        for label, rank in _CONFIDENCE_RANK.items():
            if rank == target_rank:
                return label
        return confidence
