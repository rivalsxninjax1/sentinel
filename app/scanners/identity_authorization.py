"""IdentityAuthorizationScanner — real cross-identity authorization testing, per
docs/architecture.md §25:

    USER_A → object A → allowed
    USER_B → object A → denied   (normal)
    USER_B → object A → allowed  (anomaly! flag it)

Requires at least two configured `AuthenticationContext` identities
(app/core/auth_context.py, `target.auth_contexts`). Without them, this scanner
degrades to returning no findings — the same graceful-fallback pattern used
throughout SENTINEL (Phase 4's LLM fallback, Phase 3's Playwright fallback) rather
than erroring. Phase 7's `idor_candidate` (name-heuristic only) remains registered
and still runs regardless — this scanner is additive, not a replacement, since it
only activates when identities are actually configured.

HONEST LIMITATION: SENTINEL does not know which identity "owns" the object at the
tested URL. What this scanner actually detects is narrower but still meaningful:
whether multiple *distinct* authenticated identities receive indistinguishable
access to the exact same URL. If every configured identity gets 200 with a similar
response body, that's suggestive of missing per-object authorization — but it is
NOT proof that any specific identity was accessing another's data, since we don't
have ground-truth object ownership. Confidence is capped at "low" for exactly this
reason. Treat every finding here as "investigate this endpoint's authorization
logic," not "confirmed IDOR."

Requires ACTIVE mode — this sends authenticated requests as multiple distinct
identities to a specific object URL, which is more than a passive/safe check.
"""

from __future__ import annotations

import difflib

import httpx

from app.core.auth_context import MissingCredentialError
from app.core.http_client import SentinelHTTPClient
from app.core.logging import get_logger
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

logger = get_logger(__name__)

_SIMILARITY_THRESHOLD = 0.85


def _bodies_are_similar(bodies: list[str]) -> bool:
    if len(bodies) < 2:
        return False
    ratios = []
    for i in range(len(bodies)):
        for j in range(i + 1, len(bodies)):
            ratios.append(difflib.SequenceMatcher(None, bodies[i], bodies[j]).ratio())
    return all(r >= _SIMILARITY_THRESHOLD for r in ratios)


class IdentityAuthorizationScanner(DeterministicScanner):
    name = "identity_authorization"
    vulnerability_class = "idor_bola"
    required_mode = "active"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if not target.parameter_name:
            return []
        if not target.auth_contexts or len(target.auth_contexts) < 2:
            return []  # need >= 2 identities to compare; nothing to do otherwise

        responses: dict[str, httpx.Response] = {}

        try:
            responses["anonymous"] = await http_client.get(target.url)
        except (httpx.HTTPError, ScopeViolation):
            pass

        for ctx in target.auth_contexts:
            try:
                kwargs = ctx.apply({})
            except MissingCredentialError as exc:
                logger.info("auth_context_credential_missing", label=ctx.label, error=str(exc))
                continue
            try:
                responses[ctx.label] = await http_client.get(target.url, **kwargs)
            except (httpx.HTTPError, ScopeViolation):
                continue

        authed_labels = [ctx.label for ctx in target.auth_contexts if ctx.label in responses]
        if len(authed_labels) < 2:
            return []  # couldn't get at least 2 authenticated responses to compare

        status_codes = {label: responses[label].status_code for label in authed_labels}
        if not all(code == 200 for code in status_codes.values()):
            return []  # at least one identity was denied — no anomaly to flag

        bodies = [responses[label].text for label in authed_labels]
        if not _bodies_are_similar(bodies):
            return []  # responses differ enough that this isn't the same object/view

        anon_status = responses["anonymous"].status_code if "anonymous" in responses else None
        anon_denied = anon_status in (401, 403) if anon_status is not None else None

        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title=(
                    f"No authorization differentiation observed across "
                    f"{len(authed_labels)} identities for parameter '{target.parameter_name}'"
                ),
                severity="medium",
                matched_endpoint=target.url,
                raw_output=(
                    f"identities {authed_labels} all received 200 with similar response "
                    f"bodies"
                    + (
                        f"; anonymous access was {'denied' if anon_denied else 'also allowed'}"
                        if anon_denied is not None
                        else "; anonymous baseline not available"
                    )
                ),
                metadata={
                    "parameter": target.parameter_name,
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "low",
                    "identities_tested": authed_labels,
                    "anonymous_denied": anon_denied,
                    "caveat": (
                        "does not confirm which identity legitimately owns the requested "
                        "object — only that multiple distinct identities received "
                        "indistinguishable access to the same URL"
                    ),
                },
            )
        ]
