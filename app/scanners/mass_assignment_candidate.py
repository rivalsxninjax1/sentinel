"""Mass assignment candidate check: submits a form's normal fields plus one extra,
privilege-escalation-shaped field (`role=admin`) that was never part of the
discovered form, and checks whether the response reflects that field back verbatim
— suggestive of a server that binds arbitrary request fields onto an internal
object (classic mass assignment / over-posting).

This is a CANDIDATE signal, not proof: reflection of the submitted field doesn't
confirm it was persisted or that it grants any actual privilege — only that the
server processed and echoed an unexpected field rather than rejecting/ignoring it.
Confirming real impact would require an authenticated follow-up request checking
whether the change actually took effect, which SENTINEL does not attempt (this
scanner sends one write, observes the immediate response, and stops — repeating a
mutating request to verify persistence is exactly the kind of "automated
destructive/exploitative" action outside this project's scope).

Requires ACTIVE mode: this is a real POST/PUT to a state-changing endpoint.
"""

from __future__ import annotations

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_INJECTED_FIELD_NAME = "role"
_INJECTED_FIELD_VALUE = "admin"


class MassAssignmentCandidateScanner(DeterministicScanner):
    name = "mass_assignment_candidate"
    vulnerability_class = "mass_assignment"
    required_mode = "active"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if target.method.upper() not in ("POST", "PUT", "PATCH"):
            return []
        if target.form_fields is None:
            return []

        existing_names = {f.get("name", "") for f in target.form_fields}
        if _INJECTED_FIELD_NAME in existing_names:
            return []  # already a legitimate field on this form; not a useful test

        payload = {f.get("name", f"field{i}"): "sentinel_test_value" for i, f in enumerate(target.form_fields)}
        payload[_INJECTED_FIELD_NAME] = _INJECTED_FIELD_VALUE

        try:
            response = await http_client.request(target.method, target.url, data=payload)
        except (httpx.HTTPError, ScopeViolation):
            return []

        if response.status_code >= 400:
            return []

        if f'"{_INJECTED_FIELD_NAME}"' in response.text and _INJECTED_FIELD_VALUE in response.text:
            return [
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=None,
                    title=(
                        f"Unexpected field '{_INJECTED_FIELD_NAME}={_INJECTED_FIELD_VALUE}' "
                        f"accepted and reflected (possible mass assignment)"
                    ),
                    severity="medium",
                    matched_endpoint=target.url,
                    raw_output=f"submitted {_INJECTED_FIELD_NAME}={_INJECTED_FIELD_VALUE}, "
                    f"response echoed it back",
                    metadata={
                        "vulnerability_class": self.vulnerability_class,
                        "confidence": "low",
                        "injected_field": _INJECTED_FIELD_NAME,
                        "note": "reflection does not confirm persistence or actual privilege "
                        "change — manual follow-up verification required",
                    },
                )
            ]

        return []
