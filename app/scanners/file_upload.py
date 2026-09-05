"""Unsafe file upload heuristic.

Only triggers on forms that look like an upload form (action path or a field name
containing "upload"/"file"/"attachment") — this is not a generic multipart-POST
fuzzer. Uploads a small, completely benign text file (plain marker content, never
executable code of any kind — see docs/architecture.md's non-negotiable rule against
destructive/exploitative testing) with a double-extension filename
(`sentinel_test.jpg.php`) designed only to reveal whether the server's extension
validation is naive (checks for an image extension anywhere in the name rather than
the true extension).

If the upload succeeds and the response contains a path/URL to the uploaded file,
this scanner attempts one GET to fetch it back and checks whether the response
Content-Type suggests the server would execute it rather than serve it as a static
download. It never uploads anything capable of doing something if executed — the
"proof" is purely in Content-Type/extension handling, not actual code execution.

Requires ACTIVE mode: this uploads a real file to the target and requires cleanup
the operator should be aware isn't automated (see Known limitations in the
changelog).
"""

from __future__ import annotations

import re

import httpx

from app.core.http_client import SentinelHTTPClient
from app.scanners.base import DeterministicScanner, ScanTarget
from app.scope.engine import ScopeViolation
from app.tools.models import NormalizedFinding

_UPLOAD_HINT_PATTERN = re.compile(r"upload|attachment|import", re.IGNORECASE)
_BENIGN_CONTENT = b"SENTINEL_UPLOAD_TEST_MARKER - benign test file, safe to delete"
_TEST_FILENAME = "sentinel_test.jpg.php"
_EXECUTABLE_CONTENT_TYPES = ("text/html", "application/x-httpd-php", "application/x-php")


class FileUploadScanner(DeterministicScanner):
    name = "file_upload"
    vulnerability_class = "unsafe_file_upload"
    required_mode = "active"

    async def scan(
        self, target: ScanTarget, http_client: SentinelHTTPClient
    ) -> list[NormalizedFinding]:
        if target.method.upper() not in ("POST", "PUT"):
            return []
        if target.form_fields is None:
            return []

        looks_like_upload = _UPLOAD_HINT_PATTERN.search(target.url) is not None or any(
            _UPLOAD_HINT_PATTERN.search(f.get("name", "")) for f in target.form_fields
        )
        if not looks_like_upload:
            return []

        file_field_name = next(
            (f.get("name") for f in target.form_fields if "file" in f.get("name", "").lower()),
            "file",
        )

        try:
            response = await http_client.post(
                target.url,
                files={file_field_name: (_TEST_FILENAME, _BENIGN_CONTENT, "image/jpeg")},
            )
        except (httpx.HTTPError, ScopeViolation):
            return []

        if response.status_code >= 400:
            return []

        # Look for a path/URL to the uploaded file anywhere in the response.
        match = re.search(r'["\']?([^\s"\']*sentinel_test\.jpg\.php)["\']?', response.text)
        if not match:
            return [
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=None,
                    title="Upload with double extension (.jpg.php) accepted (status "
                    f"{response.status_code}); uploaded file location not confirmed",
                    severity="info",
                    matched_endpoint=target.url,
                    raw_output=f"status={response.status_code}, upload accepted, no reference to filename found",
                    metadata={
                        "vulnerability_class": self.vulnerability_class,
                        "confidence": "low",
                        "test_filename": _TEST_FILENAME,
                    },
                )
            ]

        uploaded_path = match.group(1)
        fetch_url = uploaded_path if uploaded_path.startswith("http") else _join(target.url, uploaded_path)

        try:
            fetch_response = await http_client.get(fetch_url)
        except (httpx.HTTPError, ScopeViolation):
            return [
                NormalizedFinding(
                    tool_name=self.name,
                    tool_version=None,
                    title="Upload with double extension (.jpg.php) accepted and referenced by path",
                    severity="medium",
                    matched_endpoint=fetch_url,
                    raw_output=f"upload accepted, could not fetch back to confirm content-type handling",
                    metadata={"vulnerability_class": self.vulnerability_class, "confidence": "low"},
                )
            ]

        content_type = fetch_response.headers.get("content-type", "").lower()
        if any(exec_type in content_type for exec_type in _EXECUTABLE_CONTENT_TYPES):
            severity = "critical"
            title = (
                "Uploaded file with double extension (.jpg.php) served with an "
                f"executable Content-Type ({content_type}) — likely unrestricted file upload"
            )
        else:
            severity = "low"
            title = (
                "Uploaded file with double extension (.jpg.php) accepted and served "
                f"back as {content_type or 'unknown content-type'} (does not appear executable)"
            )

        return [
            NormalizedFinding(
                tool_name=self.name,
                tool_version=None,
                title=title,
                severity=severity,
                matched_endpoint=fetch_url,
                raw_output=f"fetched back with Content-Type: {content_type}",
                metadata={
                    "vulnerability_class": self.vulnerability_class,
                    "confidence": "low",
                    "content_type": content_type,
                    "cleanup_required": "this test file was NOT automatically deleted from the target",
                },
            )
        ]


def _join(base_url: str, path: str) -> str:
    parsed = httpx.URL(base_url)
    if path.startswith("/"):
        return f"{parsed.scheme}://{parsed.host}{path}"
    return f"{parsed.scheme}://{parsed.host}/{path}"
