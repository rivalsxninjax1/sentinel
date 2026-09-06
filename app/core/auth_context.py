"""AuthenticationContext — a named identity SENTINEL can attach to a request.

Per docs/architecture.md §26: credentials are NEVER stored in source, config files,
or the database — only an environment-variable NAME is configured; the actual
secret value is resolved from the environment at request time. The redaction
processor in app/core/logging.py catches common credential-shaped keys as a second
layer of defense, but the primary control is: the secret value itself never enters
config objects, the database, or a Finding record — only the env var *name* does.

This is what makes real cross-identity IDOR/BOLA testing (docs/architecture.md §25)
possible: `IdentityAuthorizationScanner` (Phase 8) needs at least two distinct
identities to compare access with. Without any configured, it — like Phase 7's
`idor_candidate` — degrades to "no comparison possible," never an error.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class MissingCredentialError(Exception):
    """Raised when an AuthenticationContext's configured environment variable
    isn't set. Callers should treat this identity as unavailable, not fatal."""


@dataclass(frozen=True)
class AuthContextConfig:
    label: str
    kind: str  # "header" | "cookie"
    name: str  # header name or cookie name
    env_var: str  # environment variable holding the credential value (never the value itself)


@dataclass(frozen=True)
class AuthenticationContext:
    label: str
    kind: str
    name: str
    env_var: str

    def resolve_value(self) -> str:
        value = os.environ.get(self.env_var)
        if not value:
            raise MissingCredentialError(
                f"Environment variable {self.env_var!r} is not set for auth context {self.label!r}"
            )
        return value

    def apply(self, request_kwargs: dict) -> dict:
        """Returns a new kwargs dict with this identity's credential attached,
        suitable for passing to SentinelHTTPClient.get/post/request. Raises
        MissingCredentialError if the environment variable isn't set — callers
        should catch this and skip the identity, not abort the whole scan."""
        value = self.resolve_value()
        updated = dict(request_kwargs)
        if self.kind == "header":
            headers = dict(updated.get("headers") or {})
            headers[self.name] = value
            updated["headers"] = headers
        elif self.kind == "cookie":
            cookies = dict(updated.get("cookies") or {})
            cookies[self.name] = value
            updated["cookies"] = cookies
        else:
            raise ValueError(f"Unknown auth context kind: {self.kind!r}")
        return updated


def build_contexts(configs: list[AuthContextConfig]) -> list[AuthenticationContext]:
    return [AuthenticationContext(c.label, c.kind, c.name, c.env_var) for c in configs]
