"""Registry of every deterministic scanner SENTINEL ships. Mirrors app/tools/registry.py's
extensibility contract: add a new scanner file, add it to `build_default_scanners()`,
nothing else changes.
"""

from __future__ import annotations

from app.scanners.base import DeterministicScanner
from app.scanners.information_exposure import InformationExposureScanner
from app.scanners.open_redirect import OpenRedirectScanner
from app.scanners.path_traversal import PathTraversalScanner
from app.scanners.reflected_xss import ReflectedXSSScanner
from app.scanners.security_headers import SecurityHeadersScanner
from app.scanners.sqli_error_based import SqliErrorBasedScanner


def build_default_scanners() -> list[DeterministicScanner]:
    return [
        SecurityHeadersScanner(),
        InformationExposureScanner(),
        OpenRedirectScanner(),
        ReflectedXSSScanner(),
        PathTraversalScanner(),
        SqliErrorBasedScanner(),
    ]
