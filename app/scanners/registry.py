"""Registry of every deterministic scanner SENTINEL ships. Mirrors app/tools/registry.py's
extensibility contract: add a new scanner file, add it to `build_default_scanners()`,
nothing else changes.
"""

from __future__ import annotations

from app.scanners.base import DeterministicScanner
from app.scanners.cors import CORSScanner
from app.scanners.csrf import CSRFScanner
from app.scanners.file_upload import FileUploadScanner
from app.scanners.graphql_introspection import GraphQLIntrospectionScanner
from app.scanners.http_method_enum import HTTPMethodEnumScanner
from app.scanners.identity_authorization import IdentityAuthorizationScanner
from app.scanners.idor_candidate import IDORCandidateScanner
from app.scanners.information_exposure import InformationExposureScanner
from app.scanners.jwt_weakness import JWTWeaknessScanner
from app.scanners.mass_assignment_candidate import MassAssignmentCandidateScanner
from app.scanners.open_redirect import OpenRedirectScanner
from app.scanners.path_traversal import PathTraversalScanner
from app.scanners.reflected_xss import ReflectedXSSScanner
from app.scanners.security_headers import SecurityHeadersScanner
from app.scanners.sqli_error_based import SqliErrorBasedScanner
from app.scanners.ssrf import SSRFScanner
from app.scanners.ssti import SSTIScanner
from app.scanners.websocket_auth import WebSocketAuthScanner
from app.scanners.xxe import XXEScanner


def build_default_scanners() -> list[DeterministicScanner]:
    return [
        # host-level
        SecurityHeadersScanner(),
        InformationExposureScanner(),
        CORSScanner(),
        JWTWeaknessScanner(),
        # parameter-level
        OpenRedirectScanner(),
        ReflectedXSSScanner(),
        PathTraversalScanner(),
        SqliErrorBasedScanner(),
        SSRFScanner(),
        SSTIScanner(),
        IDORCandidateScanner(),
        IdentityAuthorizationScanner(),
        # form-level
        CSRFScanner(),
        FileUploadScanner(),
        XXEScanner(),
        MassAssignmentCandidateScanner(),
        # endpoint-level (Phase 8)
        GraphQLIntrospectionScanner(),
        WebSocketAuthScanner(),
        HTTPMethodEnumScanner(),
    ]
