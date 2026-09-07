"""Static knowledge base mapping SENTINEL's internal `vulnerability_class` strings
to a CWE identifier, generic impact statement, and generic remediation guidance.

These are intentionally GENERIC — the actual impact and correct remediation always
depend on the specific application, and this knowledge base does not know anything
about the target beyond its vulnerability class. Every renderer presents this text
as general guidance, not a substitute for the specific `description`/`evidence`
already captured per finding. CWE mappings follow the commonly-accepted primary
mapping for each class; some classes (e.g. JWT weaknesses) span more than one CWE
depending on which specific weakness fired — the mapping picks the most
representative one and notes the nuance in the entry itself where it matters.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnowledgeBaseEntry:
    cwe_id: str
    cwe_name: str
    impact: str
    remediation: str


_KNOWLEDGE_BASE: dict[str, KnowledgeBaseEntry] = {
    "security_headers": KnowledgeBaseEntry(
        cwe_id="CWE-693",
        cwe_name="Protection Mechanism Failure",
        impact="Missing security headers reduce defense-in-depth against clickjacking, "
        "MIME-sniffing, and content-injection attacks; impact depends on which header "
        "is missing and what else the application does to compensate.",
        remediation="Set Content-Security-Policy, X-Frame-Options, "
        "X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy "
        "appropriately for the application; avoid disclosing server/framework "
        "versions in Server/X-Powered-By headers.",
    ),
    "information_exposure": KnowledgeBaseEntry(
        cwe_id="CWE-200",
        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
        impact="Exposed configuration, backup, or version-control files can leak "
        "credentials, source code, or internal architecture details useful for "
        "further attacks.",
        remediation="Remove sensitive files from the web root, block access via "
        "server configuration, and exclude them from deployment artifacts entirely.",
    ),
    "open_redirect": KnowledgeBaseEntry(
        cwe_id="CWE-601",
        cwe_name="URL Redirection to Untrusted Site ('Open Redirect')",
        impact="Can be used in phishing campaigns — a link to the trusted domain "
        "silently redirects victims to an attacker-controlled site.",
        remediation="Validate redirect targets against an allow-list of known-safe "
        "paths/domains rather than redirecting to any user-supplied URL.",
    ),
    "xss": KnowledgeBaseEntry(
        cwe_id="CWE-79",
        cwe_name="Improper Neutralization of Input During Web Page Generation "
        "('Cross-site Scripting')",
        impact="Allows execution of attacker-controlled script in victims' browsers "
        "in the application's origin — session theft, credential harvesting, or "
        "unauthorized actions performed as the victim.",
        remediation="Context-appropriate output encoding (HTML/attribute/JS/URL) "
        "for all user-controlled data, plus a Content-Security-Policy as "
        "defense-in-depth.",
    ),
    "path_traversal": KnowledgeBaseEntry(
        cwe_id="CWE-22",
        cwe_name="Improper Limitation of a Pathname to a Restricted Directory "
        "('Path Traversal')",
        impact="Allows reading files outside the intended directory, potentially "
        "exposing source code, configuration, or credentials.",
        remediation="Resolve and canonicalize file paths server-side, reject paths "
        "containing traversal sequences, and restrict file access to an explicit "
        "allow-list or a chroot/sandboxed directory.",
    ),
    "sqli": KnowledgeBaseEntry(
        cwe_id="CWE-89",
        cwe_name="Improper Neutralization of Special Elements used in an SQL "
        "Command ('SQL Injection')",
        impact="Can allow reading, modifying, or deleting arbitrary database "
        "content, and in some configurations further compromise of the host.",
        remediation="Use parameterized queries/prepared statements exclusively — "
        "never build SQL via string concatenation with user input.",
    ),
    "ssrf": KnowledgeBaseEntry(
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery (SSRF)",
        impact="Can allow reaching internal-only services (cloud metadata "
        "endpoints, internal APIs, admin panels) that aren't otherwise "
        "network-reachable from outside.",
        remediation="Validate and restrict outbound requests to an allow-list of "
        "expected destinations; block requests to link-local/internal address "
        "ranges by default.",
    ),
    "ssti": KnowledgeBaseEntry(
        cwe_id="CWE-1336",
        cwe_name="Improper Neutralization of Special Elements Used in a Template "
        "Engine",
        impact="Successful exploitation frequently leads to full remote code "
        "execution on the server, not just template evaluation.",
        remediation="Never render user input as a template string; use the "
        "template engine's sandboxed/logic-less mode if user content must appear "
        "in output, or escape it as plain data instead.",
    ),
    "idor_bola": KnowledgeBaseEntry(
        cwe_id="CWE-639",
        cwe_name="Authorization Bypass Through User-Controlled Key",
        impact="Allows accessing or modifying another user's data by changing an "
        "object identifier, without any authorization check tying the object to "
        "the requesting identity.",
        remediation="Enforce object-level authorization on every request: verify "
        "the authenticated identity actually owns/has rights to the specific "
        "object being accessed, not just that they're authenticated at all.",
    ),
    "cors": KnowledgeBaseEntry(
        cwe_id="CWE-942",
        cwe_name="Permissive Cross-domain Policy with Untrusted Domains",
        impact="Combined with credentialed requests, allows an attacker-controlled "
        "page to make authenticated cross-origin requests on a victim's behalf.",
        remediation="Reflect only an explicit allow-list of trusted origins in "
        "Access-Control-Allow-Origin; never combine a wildcard or reflected-origin "
        "policy with Access-Control-Allow-Credentials: true.",
    ),
    "jwt": KnowledgeBaseEntry(
        cwe_id="CWE-347",
        cwe_name="Improper Verification of Cryptographic Signature",
        impact="An `alg: none` or weak-secret token means an attacker can forge "
        "arbitrary valid-looking tokens, impersonating any user. (Note: `alg: "
        "none` specifically also maps to CWE-345, Insufficient Verification of "
        "Data Authenticity — both apply depending on which specific weakness "
        "fired.)",
        remediation="Reject tokens with alg=none server-side, use a strong "
        "randomly-generated signing secret (or asymmetric keys), and set a short "
        "expiration on every issued token.",
    ),
    "csrf": KnowledgeBaseEntry(
        cwe_id="CWE-352",
        cwe_name="Cross-Site Request Forgery (CSRF)",
        impact="Allows tricking an authenticated victim's browser into submitting "
        "a state-changing request without their knowledge or consent.",
        remediation="Use anti-CSRF tokens tied to the user's session for every "
        "state-changing form, and set cookies with SameSite=Lax or Strict.",
    ),
    "unsafe_file_upload": KnowledgeBaseEntry(
        cwe_id="CWE-434",
        cwe_name="Unrestricted Upload of File with Dangerous Type",
        impact="If an uploaded file can be both stored and later executed by the "
        "server, this leads directly to remote code execution.",
        remediation="Validate file type by content (not just extension/declared "
        "MIME type), store uploads outside the web root or in object storage with "
        "no execute permission, and serve them with a content-disposition that "
        "prevents inline execution.",
    ),
    "xxe": KnowledgeBaseEntry(
        cwe_id="CWE-611",
        cwe_name="Improper Restriction of XML External Entity Reference",
        impact="Can allow reading local files, server-side request forgery, or "
        "denial of service via the XML parser.",
        remediation="Disable external entity resolution and DTD processing in the "
        "XML parser configuration — this is a parser-level setting, not something "
        "fixable by input validation alone.",
    ),
    "mass_assignment": KnowledgeBaseEntry(
        cwe_id="CWE-915",
        cwe_name="Improperly Controlled Modification of Dynamically-Determined "
        "Object Attributes",
        impact="Allows setting fields the client shouldn't control (e.g. a role or "
        "privilege flag) by including them in a request the server binds "
        "directly onto an internal object.",
        remediation="Use an explicit allow-list of bindable fields per endpoint "
        "(or a dedicated DTO/serializer) rather than binding the full request body "
        "onto a model.",
    ),
    "graphql_introspection": KnowledgeBaseEntry(
        cwe_id="CWE-200",
        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
        impact="Exposes the complete schema (every type, field, query, and "
        "mutation) to any caller, aiding further attacks even though it isn't a "
        "vulnerability by itself in every application.",
        remediation="Disable introspection in production unless there's a "
        "specific reason to keep it enabled (e.g. a public API explicitly "
        "designed for third-party exploration).",
    ),
    "websocket_authorization": KnowledgeBaseEntry(
        cwe_id="CWE-306",
        cwe_name="Missing Authentication for Critical Function",
        impact="An unauthenticated WebSocket endpoint may expose real-time data "
        "or actions that should require authentication — impact depends entirely "
        "on what the endpoint actually does.",
        remediation="Require authentication at the WebSocket handshake (e.g. via "
        "a signed token in the connection URL or an auth cookie) if the endpoint "
        "isn't intentionally public.",
    ),
    "http_method_enumeration": KnowledgeBaseEntry(
        cwe_id="CWE-650",
        cwe_name="Trusting HTTP Permission Methods on the Server Side",
        impact="Declaring PUT/DELETE/PATCH as allowed doesn't by itself confirm "
        "they're exploitable, but often indicates the endpoint wasn't designed "
        "with per-method authorization in mind.",
        remediation="Explicitly restrict allowed methods per route at the "
        "framework/routing layer, and apply the same authorization checks "
        "regardless of which method reaches a given handler.",
    ),
}


def get_knowledge(vulnerability_class: str) -> KnowledgeBaseEntry | None:
    return _KNOWLEDGE_BASE.get(vulnerability_class)


def known_vulnerability_classes() -> set[str]:
    return set(_KNOWLEDGE_BASE.keys())
