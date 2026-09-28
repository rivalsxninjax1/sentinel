# SENTINEL Security Report — quick-scan-emis.cehrd.gov.np

- **Scan ID:** 865025e3-d2a1-4304-a045-f9dea35c7da1
- **Scan mode:** active
- **Generated:** 2026-09-13T15:18:59.589988+00:00

## Summary

| Disposition | Count |
|---|---|
| Likely | 4 |
| Potential | 9 |

| Severity | Count |
|---|---|
| medium | 10 |
| low | 1 |
| info | 2 |

## Likely (4)

### Missing security header: Content-Security-Policy

- **Vulnerability class:** security_headers
- **Severity:** medium
- **Confidence:** high
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/`
- **CWE:** CWE-693 — Protection Mechanism Failure
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200

**Impact:** Missing security headers reduce defense-in-depth against clickjacking, MIME-sniffing, and content-injection attacks; impact depends on which header is missing and what else the application does to compensate.

**Remediation:** Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy appropriately for the application; avoid disclosing server/framework versions in Server/X-Powered-By headers.

**Evidence:**
```
status=200
```

### Missing security header: Referrer-Policy

- **Vulnerability class:** security_headers
- **Severity:** info
- **Confidence:** high
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/`
- **CWE:** CWE-693 — Protection Mechanism Failure

**Description:** status=200

**Impact:** Missing security headers reduce defense-in-depth against clickjacking, MIME-sniffing, and content-injection attacks; impact depends on which header is missing and what else the application does to compensate.

**Remediation:** Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy appropriately for the application; avoid disclosing server/framework versions in Server/X-Powered-By headers.

**Evidence:**
```
status=200
```

### 'server' header discloses: Microsoft-IIS/10.0

- **Vulnerability class:** security_headers
- **Severity:** info
- **Confidence:** high
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/`
- **CWE:** CWE-693 — Protection Mechanism Failure

**Description:** server: Microsoft-IIS/10.0

**Impact:** Missing security headers reduce defense-in-depth against clickjacking, MIME-sniffing, and content-injection attacks; impact depends on which header is missing and what else the application does to compensate.

**Remediation:** Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy appropriately for the application; avoid disclosing server/framework versions in Server/X-Powered-By headers.

**Evidence:**
```
server: Microsoft-IIS/10.0
```

### Endpoint declares potentially sensitive HTTP methods: TRACE

- **Vulnerability class:** http_method_enumeration
- **Severity:** low
- **Confidence:** high
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/`
- **CWE:** CWE-650 — Trusting HTTP Permission Methods on the Server Side
- **Approximate CVSS (severity-based estimate):** 3.1

**Description:** Allow: OPTIONS, TRACE, GET, HEAD, POST

**Impact:** Declaring PUT/DELETE/PATCH as allowed doesn't by itself confirm they're exploitable, but often indicates the endpoint wasn't designed with per-method authorization in mind.

**Remediation:** Explicitly restrict allowed methods per route at the framework/routing layer, and apply the same authorization checks regardless of which method reaches a given handler.

**Evidence:**
```
Allow: OPTIONS, TRACE, GET, HEAD, POST
```

## Potential (9)

### Potentially exposed sensitive file: /.git/HEAD

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/.git/HEAD`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=5973

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=5973
```

### Potentially exposed sensitive file: /.env

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/.env`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=5973

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=5973
```

### Potentially exposed sensitive file: /.DS_Store

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/.DS_Store`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=5973

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=5973
```

### Potentially exposed sensitive file: /backup.zip

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/backup.zip`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=5973

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=5973
```

### Potentially exposed sensitive file: /backup.sql

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/backup.sql`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=5973

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=5973
```

### Potentially exposed sensitive file: /wp-config.php.bak

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/wp-config.php.bak`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=5973

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=5973
```

### Potentially exposed sensitive file: /config.php.bak

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/config.php.bak`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=5973

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=5973
```

### Potentially exposed sensitive file: /.svn/entries

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/.svn/entries`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=5973

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=5973
```

### Potentially exposed sensitive file: /web.config.bak

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://emis.cehrd.gov.np/web.config.bak`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=5973

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=5973
```
