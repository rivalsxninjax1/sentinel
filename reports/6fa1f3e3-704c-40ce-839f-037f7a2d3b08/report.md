# SENTINEL Security Report — quick-scan-nihareekacollege.edu.np

- **Scan ID:** 6fa1f3e3-704c-40ce-839f-037f7a2d3b08
- **Scan mode:** active
- **Generated:** 2026-09-13T01:51:10.884698+00:00

## Summary

| Disposition | Count |
|---|---|
| Likely | 5 |
| Potential | 9 |

| Severity | Count |
|---|---|
| medium | 10 |
| low | 2 |
| info | 2 |

## Likely (5)

### Missing security header: Content-Security-Policy

- **Vulnerability class:** security_headers
- **Severity:** medium
- **Confidence:** high
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/`
- **CWE:** CWE-693 — Protection Mechanism Failure
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200

**Impact:** Missing security headers reduce defense-in-depth against clickjacking, MIME-sniffing, and content-injection attacks; impact depends on which header is missing and what else the application does to compensate.

**Remediation:** Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy appropriately for the application; avoid disclosing server/framework versions in Server/X-Powered-By headers.

**Evidence:**
```
status=200
```

### Missing security header: X-Frame-Options

- **Vulnerability class:** security_headers
- **Severity:** low
- **Confidence:** high
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/`
- **CWE:** CWE-693 — Protection Mechanism Failure
- **Approximate CVSS (severity-based estimate):** 3.1

**Description:** status=200

**Impact:** Missing security headers reduce defense-in-depth against clickjacking, MIME-sniffing, and content-injection attacks; impact depends on which header is missing and what else the application does to compensate.

**Remediation:** Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy appropriately for the application; avoid disclosing server/framework versions in Server/X-Powered-By headers.

**Evidence:**
```
status=200
```

### Missing security header: X-Content-Type-Options

- **Vulnerability class:** security_headers
- **Severity:** low
- **Confidence:** high
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/`
- **CWE:** CWE-693 — Protection Mechanism Failure
- **Approximate CVSS (severity-based estimate):** 3.1

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
- **Endpoint:** `https://nihareekacollege.edu.np/`
- **CWE:** CWE-693 — Protection Mechanism Failure

**Description:** status=200

**Impact:** Missing security headers reduce defense-in-depth against clickjacking, MIME-sniffing, and content-injection attacks; impact depends on which header is missing and what else the application does to compensate.

**Remediation:** Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy appropriately for the application; avoid disclosing server/framework versions in Server/X-Powered-By headers.

**Evidence:**
```
status=200
```

### 'server' header discloses: Netlify

- **Vulnerability class:** security_headers
- **Severity:** info
- **Confidence:** high
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/`
- **CWE:** CWE-693 — Protection Mechanism Failure

**Description:** server: Netlify

**Impact:** Missing security headers reduce defense-in-depth against clickjacking, MIME-sniffing, and content-injection attacks; impact depends on which header is missing and what else the application does to compensate.

**Remediation:** Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy appropriately for the application; avoid disclosing server/framework versions in Server/X-Powered-By headers.

**Evidence:**
```
server: Netlify
```

## Potential (9)

### Potentially exposed sensitive file: /.git/HEAD

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/.git/HEAD`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=1180

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=1180
```

### Potentially exposed sensitive file: /.env

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/.env`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=1180

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=1180
```

### Potentially exposed sensitive file: /.DS_Store

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/.DS_Store`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=1180

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=1180
```

### Potentially exposed sensitive file: /backup.zip

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/backup.zip`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=1180

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=1180
```

### Potentially exposed sensitive file: /backup.sql

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/backup.sql`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=1180

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=1180
```

### Potentially exposed sensitive file: /wp-config.php.bak

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/wp-config.php.bak`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=1180

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=1180
```

### Potentially exposed sensitive file: /config.php.bak

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/config.php.bak`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=1180

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=1180
```

### Potentially exposed sensitive file: /.svn/entries

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/.svn/entries`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=1180

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=1180
```

### Potentially exposed sensitive file: /web.config.bak

- **Vulnerability class:** information_exposure
- **Severity:** medium
- **Confidence:** low
- **Verification status:** verified
- **Endpoint:** `https://nihareekacollege.edu.np/web.config.bak`
- **CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** status=200, length=1180

**Impact:** Exposed configuration, backup, or version-control files can leak credentials, source code, or internal architecture details useful for further attacks.

**Remediation:** Remove sensitive files from the web root, block access via server configuration, and exclude them from deployment artifacts entirely.

**Evidence:**
```
status=200, length=1180
```
