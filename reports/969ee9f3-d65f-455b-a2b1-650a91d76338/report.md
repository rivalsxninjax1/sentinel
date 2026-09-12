# SENTINEL Security Report — quick-scan-sabin-sharma.com.np

- **Scan ID:** 969ee9f3-d65f-455b-a2b1-650a91d76338
- **Scan mode:** active
- **Generated:** 2026-09-12T15:56:21.311535+00:00

## Summary

| Disposition | Count |
|---|---|
| Likely | 5 |
| Requires Manual Verification | 1 |

| Severity | Count |
|---|---|
| medium | 2 |
| low | 2 |
| info | 2 |

## Likely (5)

### Missing security header: Content-Security-Policy

- **Vulnerability class:** security_headers
- **Severity:** medium
- **Confidence:** high
- **Verification status:** verified
- **Endpoint:** `https://sabin-sharma.com.np/`
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
- **Endpoint:** `https://sabin-sharma.com.np/`
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
- **Endpoint:** `https://sabin-sharma.com.np/`
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
- **Endpoint:** `https://sabin-sharma.com.np/`
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
- **Endpoint:** `https://sabin-sharma.com.np/`
- **CWE:** CWE-693 — Protection Mechanism Failure

**Description:** server: Netlify

**Impact:** Missing security headers reduce defense-in-depth against clickjacking, MIME-sniffing, and content-injection attacks; impact depends on which header is missing and what else the application does to compensate.

**Remediation:** Set Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy appropriately for the application; avoid disclosing server/framework versions in Server/X-Powered-By headers.

**Evidence:**
```
server: Netlify
```

## Requires Manual Verification (1)

### POST form has no anti-CSRF token field

- **Vulnerability class:** csrf
- **Severity:** medium
- **Confidence:** low
- **Verification status:** needs_manual_review
- **Endpoint:** `https://sabin-sharma.com.np/submit`
- **CWE:** CWE-352 — Cross-Site Request Forgery (CSRF)
- **Approximate CVSS (severity-based estimate):** 5.4

**Description:** form fields: ['access_key', 'subject', 'from_name', 'name', 'email', 'subject', 'message']

**Impact:** Allows tricking an authenticated victim's browser into submitting a state-changing request without their knowledge or consent.

**Remediation:** Use anti-CSRF tokens tied to the user's session for every state-changing form, and set cookies with SameSite=Lax or Strict.

**Evidence:**
```
form fields: ['access_key', 'subject', 'from_name', 'name', 'email', 'subject', 'message']
```
