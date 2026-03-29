# ShadowScan — Module Documentation

Author: Noah Mordan  
License: MIT

---

## Module Overview

ShadowScan is organized into independent scanner modules. Each module targets a specific category of web vulnerability, returns a list of findings, and can be enabled or disabled individually from the dashboard.

---

## XSS — Cross-Site Scripting

**File:** `src/scanner/xss.py`

**What it does:**  
Injects a set of common XSS payloads into every GET parameter found in the target URL. After each injection, it checks whether the payload appears unescaped in the server response body, which indicates a reflected XSS vulnerability.

**Severity:** High

**Limitations:**  
Only tests reflected XSS via GET parameters. DOM-based and stored XSS require dynamic browser interaction and cannot be detected passively.

---

## SQL Injection

**File:** `src/scanner/sqli.py`

**What it does:**  
Injects classic SQL injection payloads into URL GET parameters and looks for known database error strings in the response. A match indicates that user input is being passed unsanitized into a SQL query.

**Severity:** Critical

**Limitations:**  
Only detects error-based SQLi. Blind time-based and boolean-based injections require more advanced techniques not covered in this version.

---

## HTTP Headers

**File:** `src/scanner/headers.py`

**What it does:**  
Performs a single GET request to the target and inspects the response headers. Checks for the presence of six critical security headers and flags any that are missing. Also checks for information disclosure via the `Server` and `X-Powered-By` headers.

**Headers checked:**
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- Referrer-Policy
- Permissions-Policy

**Severity:** Low to High depending on the missing header

---

## Open Redirect

**File:** `src/scanner/redirect.py`

**What it does:**  
Tests a list of commonly used redirect parameters by injecting an external URL (`https://evil.example.com`) and following redirects. If the final destination matches the injected URL, an open redirect is confirmed.

**Parameters tested:**  
`redirect`, `redirect_uri`, `url`, `next`, `return`, `goto`, `dest`, `target`, `forward`, `location`, and more.

**Severity:** Medium

**Limitations:**  
Only tests GET-based redirects. JavaScript-based or POST-based redirects are out of scope.

---

## SSRF — Server-Side Request Forgery

**File:** `src/scanner/ssrf.py`

**What it does:**  
Injects internal IP addresses and cloud metadata endpoints into URL parameters that appear to accept URLs. Checks the response body for indicators that suggest the server fetched and returned internal content.

**Payloads tested:**  
`127.0.0.1`, `localhost`, `0.0.0.0`, `169.254.169.254` (AWS metadata), RFC 1918 ranges, and encoded variants.

**Severity:** Critical

**Limitations:**  
Blind SSRF (where the response does not reflect fetched content) cannot be detected without an out-of-band callback mechanism.

---

## Directory Traversal

**File:** `src/scanner/traversal.py`

**What it does:**  
Injects path traversal sequences into parameters that are likely to reference file paths. Checks the response for content that would only appear if a system file was successfully read (e.g., `/etc/passwd` entries, Windows `win.ini` sections).

**Severity:** Critical

**Limitations:**  
Only detects traversal where file content is reflected in the response. Blind traversal (write-based or out-of-band) is not covered.

---

## Clickjacking

**File:** `src/scanner/clickjacking.py`

**What it does:**  
Checks whether the target page includes protections against being embedded in an iframe. Looks for `X-Frame-Options` and the `frame-ancestors` directive in the `Content-Security-Policy` header.

**Severity:** Medium

---

## Sensitive File Exposure

**File:** `src/scanner/exposure.py`

**What it does:**  
Probes a list of commonly exposed paths relative to the target domain root. If a path returns HTTP 200, the module flags it as a potential exposure. For paths with known sensitive content (`.env`, `.git/config`, etc.), it also scans the response body for specific indicators to elevate severity to Critical.

**Paths probed include:**  
`.env`, `.git/config`, `phpinfo.php`, `wp-config.php`, `backup.zip`, `dump.sql`, `actuator/env`, `swagger-ui.html`, and more.

**Severity:** High to Critical

---

## Score Calculation

The global security score starts at 100 and is decremented for each finding based on its severity:

| Severity | Deduction |
|----------|-----------|
| Critical | 25 points |
| High     | 15 points |
| Medium   |  8 points |
| Low      |  3 points |
| Info     |  0 points |

The score is clamped to a minimum of 0.

**Grade scale:**

| Score    | Grade |
|----------|-------|
| 85 - 100 | A     |
| 70 - 84  | B     |
| 50 - 69  | C     |
| 30 - 49  | D     |
| 0 - 29   | F     |
