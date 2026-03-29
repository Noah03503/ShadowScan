"""
ShadowScan — XSS Detection Module
Author  : Noah Mordan
License : MIT

Tests common XSS payloads against URL parameters.
Detects reflected XSS by checking if the payload appears in the response body.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "';alert('XSS');//",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
]


def scan_xss(url: str) -> list:
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        results.append({
            "module": "XSS",
            "severity": "Info",
            "title": "No URL parameters found",
            "description": "The target URL has no GET parameters to test for XSS injection.",
            "evidence": None,
            "recommendation": "Test forms or POST endpoints manually.",
        })
        return results

    for param_name in params:
        for payload in PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = requests.get(test_url, timeout=8, verify=False)
                if payload in response.text:
                    results.append({
                        "module": "XSS",
                        "severity": "High",
                        "title": f"Reflected XSS detected in parameter '{param_name}'",
                        "description": (
                            f"The payload was reflected unescaped in the server response "
                            f"for the parameter '{param_name}'. An attacker could inject "
                            f"malicious scripts executed in the victim's browser."
                        ),
                        "evidence": f"Payload: {payload}  |  URL: {test_url}",
                        "recommendation": (
                            "Encode all user-supplied input before rendering it in HTML. "
                            "Use a Content-Security-Policy header to limit script execution."
                        ),
                    })
                    break
            except requests.RequestException:
                pass

    if not results:
        results.append({
            "module": "XSS",
            "severity": "Info",
            "title": "No reflected XSS detected",
            "description": "None of the tested payloads were reflected in the server response.",
            "evidence": None,
            "recommendation": "Continue testing POST parameters and JavaScript-based sinks.",
        })

    return results
