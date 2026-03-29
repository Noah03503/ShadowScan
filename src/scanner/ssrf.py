"""
ShadowScan — SSRF Detection Module
Author  : Noah Mordan
License : MIT

Tests URL parameters for Server-Side Request Forgery by injecting
internal/loopback addresses and checking for unexpected responses.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://192.168.0.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://0x7f000001",
    "http://2130706433",
]

URL_PARAMS = [
    "url", "uri", "src", "source", "dest", "destination",
    "redirect", "link", "href", "path", "load", "file",
    "fetch", "request", "image", "img", "data",
]

INTERNAL_INDICATORS = [
    "root:", "daemon:", "/bin/bash",
    "ami-id", "instance-id", "local-hostname",
    "metadata", "internal server error",
    "connection refused", "network is unreachable",
]


def scan_ssrf(url: str) -> list:
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    all_params_to_test = list(params.keys()) + [
        p for p in URL_PARAMS if p not in params
    ]

    for param_name in all_params_to_test:
        for payload in SSRF_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = requests.get(test_url, timeout=6, verify=False)
                body_lower = response.text.lower()

                for indicator in INTERNAL_INDICATORS:
                    if indicator in body_lower:
                        results.append({
                            "module": "SSRF",
                            "severity": "Critical",
                            "title": f"SSRF detected via parameter '{param_name}'",
                            "description": (
                                f"The server appears to have fetched an internal resource when "
                                f"the parameter '{param_name}' was set to '{payload}'. "
                                f"SSRF can expose internal infrastructure, cloud metadata, "
                                f"and sensitive configuration data."
                            ),
                            "evidence": (
                                f"Payload: {payload}  |  "
                                f"Indicator found: '{indicator}'  |  "
                                f"URL: {test_url}"
                            ),
                            "recommendation": (
                                "Validate and whitelist all URLs before the server fetches them. "
                                "Block requests to private IP ranges (RFC 1918) and loopback addresses. "
                                "Use a dedicated egress proxy with strict allowlists."
                            ),
                        })
                        break
            except requests.RequestException:
                pass

    if not results:
        results.append({
            "module": "SSRF",
            "severity": "Info",
            "title": "No SSRF detected",
            "description": "No internal resource indicators were found in server responses.",
            "evidence": None,
            "recommendation": "Test POST parameters and API endpoints that accept URLs manually.",
        })

    return results
