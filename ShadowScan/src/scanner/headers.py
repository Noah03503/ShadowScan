"""
ShadowScan — HTTP Security Headers Analysis Module
Author  : Noah Mordan
License : MIT

Checks for the presence and correctness of critical HTTP security headers.
"""

import requests

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": (
            "Content-Security-Policy (CSP) is missing. This header controls which resources "
            "the browser is allowed to load, and is a critical defense against XSS attacks."
        ),
        "recommendation": (
            "Define a strict CSP policy. At minimum: "
            "Content-Security-Policy: default-src 'self'"
        ),
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": (
            "X-Frame-Options is missing. Without this header, the page can be embedded "
            "in an iframe by an attacker, enabling Clickjacking attacks."
        ),
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN.",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": (
            "X-Content-Type-Options is missing. Browsers may MIME-sniff responses, "
            "potentially executing malicious content as a different content type."
        ),
        "recommendation": "Set X-Content-Type-Options: nosniff.",
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": (
            "Strict-Transport-Security (HSTS) is missing. Without it, the browser may "
            "fall back to HTTP, exposing the connection to man-in-the-middle attacks."
        ),
        "recommendation": (
            "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": (
            "Referrer-Policy is missing. Sensitive URL information may be leaked "
            "to third parties through the Referer header."
        ),
        "recommendation": "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": (
            "Permissions-Policy is missing. This header allows you to control which browser "
            "features and APIs can be used (camera, microphone, geolocation, etc.)."
        ),
        "recommendation": (
            "Define a Permissions-Policy that disables unused browser features. "
            "Example: Permissions-Policy: geolocation=(), camera=(), microphone=()"
        ),
    },
}


def scan_headers(url: str) -> list:
    results = []

    try:
        response = requests.get(url, timeout=8, verify=False)
        headers = {k.lower(): v for k, v in response.headers.items()}

        server = response.headers.get("Server")
        if server:
            results.append({
                "module": "HTTP Headers",
                "severity": "Low",
                "title": "Server version disclosed in headers",
                "description": (
                    f"The 'Server' header exposes the web server software and possibly its version. "
                    f"This information helps attackers identify known vulnerabilities."
                ),
                "evidence": f"Server: {server}",
                "recommendation": "Remove or anonymize the Server header in your web server configuration.",
            })

        x_powered = response.headers.get("X-Powered-By")
        if x_powered:
            results.append({
                "module": "HTTP Headers",
                "severity": "Low",
                "title": "Technology disclosed via X-Powered-By header",
                "description": (
                    f"The 'X-Powered-By' header reveals the backend technology stack, "
                    f"aiding attackers in targeting known vulnerabilities."
                ),
                "evidence": f"X-Powered-By: {x_powered}",
                "recommendation": "Disable the X-Powered-By header in your framework or server configuration.",
            })

        for header_name, meta in REQUIRED_HEADERS.items():
            if header_name.lower() not in headers:
                results.append({
                    "module": "HTTP Headers",
                    "severity": meta["severity"],
                    "title": f"Missing security header: {header_name}",
                    "description": meta["description"],
                    "evidence": f"Header '{header_name}' not found in server response.",
                    "recommendation": meta["recommendation"],
                })

        if not results:
            results.append({
                "module": "HTTP Headers",
                "severity": "Info",
                "title": "All security headers are present",
                "description": "The server response includes all recommended HTTP security headers.",
                "evidence": None,
                "recommendation": "Review each header value to ensure configurations are strict and correct.",
            })

    except requests.RequestException as e:
        results.append({
            "module": "HTTP Headers",
            "severity": "Info",
            "title": "Request failed",
            "description": f"Could not reach the target URL to analyze headers.",
            "evidence": str(e),
            "recommendation": "Verify the URL is accessible and try again.",
        })

    return results
