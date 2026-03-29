"""
ShadowScan — Clickjacking Detection Module
Author  : Noah Mordan
License : MIT

Checks whether the target page can be embedded in an iframe,
which would enable clickjacking attacks.
"""

import requests


def scan_clickjacking(url: str) -> list:
    results = []

    try:
        response = requests.get(url, timeout=8, verify=False)
        headers = {k.lower(): v for k, v in response.headers.items()}

        x_frame = headers.get("x-frame-options")
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not x_frame and not has_frame_ancestors:
            results.append({
                "module": "Clickjacking",
                "severity": "Medium",
                "title": "Page is vulnerable to Clickjacking",
                "description": (
                    "Neither the 'X-Frame-Options' header nor a 'frame-ancestors' directive in "
                    "Content-Security-Policy was found. This means the page can be embedded in "
                    "an iframe on any external website, enabling clickjacking attacks where a "
                    "victim is tricked into clicking invisible UI elements."
                ),
                "evidence": (
                    "X-Frame-Options: not set  |  "
                    "CSP frame-ancestors: not set"
                ),
                "recommendation": (
                    "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to prevent framing. "
                    "Alternatively, use 'Content-Security-Policy: frame-ancestors none' for finer control."
                ),
            })
        else:
            protection = x_frame if x_frame else f"CSP frame-ancestors: {csp}"
            results.append({
                "module": "Clickjacking",
                "severity": "Info",
                "title": "Clickjacking protection is in place",
                "description": "The server response includes framing protection headers.",
                "evidence": f"Protection detected: {protection}",
                "recommendation": "Verify the header value is set to DENY or a strict allowlist.",
            })

    except requests.RequestException as e:
        results.append({
            "module": "Clickjacking",
            "severity": "Info",
            "title": "Request failed",
            "description": "Could not reach the target URL to check clickjacking headers.",
            "evidence": str(e),
            "recommendation": "Verify the URL is accessible and try again.",
        })

    return results
