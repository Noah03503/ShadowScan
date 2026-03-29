"""
ShadowScan — Open Redirect Detection Module
Author  : Noah Mordan
License : MIT

Tests common redirect parameters for unvalidated external redirections.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "redirectUrl",
    "url", "next", "return", "returnTo", "return_url",
    "goto", "target", "dest", "destination", "continue",
    "forward", "location", "link", "out", "view",
]

TEST_EXTERNAL_URL = "https://evil.example.com"


def scan_redirect(url: str) -> list:
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    tested = False

    all_params_to_test = list(params.keys()) + [
        p for p in REDIRECT_PARAMS if p not in params
    ]

    for param_name in all_params_to_test:
        test_params = params.copy()
        test_params[param_name] = [TEST_EXTERNAL_URL]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            response = requests.get(
                test_url,
                timeout=8,
                verify=False,
                allow_redirects=True,
            )
            tested = True

            final_url = response.url
            if TEST_EXTERNAL_URL in final_url or "evil.example.com" in final_url:
                results.append({
                    "module": "Open Redirect",
                    "severity": "Medium",
                    "title": f"Open Redirect detected via parameter '{param_name}'",
                    "description": (
                        f"The parameter '{param_name}' redirected the browser to an external "
                        f"domain without validation. Attackers can craft phishing URLs that "
                        f"appear trusted but redirect victims to malicious sites."
                    ),
                    "evidence": f"Redirected to: {final_url}  |  Test URL: {test_url}",
                    "recommendation": (
                        "Validate redirect destinations against a whitelist of allowed URLs or domains. "
                        "Never redirect to arbitrary user-supplied URLs."
                    ),
                })
        except requests.RequestException:
            pass

    if not results:
        results.append({
            "module": "Open Redirect",
            "severity": "Info",
            "title": "No Open Redirect detected",
            "description": (
                "No unvalidated external redirect was triggered by the tested parameters."
                if tested else
                "No redirect parameters were found or reachable."
            ),
            "evidence": None,
            "recommendation": "Test POST-based redirects and JavaScript-based redirections manually.",
        })

    return results
