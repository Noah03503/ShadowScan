"""
ShadowScan — HTTP Requester Utility
Author  : Noah Mordan
License : MIT

Centralized HTTP request handler with consistent headers,
timeout management, and SSL verification control.
"""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": (
        "ShadowScan/1.0 (Security Scanner — authorized testing only) "
        "by Noah Mordan"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

DEFAULT_TIMEOUT = 8


def get(url: str, params: dict = None, headers: dict = None, allow_redirects: bool = True) -> requests.Response:
    merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
    return requests.get(
        url,
        params=params,
        headers=merged_headers,
        timeout=DEFAULT_TIMEOUT,
        verify=False,
        allow_redirects=allow_redirects,
    )


def post(url: str, data: dict = None, json: dict = None, headers: dict = None) -> requests.Response:
    merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
    return requests.post(
        url,
        data=data,
        json=json,
        headers=merged_headers,
        timeout=DEFAULT_TIMEOUT,
        verify=False,
    )
