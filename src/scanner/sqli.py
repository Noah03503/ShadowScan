"""
ShadowScan — SQL Injection Detection Module
Author  : Noah Mordan
License : MIT

Tests common SQLi payloads against URL parameters.
Detects errors leaked by the database in the server response.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1 AND 1=1",
    "1 AND 1=2",
    "'; DROP TABLE users;--",
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "sqlite3::exception",
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
    "ora-",
    "db2 sql error",
    "syntax error",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
]


def scan_sqli(url: str) -> list:
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        results.append({
            "module": "SQL Injection",
            "severity": "Info",
            "title": "No URL parameters found",
            "description": "The target URL has no GET parameters to test for SQL injection.",
            "evidence": None,
            "recommendation": "Test POST forms and API endpoints manually.",
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
                body_lower = response.text.lower()

                for signature in SQL_ERROR_SIGNATURES:
                    if signature in body_lower:
                        results.append({
                            "module": "SQL Injection",
                            "severity": "Critical",
                            "title": f"SQL Injection detected in parameter '{param_name}'",
                            "description": (
                                f"A database error was triggered by injecting a payload into "
                                f"the parameter '{param_name}'. This indicates the input is "
                                f"passed unsanitized to a SQL query."
                            ),
                            "evidence": (
                                f"Payload: {payload}  |  "
                                f"Error signature found: '{signature}'  |  "
                                f"URL: {test_url}"
                            ),
                            "recommendation": (
                                "Use parameterized queries or prepared statements. "
                                "Never concatenate user input directly into SQL queries. "
                                "Disable verbose database error messages in production."
                            ),
                        })
                        break
            except requests.RequestException:
                pass

    if not results:
        results.append({
            "module": "SQL Injection",
            "severity": "Info",
            "title": "No SQL Injection detected",
            "description": "No database error signatures were triggered by the tested payloads.",
            "evidence": None,
            "recommendation": "Consider blind SQLi testing with time-based or boolean-based payloads.",
        })

    return results
