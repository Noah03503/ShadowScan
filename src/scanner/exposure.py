"""
ShadowScan — Sensitive Information Exposure Module
Author  : Noah Mordan
License : MIT

Probes for commonly exposed sensitive files, backup files, and
configuration endpoints that should not be publicly accessible.
"""

import requests
from urllib.parse import urlparse

SENSITIVE_PATHS = [
    ".env",
    ".env.local",
    ".env.backup",
    ".git/config",
    ".git/HEAD",
    ".htaccess",
    ".htpasswd",
    "config.php",
    "config.yml",
    "config.yaml",
    "database.yml",
    "wp-config.php",
    "settings.py",
    "local_settings.py",
    "web.config",
    "phpinfo.php",
    "info.php",
    "robots.txt",
    "sitemap.xml",
    "backup.zip",
    "backup.tar.gz",
    "dump.sql",
    "db.sql",
    "admin/",
    "administrator/",
    "phpmyadmin/",
    "server-status",
    "server-info",
    "actuator",
    "actuator/env",
    "actuator/health",
    "swagger-ui.html",
    "api/swagger.json",
    "api/openapi.json",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
]

SENSITIVE_CONTENT_INDICATORS = {
    ".env": ["APP_KEY", "DB_PASSWORD", "SECRET_KEY", "API_KEY"],
    ".git/config": ["[core]", "[remote", "repositoryformatversion"],
    "phpinfo.php": ["PHP Version", "phpinfo()"],
    "info.php": ["PHP Version", "phpinfo()"],
    "wp-config.php": ["DB_NAME", "DB_USER", "DB_PASSWORD"],
    "config.php": ["define(", "password", "host"],
    "dump.sql": ["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
    "db.sql": ["INSERT INTO", "CREATE TABLE"],
    "actuator/env": ["profiles", "propertySources"],
}


def scan_exposure(url: str) -> list:
    results = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    for path in SENSITIVE_PATHS:
        target = f"{base_url}/{path}"
        try:
            response = requests.get(target, timeout=6, verify=False)

            if response.status_code in (200, 206):
                severity = "High"
                found_indicators = []

                for key, indicators in SENSITIVE_CONTENT_INDICATORS.items():
                    if key in path:
                        for indicator in indicators:
                            if indicator in response.text:
                                found_indicators.append(indicator)
                                severity = "Critical"

                title = f"Sensitive file accessible: /{path}"
                description = (
                    f"The file '/{path}' returned HTTP {response.status_code} and appears to be "
                    f"publicly accessible. This file may expose credentials, configuration data, "
                    f"or internal application details."
                )

                evidence = f"URL: {target}  |  HTTP Status: {response.status_code}"
                if found_indicators:
                    evidence += f"  |  Sensitive content detected: {', '.join(found_indicators)}"

                results.append({
                    "module": "Sensitive Exposure",
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "evidence": evidence,
                    "recommendation": (
                        f"Restrict access to '/{path}' via server configuration. "
                        "Remove sensitive files from public directories. "
                        "Ensure .git, .env, and configuration files are excluded from the web root."
                    ),
                })

        except requests.RequestException:
            pass

    if not results:
        results.append({
            "module": "Sensitive Exposure",
            "severity": "Info",
            "title": "No sensitive files exposed",
            "description": "None of the probed sensitive paths returned an accessible response.",
            "evidence": None,
            "recommendation": "Regularly audit publicly accessible files and directories.",
        })

    return results
