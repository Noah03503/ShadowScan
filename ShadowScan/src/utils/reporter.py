"""
ShadowScan — Report Generator
Author  : Noah Mordan
License : MIT

Structures the scan results into a clean report object
ready to be returned by the API and consumed by the dashboard.
"""

from datetime import datetime, timezone


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def generate_report(url: str, results: list, score: int) -> dict:
    sorted_results = sorted(
        results,
        key=lambda r: SEVERITY_ORDER.index(r.get("severity", "Info"))
        if r.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER)
    )

    counts = {s: 0 for s in SEVERITY_ORDER}
    for finding in results:
        severity = finding.get("severity", "Info")
        if severity in counts:
            counts[severity] += 1

    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return {
        "meta": {
            "tool": "ShadowScan",
            "version": "1.0.0",
            "author": "Noah Mordan",
            "target": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "score": score,
        "grade": grade,
        "summary": counts,
        "findings": sorted_results,
    }
