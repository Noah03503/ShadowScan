"""
ShadowScan — Security Score Calculator
Author  : Noah Mordan
License : MIT

Calculates a global security score (0 to 100) based on the findings.
Critical findings have the highest negative weight.
"""

SEVERITY_WEIGHTS = {
    "Critical": 25,
    "High":     15,
    "Medium":   8,
    "Low":      3,
    "Info":     0,
}


def calculate_score(results: list) -> int:
    score = 100

    for finding in results:
        severity = finding.get("severity", "Info")
        deduction = SEVERITY_WEIGHTS.get(severity, 0)
        score -= deduction

    return max(0, score)
