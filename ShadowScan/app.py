"""
ShadowScan - Web Vulnerability Scanner
Author  : Noah Mordan
License : MIT
"""

from flask import Flask, render_template, request, jsonify
from src.scanner.xss import scan_xss
from src.scanner.sqli import scan_sqli
from src.scanner.headers import scan_headers
from src.scanner.redirect import scan_redirect
from src.scanner.ssrf import scan_ssrf
from src.scanner.traversal import scan_traversal
from src.scanner.clickjacking import scan_clickjacking
from src.scanner.exposure import scan_exposure
from src.utils.scorer import calculate_score
from src.utils.reporter import generate_report

app = Flask(
    __name__,
    template_folder="src/ui",
    static_folder="src/ui",
    static_url_path="",
)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target_url = data.get("url", "").strip()
    modules = data.get("modules", [])

    if not target_url:
        return jsonify({"error": "No URL provided."}), 400

    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    results = []

    module_map = {
        "xss":          scan_xss,
        "sqli":         scan_sqli,
        "headers":      scan_headers,
        "redirect":     scan_redirect,
        "ssrf":         scan_ssrf,
        "traversal":    scan_traversal,
        "clickjacking": scan_clickjacking,
        "exposure":     scan_exposure,
    }

    for module_name in modules:
        scanner_fn = module_map.get(module_name)
        if scanner_fn:
            module_results = scanner_fn(target_url)
            results.extend(module_results)

    score = calculate_score(results)
    report = generate_report(target_url, results, score)

    return jsonify(report)


if __name__ == "__main__":
    print("ShadowScan running at http://localhost:5000")
    app.run(debug=True, port=5000)
