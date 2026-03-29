# ShadowScan

**Web Vulnerability Scanner — by Noah Mordan**

ShadowScan is an open-source web vulnerability scanner with a local dark-mode dashboard. It detects common security flaws in web applications and generates a detailed security report with a global score.

Built for educational purposes and authorized penetration testing only.

---

## Features

- XSS (Cross-Site Scripting) detection
- SQL Injection detection
- Missing HTTP security headers analysis
- Open Redirect detection
- SSRF (Server-Side Request Forgery) detection
- Directory Traversal detection
- Clickjacking detection
- Sensitive file and information exposure detection
- Global security score (0 to 100)
- Local web dashboard with real-time results
- JSON report export

---

## Requirements

- Python 3.9 or higher
- pip

---

## Installation

```bash
git clone https://github.com/Noah03503/ShadowScan.git
cd ShadowScan
pip install -r requirements.txt
```

---

## Usage

```bash
python app.py
```

Then open your browser at:

```
http://localhost:5000
```

Enter the target URL, select the modules you want to run, and launch the scan.

---

## Project Structure

```
ShadowScan/
├── app.py                  # Flask entry point
├── requirements.txt
├── LICENSE
├── README.md
├── .gitignore
├── src/
│   ├── scanner/
│   │   ├── xss.py          # XSS detection module
│   │   ├── sqli.py         # SQL Injection detection module
│   │   ├── headers.py      # HTTP headers analysis module
│   │   ├── redirect.py     # Open Redirect detection module
│   │   ├── ssrf.py         # SSRF detection module
│   │   ├── traversal.py    # Directory Traversal detection module
│   │   ├── clickjacking.py # Clickjacking detection module
│   │   └── exposure.py     # Sensitive exposure detection module
│   ├── utils/
│   │   ├── requester.py    # HTTP request handler
│   │   ├── reporter.py     # Report generation
│   │   └── scorer.py       # Security score calculator
│   └── ui/
│       ├── index.html      # Dashboard
│       ├── style.css       # Dashboard styles
│       └── app.js          # Dashboard logic
└── docs/
    └── modules.md          # Detailed module documentation
```

---

## Disclaimer

ShadowScan is intended for educational purposes and authorized security testing only.
Do not use this tool against any system without explicit written permission from the owner.
The author, Noah Mordan, takes no responsibility for any misuse of this software.

---

## License

MIT License — Copyright (c) 2026 Noah Mordan

See [LICENSE](./LICENSE) for full details.

---

## Author

**Noah Mordan**
GitHub: [github.com/NoahMordan](https://github.com/Noah03503)
