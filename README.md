# PhishGuard - Phishing URL Checker

A Python CLI tool that analyzes URLs for phishing indicators. Uses heuristic checks to assess risk and help you decide if a link is safe to click.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Blueprint](#blueprint)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Checks Performed](#checks-performed)
- [Example Output](#example-output)

---

## Overview

PhishGuard analyzes any URL and runs 10 heuristic checks to detect common phishing patterns. It outputs a risk score (0–100), a verdict, and a breakdown of each check. Useful for security audits, email analysis, and learning how phishers构造 suspicious links.

---

## Blueprint

This flowchart shows the full workflow from setup to output:

<img src= "https://imgur.com/LJSFDVI.png" width="90%" alt="Terminal view">

| Phase | Steps |
|-------|-------|
| **SETUP** | Install Python → Create project folder → Install dependencies (`pip install requests`) |
| **RUN** | Execute `python checker.py <URL>` |
| **TROUBLESHOOTING** | Verify URL format → Check URL is valid → Retry |
| **OUTPUT** | Phishing Risk Report with score, verdict, and per-check results |

---

## Features

- ✅ 10 phishing indicator checks
- ✅ Risk score (0–100) and verdict (HIGH/MEDIUM/LOW/SAFE)
- ✅ No external APIs — works offline
- ✅ Instant results — no network requests to target URL
- ✅ Detects: suspicious TLDs, brand imitation, URL shorteners, Unicode tricks, and more

---

## Installation

### Prerequisites

- **Python 3.8+**
- **pip** (Python package manager)

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/phish-guard.git
   cd phish-guard
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the checker**
   ```bash
   python checker.py https://example.com
   ```

---

## Usage

### Analyze a URL

```bash
python checker.py https://secure-paypal-login.com/account/verify
```

### URL without protocol (auto-adds https)

```bash
python checker.py bit.ly/3xYz123
```

### Verbose mode

```bash
python checker.py https://suspicious-site.xyz -v
```

### Help

```bash
python checker.py --help
```

---

## Checks Performed

| Check | What it detects |
|-------|-----------------|
| **IP Address** | URLs using raw IPs instead of domains |
| **Suspicious TLD** | High-risk TLDs (.tk, .xyz, .top, .ml, etc.) |
| **URL Shortener** | bit.ly, tinyurl.com, t.co, etc. |
| **Long URL** | URLs over 150 characters |
| **Deep Subdomains** | Many subdomains (e.g., a.b.c.d.e.fake-bank.com) |
| **Hyphen Heavy** | Multiple hyphens (secure-paypal-login.com) |
| **Brand Imitation** | Domains mimicking PayPal, Amazon, banks, etc. |
| **Suspicious Path** | Paths with login, verify, password, etc. |
| **HTTPS** | Whether the URL uses HTTPS |
| **Unicode Characters** | Homograph attacks (e.g., paypaΙ.com with Greek I) |

---

## Example Output

```
============================================================
[*] PHISHGUARD - Phishing URL Analysis Report
============================================================

[*] URL: https://secure-paypal-account.xyz/login/verify

[*] RISK SCORE: 85/100
[*] VERDICT: HIGH RISK
------------------------------------------------------------

Summary: 4 risk(s) | 2 warning(s) | 4 OK
------------------------------------------------------------

[!] Suspicious TLD: [RISK]
   TLD often used in phishing campaigns

[!] Hyphen Heavy: [RISK]
   3 hyphens - e.g. secure-paypal-login.com

[!] Brand Imitation: [RISK]
   Domain may imitate "paypal" - verify carefully

[!] Suspicious Path: [WARN]
   Path contains: login, verify

[+] HTTPS: [OK]
   URL uses HTTPS
...
============================================================
NOTE: This tool uses heuristics only. Always verify URLs manually.
============================================================
```

---

## Project Structure

```
phish-guard/
├── checker.py          # Main checker script
├── requirements.txt    # Python dependencies
├── blueprint.png       # Workflow flowchart
└── README.md           # This file
```

---
