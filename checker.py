import argparse
import re
import sys
from urllib.parse import urlparse, unquote

try:
    import requests
except ImportError:
    print("Error: requests library required. Run: pip install requests")
    sys.exit(1)


# High-risk TLDs often used in phishing (free or suspicious)
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
    ".link", ".stream", ".download", ".win", ".racing", ".loan", ".gq",
    ".cf", ".ga", ".ml", ".tk", ".cc", ".buzz", ".rest", ".party", ".review",
    ".accountant", ".date", ".download", ".faith", ".men", ".mobile",
}

# URL shorteners (can hide final destination)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "short.io", "cutt.ly", "rebrand.ly", "bl.ink",
}

# Common brand names phishers impersonate
BRAND_NAMES = {
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "bank",
    "chase", "wellsfargo", "boa", "citibank", "dropbox", "linkedin",
    "facebook", "instagram", "twitter", "whatsapp", "dhl", "fedex", "ups",
    "irs", "hmrc", "office365", "outlook", "icloud", "adobe", "spotify",
}

# Suspicious keywords often in phishing paths
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "account", "verify", "secure", "update", "confirm",
    "validation", "authenticate", "password", "reset", "unusual", "suspended",
    "locked", "urgent", "action-required", "billing", "payment", "refund",
]


def is_ip_address(hostname: str) -> bool:
    """Check if hostname is an IP address (phishers sometimes use direct IPs)."""
    ipv4 = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ipv4, hostname):
        return True
    if "[" in hostname and "]" in hostname:  # IPv6
        return True
    return False


def check_url(url: str, follow_redirects: bool = True) -> list:
    """Run all phishing checks on the URL."""
    results = []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    full_url = url
    unquoted_domain = unquote(domain)

    # 1. IP address check
    if is_ip_address(domain.split(":")[0]):
        results.append({
            "check": "IP Address in URL",
            "status": "RISK",
            "score": 30,
            "detail": "URL uses IP instead of domain name - common in phishing",
        })
    else:
        results.append({
            "check": "IP Address in URL",
            "status": "OK",
            "score": 0,
            "detail": "URL uses a domain name",
        })

    # 2. Suspicious TLD
    tld = "." + ".".join(domain.split(".")[-2:]) if "." in domain else ""
    if any(domain.endswith(t) for t in SUSPICIOUS_TLDS):
        results.append({
            "check": "Suspicious TLD",
            "status": "RISK",
            "score": 25,
            "detail": f"TLD often used in phishing campaigns",
        })
    else:
        results.append({
            "check": "Suspicious TLD",
            "status": "OK",
            "score": 0,
            "detail": "Domain uses common TLD",
        })

    # 3. URL shortener
    base_domain = domain.replace("www.", "").split("/")[0]
    if any(short in base_domain for short in SHORTENER_DOMAINS):
        results.append({
            "check": "URL Shortener",
            "status": "WARN",
            "score": 15,
            "detail": "Shortened URL - final destination may be hidden",
        })
    else:
        results.append({
            "check": "URL Shortener",
            "status": "OK",
            "score": 0,
            "detail": "Not a known URL shortener",
        })

    # 4. URL length
    if len(full_url) > 150:
        results.append({
            "check": "Long URL",
            "status": "RISK",
            "score": 20,
            "detail": f"URL is {len(full_url)} chars - phishers often use long URLs",
        })
    else:
        results.append({
            "check": "Long URL",
            "status": "OK",
            "score": 0,
            "detail": f"URL length: {len(full_url)} chars",
        })

    # 5. Subdomain depth
    parts = domain.replace("www.", "").split(".")
    subdomain_count = max(0, len(parts) - 2)
    if subdomain_count > 3:
        results.append({
            "check": "Deep Subdomains",
            "status": "RISK",
            "score": 20,
            "detail": f"{subdomain_count} subdomains - can mimic legitimate sites",
        })
    else:
        results.append({
            "check": "Deep Subdomains",
            "status": "OK",
            "score": 0,
            "detail": f"Subdomain depth: {subdomain_count}",
        })

    # 6. Hyphen count (typosquatting)
    domain_only = parts[0] if parts else ""
    hyphen_count = domain_only.count("-")
    if hyphen_count >= 2:
        results.append({
            "check": "Hyphen Heavy",
            "status": "RISK",
            "score": 25,
            "detail": f"{hyphen_count} hyphens - e.g. secure-paypal-login.com",
        })
    else:
        results.append({
            "check": "Hyphen Heavy",
            "status": "OK",
            "score": 0,
            "detail": "Normal domain structure",
        })

    # 7. Brand name + suspicious context (exclude legitimate brand domains)
    parts_no_www = domain.replace("www.", "").split(".")
    domain_name = parts_no_www[-2] if len(parts_no_www) >= 2 else ""
    domain_name_clean = re.sub(r"[^a-z0-9]", "", domain_name)
    flagged_brand = None
    for brand in BRAND_NAMES:
        if brand in domain_name_clean:
            # Legitimate: domain IS the brand (e.g. google.com, paypal.com)
            if domain_name_clean == brand:
                break
            # Suspicious: domain contains brand but is not the brand itself
            flagged_brand = brand
            break
    if flagged_brand:
        results.append({
            "check": "Brand Imitation",
            "status": "RISK",
            "score": 35,
            "detail": f'Domain may imitate "{flagged_brand}" - verify carefully',
        })
    else:
        results.append({
            "check": "Brand Imitation",
            "status": "OK",
            "score": 0,
            "detail": "No obvious brand impersonation",
        })

    # 8. Suspicious keywords in path
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path]
    if found_keywords:
        results.append({
            "check": "Suspicious Path",
            "status": "WARN",
            "score": 15,
            "detail": f"Path contains: {', '.join(found_keywords[:3])}",
        })
    else:
        results.append({
            "check": "Suspicious Path",
            "status": "OK",
            "score": 0,
            "detail": "No high-risk keywords in path",
        })

    # 9. HTTPS
    if parsed.scheme == "http":
        results.append({
            "check": "HTTPS",
            "status": "WARN",
            "score": 20,
            "detail": "Not using HTTPS - credentials could be exposed",
        })
    else:
        results.append({
            "check": "HTTPS",
            "status": "OK",
            "score": 0,
            "detail": "URL uses HTTPS",
        })

    # 10. Unicode/homograph check
    if any(ord(c) > 127 for c in unquoted_domain):
        results.append({
            "check": "Unicode Characters",
            "status": "RISK",
            "score": 40,
            "detail": "Unicode in domain - potential homograph attack",
        })
    else:
        results.append({
            "check": "Unicode Characters",
            "status": "OK",
            "score": 0,
            "detail": "No suspicious Unicode",
        })

    return results


def calculate_risk(results: list) -> tuple[int, str]:
    """Calculate total risk score (0-100) and verdict."""
    total = sum(r["score"] for r in results)
    total = min(100, total)

    if total >= 70:
        verdict = "HIGH RISK"
    elif total >= 40:
        verdict = "MEDIUM RISK"
    elif total >= 20:
        verdict = "LOW RISK"
    else:
        verdict = "LIKELY SAFE"

    return total, verdict


def print_report(url: str, results: list, verbose: bool = False):
    """Print formatted phishing analysis report."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    score, verdict = calculate_risk(results)

    print("\n" + "=" * 60)
    print("[*] PHISHGUARD - Phishing URL Analysis Report")
    print("=" * 60)
    print(f"\n[*] URL: {url}")
    print(f"\n[*] RISK SCORE: {score}/100")
    print(f"[*] VERDICT: {verdict}")
    print("-" * 60)

    risk_count = sum(1 for r in results if r["status"] == "RISK")
    warn_count = sum(1 for r in results if r["status"] == "WARN")
    ok_count = sum(1 for r in results if r["status"] == "OK")

    print(f"\nSummary: {risk_count} risk(s) | {warn_count} warning(s) | {ok_count} OK")
    print("-" * 60)

    for r in results:
        icon = "[!]" if r["status"] == "RISK" else "[~]" if r["status"] == "WARN" else "[+]"
        print(f"\n{icon} {r['check']}: [{r['status']}]")
        print(f"   {r['detail']}")

    print("\n" + "=" * 60)
    print("NOTE: This tool uses heuristics only. Always verify URLs manually.")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard - Analyze URLs for phishing indicators"
    )
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()
    results = check_url(args.url)
    print_report(args.url, results, args.verbose)


if __name__ == "__main__":
    main()
