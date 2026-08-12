#!/usr/bin/env python3
"""
Phishing URL Detector
URL analysis and risk scoring engine.

This module analyzes URLs using static characteristics only.
It does NOT connect to or visit the target URL.
"""

from urllib.parse import urlparse
import ipaddress
import re


# Suspicious words frequently found in phishing URLs
SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "password",
    "credential",
    "authenticate",
    "banking",
    "wallet",
    "payment",
    "recover",
    "unlock",
}


def is_ip_address(hostname):
    """Check whether the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url):
    """
    Analyze a URL and calculate a phishing risk score.

    Returns:
        dict: Analysis results containing score, risk level,
              indicators, and parsed URL information.
    """

    indicators = []
    score = 0

    # ---------------------------------------------------------
    # Basic URL parsing
    # ---------------------------------------------------------
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # ---------------------------------------------------------
    # 1. Protocol check
    # ---------------------------------------------------------
    if parsed.scheme.lower() == "http":
        score += 15
        indicators.append("URL uses HTTP instead of HTTPS")

    elif parsed.scheme.lower() != "https":
        score += 10
        indicators.append("URL does not use HTTPS")

    # ---------------------------------------------------------
    # 2. IP address instead of domain
    # ---------------------------------------------------------
    if is_ip_address(hostname):
        score += 25
        indicators.append("Hostname is an IP address")

    # ---------------------------------------------------------
    # 3. URL length
    # ---------------------------------------------------------
    if len(url) > 100:
        score += 10
        indicators.append("Very long URL")

    if len(url) > 200:
        score += 10
        indicators.append("Extremely long URL")

    # ---------------------------------------------------------
    # 4. Suspicious @ character
    # ---------------------------------------------------------
    if "@" in url:
        score += 20
        indicators.append("URL contains '@' character")

    # ---------------------------------------------------------
    # 5. Excessive subdomains
    # ---------------------------------------------------------
    if hostname:
        subdomain_parts = hostname.split(".")

        if len(subdomain_parts) >= 4:
            score += 15
            indicators.append("Excessive number of subdomains")

    # ---------------------------------------------------------
    # 6. Suspicious number of hyphens
    # ---------------------------------------------------------
    if hostname.count("-") >= 3:
        score += 10
        indicators.append("Domain contains many hyphens")

    # ---------------------------------------------------------
    # 7. Suspicious keywords
    # ---------------------------------------------------------
    url_lower = url.lower()

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:
        # Cap keyword contribution so a long URL
        # does not automatically become high risk.
        keyword_score = min(len(found_keywords) * 5, 20)
        score += keyword_score

        indicators.append(
            "Suspicious keywords: " + ", ".join(sorted(found_keywords))
        )

    # ---------------------------------------------------------
    # 8. Excessive special characters
    # ---------------------------------------------------------
    special_characters = re.findall(r"[^a-zA-Z0-9./:_?=&%-]", url)

    if len(special_characters) >= 3:
        score += 10
        indicators.append("Many unusual special characters")

    # ---------------------------------------------------------
    # 9. Excessive URL encoding
    # ---------------------------------------------------------
    encoded_parts = re.findall(r"%[0-9a-fA-F]{2}", url)

    if len(encoded_parts) >= 5:
        score += 10
        indicators.append("Excessive URL encoding")

    # ---------------------------------------------------------
    # 10. Suspicious query parameters
    # ---------------------------------------------------------
    if query:
        parameters = query.split("&")

        if len(parameters) >= 6:
            score += 10
            indicators.append("Large number of query parameters")

    # ---------------------------------------------------------
    # 11. Domain looks suspicious
    # ---------------------------------------------------------
    if hostname:
        # Detect long domain labels
        labels = hostname.split(".")

        if any(len(label) > 30 for label in labels):
            score += 10
            indicators.append("Very long domain label")

    # ---------------------------------------------------------
    # Limit score to 100
    # ---------------------------------------------------------
    score = min(score, 100)

    # ---------------------------------------------------------
    # Risk classification
    # ---------------------------------------------------------
    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "url": url,
        "score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "protocol": parsed.scheme,
        "hostname": hostname,
        "port": parsed.port,
        "path": path,
        "query": query,
    }


if __name__ == "__main__":
    # Simple standalone test
    test_url = "http://secure-login-example.com/verify/account"

    result = analyze_url(test_url)

    print(f"URL: {result['url']}")
    print(f"Risk Score: {result['score']}/100")
    print(f"Risk Level: {result['risk_level']}")

    print("\nIndicators:")

    if result["indicators"]:
        for indicator in result["indicators"]:
            print(f"[!] {indicator}")
    else:
        print("[+] No suspicious indicators detected")
