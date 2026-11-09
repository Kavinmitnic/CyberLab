from urllib.parse import urlparse
import re
import ipaddress

def analyze_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if parsed.scheme != "https":
        score += 1
        reasons.append("HTTPS missing")

    if "@" in url:
        score += 2
        reasons.append("@ symbol detected")

    if len(url) > 100:
        score += 1
        reasons.append("Unusually long URL")

    if re.search(r"(login|verify|secure|account|update)", url, re.I):
        score += 1
        reasons.append("Sensitive keywords found")

    try:
        ipaddress.ip_address(host)
        score += 2
        reasons.append("IP address used as domain")
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        reasons.append("Punycode domain detected")

    print("\n--- URL SECURITY REPORT ---")
    print("URL:", url)
    print("Risk score:", score)

    if score >= 4:
        print("Assessment: Suspicious")
    elif score >= 2:
        print("Assessment: Needs review")
    else:
        print("Assessment: No obvious warning signs")

    for reason in reasons:
        print("-", reason)

while True:
    url = input("\nEnter URL (or exit): ").strip()

    if url.lower() == "exit":
        break

    if not url.startswith(("http://", "https://")):
        print("Please enter a complete URL.")
        continue

    analyze_url(url)

0

