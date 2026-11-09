
from urllib.parse import urlsplit
import ipaddress

def analyze_url(url):
    score = 0
    warnings = []

    try:
        parsed = urlsplit(url)
        host = parsed.hostname

        if parsed.scheme not in ("http", "https") or not host:
            print("Invalid URL")
            return

        host = host.lower()

        if parsed.scheme != "https":
            score += 1
            warnings.append("HTTPS missing")

        if "@" in url:
            score += 2
            warnings.append("At symbol detected")

        try:
            ipaddress.ip_address(host)
            score += 2
            warnings.append("IP address hostname")
        except ValueError:
            pass

        if "xn--" in host:
            score += 2
            warnings.append("Punycode hostname")

        if len(url) > 100:
            score += 1
            warnings.append("Long URL")

        keywords = [
            "login", "verify", "password",
            "account", "signin", "wallet"
        ]

        if any(word in url.lower() for word in keywords):
            score += 1
            warnings.append("Sensitive keyword")

        print("\n===== PHISHGUARD v2.0 =====")
        print("Hostname:", host)
        print("Risk score:", score)

        if score >= 5:
            print("Assessment: HIGHER RISK")
        elif score >= 3:
            print("Assessment: REVIEW CAREFULLY")
        elif score >= 1:
            print("Assessment: LOW-LEVEL WARNINGS")
        else:
            print("Assessment: NO OBVIOUS WARNINGS")

        print("\nFindings:")

        if warnings:
            for warning in warnings:
                print("-", warning)
        else:
            print("No obvious warning detected")

        print("\nHeuristic assessment only.")

    except ValueError:
        print("Invalid URL")

print("PHISHGUARD v2.0")
print("Type exit to close")

while True:
    url = input("\nEnter URL: ").strip()

    if url.lower() == "exit":
        break

    if url:
        analyze_url(url)





0

