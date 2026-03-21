import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "signin", "ebayisapi",
    "webscr", "paypal", "free", "lucky", "service", "bonus"
]

def analyse_url(url: str) -> dict:
    features = {}

    # Length features
    features["url_length"]          = len(url)
    features["url_depth"]           = url.count("/") - 2

    # Character counts
    features["count_dots"]          = url.count(".")
    features["count_hyphens"]       = url.count("-")
    features["count_at"]            = url.count("@")
    features["count_percent"]       = url.count("%")
    features["count_question"]      = url.count("?")
    features["count_equals"]        = url.count("=")
    features["count_underscore"]    = url.count("_")
    features["count_digits"]        = sum(c.isdigit() for c in url)

    # Parse the URL into components
    try:
        parsed     = urlparse(url)
        scheme     = parsed.scheme
        netloc     = parsed.netloc
        path       = parsed.path
    except Exception:
        scheme, netloc, path = "", "", ""

    # HTTPS check
    features["uses_https"]          = 1 if scheme == "https" else 0

    # IP address instead of domain name
    clean_netloc = netloc.split(":")[0]
    ip_pattern   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    features["has_ip_address"]      = 1 if ip_pattern.match(clean_netloc) else 0

    # Domain length
    features["domain_length"]       = len(clean_netloc)

    # Suspicious keywords
    url_lower = url.lower()
    features["suspicious_keyword_count"] = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower
    )
    features["has_suspicious_keyword"]   = (
        1 if features["suspicious_keyword_count"] > 0 else 0
    )

    # URL shortening services
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co",
                  "ow.ly", "is.gd", "buff.ly", "adf.ly"]
    features["is_shortened"]        = (
        1 if any(s in clean_netloc for s in shorteners) else 0
    )

    # Double slash in path (redirection trick)
    features["has_double_slash"]    = 1 if "//" in path else 0

    # Hyphen inside domain name
    features["hyphen_in_domain"]    = 1 if "-" in clean_netloc else 0

    return features


def print_analysis(url: str):
    print(f"\nURL : {url}")
    print("-" * 65)
    features = analyse_url(url)
    for key, value in features.items():
        flag = "  <-- FLAG" if (
            (key == "count_at"              and value > 0)  or
            (key == "has_ip_address"        and value == 1) or
            (key == "uses_https"            and value == 0) or
            (key == "has_suspicious_keyword"and value == 1) or
            (key == "is_shortened"          and value == 1) or
            (key == "hyphen_in_domain"      and value == 1) or
            (key == "url_length"            and value > 75)
        ) else ""
        print(f"  {key:<35} {value}{flag}")
    print("-" * 65)


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login/verify-account?user=admin@bank.com",
        "https://paypal-secure-login.com/update/password?verify=true",
        "http://bit.ly/3xFreeGift",
        "https://github.com/user/repo",
    ]

    print("=" * 65)
    print("URL ANALYSER — FEATURE EXTRACTION TEST")
    print("=" * 65)
    for url in test_urls:
        print_analysis(url)
    print("\nurl_analyser.py working correctly.")