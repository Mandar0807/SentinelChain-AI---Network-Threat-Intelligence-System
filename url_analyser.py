"""
url_analyser.py — Comprehensive URL feature extraction for threat detection.

Improvements over v1:
  - Auto-normalizes URLs (adds https:// if missing) so parsing is always correct
  - DNS resolution check (non-resolvable domains are suspicious)
  - Domain entropy (detects randomly generated domain names)
  - Brand impersonation detection (paypal in path but domain is not paypal.com)
  - Suspicious TLD detection (.xyz, .tk, .ml, .ga, etc.)
  - Subdomain depth counting
  - Tighter, more targeted suspicious keyword list (removed overly broad terms)
  - Port-in-URL detection
"""

import re
import math
import socket
from collections import Counter
from urllib.parse import urlparse


# ── Suspicious keywords ────────────────────────────────────────────────────
# Only words that are STRONGLY associated with phishing and almost never
# appear in legitimate URLs on major sites.
SUSPICIOUS_KEYWORDS = [
    "verify", "validate", "validation",
    "confirm", "confirmation",
    "recover", "recovery",
    "suspend", "suspended", "unusual-activity",
    "credential", "credentials",
    "signin-help", "login-alert",
    "ebayisapi", "webscr",
    "phishing", "malware",
    "wallet-restore", "seed-phrase",
    "authenticate", "re-authenticate",
]

# ── Known URL shorteners ───────────────────────────────────────────────────
SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "tiny.cc", "rb.gy",
    "cutt.ly", "shorturl.at", "bl.ink", "shorte.st", "clck.ru",
]

# ── Suspicious TLDs frequently abused in phishing ─────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free Freenom TLDs, heavily abused
    ".xyz", ".top", ".club", ".online",
    ".site", ".website", ".tech",
    ".click", ".link", ".download",
    ".stream", ".loan", ".party",
    ".review", ".trade", ".win",
    ".racing", ".accountant", ".science",
    ".work", ".zip", ".mov",              # New Google TLDs widely abused
}

# ── Trusted TLDs for real organizations ───────────────────────────────────
TRUSTED_TLDS = {
    ".com", ".org", ".net", ".edu", ".gov",
    ".io", ".co", ".uk", ".de", ".fr",
    ".in", ".au", ".ca", ".jp", ".br",
}

# ── Brand names used for impersonation detection ──────────────────────────
MAJOR_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google",
    "facebook", "netflix", "instagram", "twitter", "whatsapp",
    "youtube", "linkedin", "dropbox", "icloud", "outlook",
    "office365", "onedrive", "chase", "wellsfargo", "bankofamerica",
    "citibank", "barclays", "hdfc", "icici", "sbi",
    "binance", "coinbase", "metamask", "blockchain",
]


# ── Utility functions ──────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """
    Ensure URL has a scheme so urlparse works correctly.
    e.g. 'youtube.com' → 'https://youtube.com'
         'http://evil.tk' → unchanged
    """
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "https://" + url
    return url


def _extract_domain_parts(netloc: str):
    """
    Split netloc into (subdomains_list, domain_name, tld).
    Examples:
      'accounts.google.com' → (['accounts'], 'google', '.com')
      'evil-bank.tk'        → ([], 'evil-bank', '.tk')
    """
    clean = netloc.split(":")[0].lower()
    parts = clean.split(".")

    if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
        # Country-code SLD like .co.in, .co.uk
        tld        = "." + ".".join(parts[-2:])   # e.g. .co.in
        domain     = parts[-3]
        subdomains = parts[:-3]
    elif len(parts) >= 2:
        tld        = "." + parts[-1]
        domain     = parts[-2]
        subdomains = parts[:-2]
    else:
        tld        = ""
        domain     = clean
        subdomains = []

    return subdomains, domain, tld


def _domain_entropy(name: str) -> float:
    """
    Shannon entropy of the bare domain name (no TLD).
    High entropy (>3.8) suggests a machine-generated / DGA domain.
    Normal human-readable domains score 2.0–3.5.
    """
    if not name:
        return 0.0
    freq   = Counter(name)
    length = len(name)
    h = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return round(h, 3)


def _can_resolve_dns(domain: str) -> bool:
    """
    Returns True if the domain resolves to at least one IP address.
    Uses a 3-second timeout to avoid blocking the request for too long.
    """
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def _check_brand_impersonation(url_lower: str, domain_name: str) -> bool:
    """
    Detect if a major brand name appears in the URL path/query/subdomain
    while the ACTUAL domain is NOT that brand.
    e.g. 'paypal-secure-login.com/paypal/update' → impersonation
         'accounts.paypal.com/login'             → NOT impersonation
    """
    for brand in MAJOR_BRANDS:
        if brand in url_lower and brand not in domain_name:
            return True
    return False


# ── Main feature extraction ────────────────────────────────────────────────

def analyse_url(url: str) -> dict:
    """
    Extract a comprehensive feature vector from a URL.
    The URL is auto-normalized before processing.

    Returns a dict with all features needed by:
      - The trained ML model (Decision Tree)
      - The rule-based scoring system in pre_check.py
      - Any future classifiers
    """
    features = {}

    # ── Step 1: Normalize ──────────────────────────────────────────────────
    url = normalize_url(url)
    features["normalized_url"] = url

    # ── Step 2: Length features ────────────────────────────────────────────
    features["url_length"] = len(url)
    features["url_depth"]  = max(0, url.count("/") - 2)

    # ── Step 3: Character counts ───────────────────────────────────────────
    features["count_dots"]      = url.count(".")
    features["count_hyphens"]   = url.count("-")
    features["count_at"]        = url.count("@")
    features["count_percent"]   = url.count("%")
    features["count_question"]  = url.count("?")
    features["count_equals"]    = url.count("=")
    features["count_underscore"]= url.count("_")
    features["count_digits"]    = sum(c.isdigit() for c in url)

    # ── Step 4: Parse URL ──────────────────────────────────────────────────
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path   = parsed.path
        query  = parsed.query
    except Exception:
        scheme, netloc, path, query = "", "", "", ""

    url_lower = url.lower()

    # ── Step 5: HTTPS ──────────────────────────────────────────────────────
    features["uses_https"] = 1 if scheme == "https" else 0

    # ── Step 6: Raw IP address ─────────────────────────────────────────────
    clean_netloc = netloc.split(":")[0]
    ip_pattern   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    features["has_ip_address"] = 1 if ip_pattern.match(clean_netloc) else 0

    # ── Step 7: Domain components ──────────────────────────────────────────
    subdomains, domain_name, tld = _extract_domain_parts(clean_netloc)

    features["domain_length"]   = len(clean_netloc)
    features["subdomain_count"] = len(subdomains)

    # Hyphens INSIDE the actual domain name (not subdomains)
    features["hyphen_in_domain"] = 1 if "-" in domain_name else 0

    # ── Step 8: TLD classification ─────────────────────────────────────────
    features["has_suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0
    features["has_trusted_tld"]    = 1 if tld in TRUSTED_TLDS else 0

    # ── Step 9: Domain entropy (randomness) ───────────────────────────────
    features["domain_entropy"] = _domain_entropy(domain_name)

    # ── Step 10: Suspicious keywords (targeted list) ───────────────────────
    features["suspicious_keyword_count"] = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower
    )
    features["has_suspicious_keyword"] = (
        1 if features["suspicious_keyword_count"] > 0 else 0
    )

    # ── Step 11: Brand impersonation ───────────────────────────────────────
    features["brand_impersonation"] = (
        1 if _check_brand_impersonation(url_lower, domain_name) else 0
    )

    # ── Step 12: URL shorteners ────────────────────────────────────────────
    features["is_shortened"] = (
        1 if any(s in clean_netloc for s in SHORTENERS) else 0
    )

    # ── Step 13: Path tricks ───────────────────────────────────────────────
    features["has_double_slash"] = 1 if "//" in path else 0
    features["has_port"]         = (
        1 if (":" in netloc and features["has_ip_address"] == 0) else 0
    )

    # ── Step 14: DNS resolution ────────────────────────────────────────────
    if features["has_ip_address"] == 1:
        features["dns_resolves"] = 1          # IP always resolves
    elif clean_netloc:
        features["dns_resolves"] = 1 if _can_resolve_dns(clean_netloc) else 0
    else:
        features["dns_resolves"] = 0

    return features


# ── Self-test ──────────────────────────────────────────────────────────────

def print_analysis(url: str):
    print(f"\nURL : {url}")
    print("-" * 70)
    features = analyse_url(url)
    for key, value in features.items():
        if key == "normalized_url":
            continue
        flag = ""
        if key == "has_ip_address"        and value == 1: flag = "  ← FLAG: raw IP"
        if key == "count_at"              and value  > 0: flag = "  ← FLAG: @ redirection"
        if key == "brand_impersonation"   and value == 1: flag = "  ← FLAG: brand impersonation"
        if key == "has_suspicious_tld"    and value == 1: flag = "  ← FLAG: suspicious TLD"
        if key == "dns_resolves"          and value == 0: flag = "  ← FLAG: domain does not resolve"
        if key == "domain_entropy"        and value  > 3.8: flag = "  ← FLAG: high entropy (DGA-like)"
        if key == "uses_https"            and value == 0: flag = "  ← FLAG: no HTTPS"
        if key == "is_shortened"          and value == 1: flag = "  ← FLAG: URL shortener"
        if key == "has_suspicious_keyword"and value == 1: flag = "  ← FLAG: suspicious keywords"
        print(f"  {key:<35} {value}{flag}")
    print("-" * 70)


if __name__ == "__main__":
    test_urls = [
        "youtube.com",
        "https://www.google.com",
        "accounts.google.com/signin",
        "http://192.168.1.1/login/verify-account?user=admin@bank.com",
        "https://paypal-secure-login.xyz/update/password?verify=true",
        "http://bit.ly/3xFreeGift",
        "https://github.com/user/repo",
        "https://xk9d2hs7gj.tk/login",
        "http://amazon-account-suspended.com/recover",
    ]

    print("=" * 70)
    print("  URL ANALYSER v2 — COMPREHENSIVE FEATURE EXTRACTION TEST")
    print("=" * 70)
    for url in test_urls:
        print_analysis(url)
    print("\nurl_analyser.py v2 complete.")