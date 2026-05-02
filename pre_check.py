"""
pre_check.py — Universal pre-execution threat analysis engine.

v2 improvements:
  - 3-tier URL decision system:
      Tier 1: Trusted domain whitelist (200+ known-safe sites → instant SAFE)
      Tier 2: Hard malicious pattern detection (instant MALICIOUS)
      Tier 3: AI model + calibrated rule-based fallback
  - URL auto-normalization (so 'youtube.com' is parsed correctly)
  - Subdomain-aware trusted domain matching (accounts.google.com is also SAFE)
  - Smarter rule-based scoring with weighted, context-aware flags
"""

import os
from urllib.parse import urlparse

from url_analyser  import analyse_url, normalize_url
from file_analyser import analyse_file


# ══════════════════════════════════════════════════════════════════════════════
# TIER 1 — TRUSTED DOMAIN WHITELIST
# ══════════════════════════════════════════════════════════════════════════════

TRUSTED_DOMAINS = {
    # ── Search & Productivity ────────────────────────────────────────────────
    "google.com", "google.co.in", "google.co.uk",
    "youtube.com", "gmail.com", "drive.google.com",
    "docs.google.com", "maps.google.com", "meet.google.com",
    "bing.com", "yahoo.com", "yahoo.co.in",
    "duckduckgo.com", "baidu.com", "yandex.com",
    "wolframalpha.com",

    # ── Social Media ─────────────────────────────────────────────────────────
    "facebook.com", "fb.com", "instagram.com",
    "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "pinterest.com", "tiktok.com",
    "snapchat.com", "tumblr.com", "quora.com",
    "discord.com", "slack.com", "telegram.org",
    "whatsapp.com", "signal.org",

    # ── Microsoft ecosystem ───────────────────────────────────────────────────
    "microsoft.com", "office.com", "outlook.com",
    "hotmail.com", "live.com", "azure.com",
    "microsoftonline.com", "windows.com", "windowsazure.com",
    "onedrive.live.com", "sharepoint.com",
    "xbox.com", "msn.com", "skype.com",
    "visualstudio.com", "github.com",

    # ── Apple ────────────────────────────────────────────────────────────────
    "apple.com", "icloud.com", "itunes.apple.com",

    # ── Amazon & Shopping ────────────────────────────────────────────────────
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
    "amazon.fr", "amazon.co.jp", "amazon.ca",
    "aws.amazon.com", "console.aws.amazon.com",
    "ebay.com", "flipkart.com", "etsy.com",
    "shopify.com", "walmart.com", "target.com",
    "myntra.com", "meesho.com", "ajio.com",

    # ── Developer & Tech ─────────────────────────────────────────────────────
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com",
    "npmjs.com", "pypi.org", "docker.com",
    "kubernetes.io", "heroku.com", "netlify.com",
    "vercel.com", "cloudflare.com", "digitalocean.com",
    "replit.com", "codepen.io", "codesandbox.io",
    "jsfiddle.net", "leetcode.com", "hackerrank.com",
    "geeksforgeeks.org", "kaggle.com",

    # ── Finance & Payments ───────────────────────────────────────────────────
    "paypal.com", "stripe.com", "visa.com",
    "mastercard.com", "razorpay.com", "paytm.com",
    "phonepe.com", "gpay.app",

    # ── Media & Streaming ────────────────────────────────────────────────────
    "netflix.com", "spotify.com", "twitch.tv",
    "hulu.com", "primevideo.com", "hotstar.com",
    "disneyplus.com", "soundcloud.com", "vimeo.com",
    "dailymotion.com", "crunchyroll.com",

    # ── News & Information ───────────────────────────────────────────────────
    "wikipedia.org", "nytimes.com", "bbc.com",
    "bbc.co.uk", "cnn.com", "reuters.com",
    "theguardian.com", "medium.com", "substack.com",
    "wordpress.com", "blogspot.com",
    "ndtv.com", "timesofindia.indiatimes.com", "hindustantimes.com",
    "thehindu.com", "indiatoday.in",

    # ── Education ────────────────────────────────────────────────────────────
    "khanacademy.org", "coursera.org", "udemy.com",
    "edx.org", "mit.edu", "harvard.edu",
    "stanford.edu", "w3schools.com",
    "moodle.org", "duolingo.com",

    # ── Cloud & Hosting ──────────────────────────────────────────────────────
    "cloud.google.com", "firebase.google.com",
    "ibm.com", "oracle.com", "sap.com",
    "salesforce.com", "hubspot.com",

    # ── Tools & Utilities ────────────────────────────────────────────────────
    "dropbox.com", "box.com", "zoom.us",
    "webex.com", "canva.com", "figma.com",
    "notion.so", "airtable.com", "trello.com",
    "mailchimp.com", "sendgrid.com",
    "adobe.com", "autodesk.com",
    "openai.com", "anthropic.com", "huggingface.co",
    "deepmind.google",

    # ── Hardware & Devices ───────────────────────────────────────────────────
    "nvidia.com", "amd.com", "intel.com",
    "dell.com", "hp.com", "lenovo.com",
    "asus.com", "samsung.com", "lg.com",

    # ── Indian Government & Telecom ───────────────────────────────────────────
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in",
    "mygov.in", "india.gov.in", "epfindia.gov.in",
    "jio.com", "airtel.com", "bsnl.in", "vi.in",
    "zomato.com", "swiggy.com", "ola.com",
    "naukri.com", "indiamart.com",

    # ── Security & Antivirus ─────────────────────────────────────────────────
    "virustotal.com", "norton.com", "mcafee.com",
    "kaspersky.com", "avast.com", "malwarebytes.com",
}

# Derive the base domain set (strips www. and expands to allow subdomains)
TRUSTED_BASE_DOMAINS = set()
for _d in TRUSTED_DOMAINS:
    TRUSTED_BASE_DOMAINS.add(_d.replace("www.", ""))


def _extract_base_domain(url: str) -> str:
    """
    Extract just the registrable domain from a full URL.
    Handles country-code SLDs like .co.in, .co.uk.
    Examples:
      'accounts.google.com'   → 'google.com'
      'www.youtube.com'       → 'youtube.com'
      'mail.yahoo.co.in'      → 'yahoo.co.in'
      'http://192.168.1.1'    → '192.168.1.1'
    """
    try:
        url   = normalize_url(url)
        parsed = urlparse(url)
        netloc = (parsed.netloc or parsed.path).lower()
        netloc = netloc.split(":")[0].split("?")[0].split("/")[0]
        parts  = netloc.split(".")

        if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
            # Country-code SLD pattern (.co.in, .co.uk, .com.au …)
            return ".".join(parts[-3:])
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return netloc
    except Exception:
        return ""


def _is_trusted_domain(url: str) -> bool:
    """
    Returns True if the URL's registrable domain is in the trusted whitelist.
    Automatically covers all subdomains of trusted domains.
    """
    base = _extract_base_domain(url)
    return base in TRUSTED_BASE_DOMAINS


# ══════════════════════════════════════════════════════════════════════════════
# TIER 2 — HARD MALICIOUS PATTERN DETECTION
# ══════════════════════════════════════════════════════════════════════════════

# Phishing keywords that are very rarely in legitimate URLs
_PHISH_KEYWORDS = [
    "verify", "validate", "credential", "suspend", "recover",
    "seed-phrase", "wallet-restore", "re-authenticate",
    "ebayisapi", "webscr",
]


def _hard_malicious_check(features: dict, url: str) -> dict:
    """
    Checks for patterns that are almost exclusively found in malicious URLs.
    Returns {'is_malicious': bool, 'reasons': list[str]}
    """
    reasons = []
    url_lower = url.lower()

    # Pattern 1: Raw IP as host + no HTTPS = almost always malicious
    if features.get("has_ip_address") == 1 and features.get("uses_https") == 0:
        reasons.append(
            "Raw IP address used as host with no HTTPS encryption"
        )

    # Pattern 2: @ symbol in URL = redirection attack (RFC trick)
    if features.get("count_at", 0) > 0:
        reasons.append(
            "@ symbol in URL — classic redirection attack (browser ignores "
            "everything before @)"
        )

    # Pattern 3: Brand impersonation
    if features.get("brand_impersonation") == 1:
        reasons.append(
            "Brand name found in URL path but not in the actual domain — "
            "impersonation attack"
        )

    # Pattern 4: Domain does not resolve + suspicious TLD
    if (features.get("dns_resolves") == 0
            and features.get("has_ip_address") == 0):
        reasons.append(
            "Domain does not resolve to any IP address — likely fake or "
            "taken-down phishing domain"
        )

    # Pattern 5: Suspicious TLD + phishing keyword combination
    if (features.get("has_suspicious_tld") == 1
            and features.get("has_suspicious_keyword") == 1):
        reasons.append(
            f"High-risk TLD combined with phishing keyword — "
            f"strong malicious signal"
        )

    # Pattern 6: High-entropy DGA domain + suspicious TLD
    if (features.get("domain_entropy", 0) > 3.8
            and features.get("has_suspicious_tld") == 1):
        reasons.append(
            f"Machine-generated domain name (entropy: "
            f"{features.get('domain_entropy')}) — possible DGA malware domain"
        )

    return {
        "is_malicious": len(reasons) > 0,
        "reasons"     : reasons,
    }


# ══════════════════════════════════════════════════════════════════════════════
# TIER 3 — RULE-BASED SOFT SCORING (for explanation & AI fallback)
# ══════════════════════════════════════════════════════════════════════════════

def _rule_based_url(features: dict) -> tuple:
    """
    Weighted rule-based scoring system.
    Returns (flags: list[str], score: int 0-100).
    This is used to generate human-readable explanations and as AI fallback.
    Designed to produce ZERO false positives for clean websites.
    """
    flags = []
    score = 0

    # ── High-confidence signals ────────────────────────────────────────────
    if features.get("has_ip_address") == 1:
        flags.append("Uses raw IP address instead of a domain name (+35)")
        score += 35

    if features.get("uses_https") == 0:
        flags.append("No HTTPS — connection is not encrypted (+20)")
        score += 20

    if features.get("brand_impersonation") == 1:
        flags.append("Brand name in URL path does not match actual domain — "
                     "impersonation attempt (+40)")
        score += 40

    if features.get("dns_resolves") == 0 and features.get("has_ip_address") == 0:
        flags.append("Domain fails DNS resolution — may be fake or inactive (+30)")
        score += 30

    # ── Medium-confidence signals ──────────────────────────────────────────
    if features.get("count_at", 0) > 0:
        flags.append("@ symbol in URL — redirection trick (+30)")
        score += 30

    if features.get("has_suspicious_tld") == 1:
        flags.append("High-risk top-level domain (e.g. .tk, .xyz, .ml) (+20)")
        score += 20

    if features.get("has_suspicious_keyword") == 1:
        kw = features.get("suspicious_keyword_count", 0)
        flags.append(f"Contains {kw} phishing keyword(s) in the URL (+15)")
        score += 15

    if features.get("is_shortened") == 1:
        flags.append("URL shortener used — hides the real destination (+20)")
        score += 20

    if features.get("domain_entropy", 0) > 3.8:
        flags.append(
            f"Domain appears randomly generated "
            f"(entropy score: {features.get('domain_entropy')}) (+15)"
        )
        score += 15

    # ── Lower-confidence signals ───────────────────────────────────────────
    if features.get("count_at", 0) == 0:          # Don't double-count
        pass

    if features.get("url_length", 0) > 100:
        flags.append(f"Unusually long URL ({features['url_length']} chars) (+10)")
        score += 10

    if features.get("count_percent", 0) > 5:
        flags.append("Heavy URL-encoding — possible obfuscation (+10)")
        score += 10

    if features.get("has_double_slash") == 1:
        flags.append("Double slash in URL path — possible redirect injection (+8)")
        score += 8

    if features.get("subdomain_count", 0) > 2:
        flags.append(
            f"Excessive subdomain depth ({features['subdomain_count']} levels) — "
            f"common in phishing (+8)"
        )
        score += 8

    # NOTE: hyphens in domain alone are NOT flagged here.
    # Many legitimate SaaS sites use hyphens (e.g. google-analytics.com).
    # They only matter when combined with other signals (handled by the model).

    return flags, min(score, 100)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def analyse(input_data: str) -> dict:
    """
    Universal entry point for the pre-check engine.
    Accepts a URL string (with or without scheme) or a local file path.

    Decision order:
      1. If the path exists on disk → file analysis
      2. Everything else → URL analysis (bare domains, full URLs, IPs)
    """
    result = {
        "input"      : input_data,
        "input_type" : None,
        "features"   : {},
        "flags"      : [],
        "risk_score" : 0,
        "verdict"    : None,
        "confidence" : 0,
        "source"     : None,
    }

    # Check if it's a local file path first
    if os.path.exists(input_data):
        result["input_type"] = "file"
        _analyse_file(input_data, result)
    else:
        # Treat everything else as a URL (bare domain, full URL, IP)
        result["input_type"] = "url"
        _analyse_url(input_data, result)

    return result


def _analyse_url(url: str, result: dict):
    """
    3-tier URL analysis pipeline.
    Tier 1 → Trusted domain whitelist
    Tier 2 → Hard malicious pattern check
    Tier 3 → AI model + rule-based fallback
    """
    # Normalize first so all tiers see the canonical URL
    url_normalized = normalize_url(url)
    result["input"] = url_normalized

    # Extract all features (DNS lookup happens here)
    features           = analyse_url(url_normalized)
    result["features"] = features

    # ── TIER 1: Trusted Domain Whitelist ────────────────────────────────────
    if _is_trusted_domain(url_normalized):
        result["verdict"]    = "SAFE"
        result["confidence"] = 99
        result["risk_score"] = 0
        result["source"]     = "Trusted Domain Whitelist"
        result["flags"]      = []
        return

    # ── TIER 2: Hard Malicious Patterns ────────────────────────────────────
    hard = _hard_malicious_check(features, url_normalized)
    if hard["is_malicious"]:
        result["verdict"]    = "MALICIOUS"
        result["confidence"] = 95
        result["risk_score"] = 90
        result["source"]     = "Hard Rule Detection"
        result["flags"]      = hard["reasons"]
        return

    # ── TIER 3: AI Model + Rule-based fallback ──────────────────────────────
    try:
        from model import predict
        prediction           = predict(features)
        result["verdict"]    = prediction["verdict"]
        result["confidence"] = prediction["confidence"]
        result["risk_score"] = prediction["phishing_pct"]
        result["source"]     = "AI Model"
    except Exception:
        # Fallback to rule-based if model unavailable
        soft_flags, score = _rule_based_url(features)
        result["risk_score"] = score
        result["source"]     = "Rule-based"
        if score <= 15:
            result["verdict"]    = "SAFE"
            result["confidence"] = 90
        elif score <= 45:
            result["verdict"]    = "SUSPICIOUS"
            result["confidence"] = 65
        else:
            result["verdict"]    = "MALICIOUS"
            result["confidence"] = 80

    # Always attach human-readable rule flags for display (Tier 3 only)
    soft_flags, _ = _rule_based_url(features)
    result["flags"] = soft_flags


def _analyse_file(filepath: str, result: dict):
    """File analysis — magic byte detection (unchanged from v1)."""
    features             = analyse_file(filepath)
    result["features"]   = features
    flags, score         = _rule_based_file(features)
    result["flags"]      = flags
    result["risk_score"] = score
    result["source"]     = "Magic Byte Analysis"

    if score == 0:
        result["verdict"]    = "SAFE"
        result["confidence"] = 95
    elif score <= 40:
        result["verdict"]    = "SUSPICIOUS"
        result["confidence"] = 65
    else:
        result["verdict"]    = "MALICIOUS"
        result["confidence"] = 90


def _rule_based_file(features: dict):
    """
    Weighted rule-based scoring system for files.
    Returns (flags: list[str], score: int 0-100).
    """
    flags = []
    score = 0
    
    # ── High-confidence malicious signals ──────────────────────────────────
    if features.get("is_disguised_exe") == 1:
        flags.append(f"Disguised Executable: File claims to be '{features.get('extension')}' but is actually '{features.get('detected_mime_type')}' (+60)")
        score += 60
        
    if features.get("contains_dangerous_file") == 1:
        found_files = ", ".join(features.get("dangerous_files_found", [])[:3])
        flags.append(f"Dangerous Archive: Contains malicious files (e.g., {found_files}) hidden inside (+80)")
        score += 80
        
    if features.get("is_packed_executable") == 1:
        flags.append(f"Packed Malware: Executable file has unusually high entropy ({features.get('entropy')}), indicating it is packed or encrypted (+60)")
        score += 60

    # ── Medium-confidence signals ──────────────────────────────────────────
    if features.get("extension_mismatch") == 1 and features.get("is_disguised_exe") == 0:
        flags.append(features.get("mismatch_detail", "Extension mismatch") + " (+40)")
        score += 40
        
    if features.get("is_dangerous_type") == 1 and features.get("is_disguised_exe") == 0 and features.get("is_packed_executable") == 0:
        flags.append(f"Dangerous file type detected: {features.get('detected_mime_type')} (+30)")
        score += 30

    return flags, min(score, 100)


# ══════════════════════════════════════════════════════════════════════════════
# SELF-TEST
# ══════════════════════════════════════════════════════════════════════════════

def print_result(result: dict):
    icon = {"SAFE": "✓", "SUSPICIOUS": "!", "MALICIOUS": "✗"}.get(
        result["verdict"], "?"
    )
    print(f"\n{'=' * 65}")
    print(f"  Input      : {result['input']}")
    print(f"  Type       : {result['input_type'].upper()}")
    print(f"  Verdict    : [{icon}] {result['verdict']}")
    print(f"  Confidence : {result.get('confidence', 0)}%")
    print(f"  Risk Score : {result['risk_score']} / 100")
    print(f"  Source     : {result.get('source', 'N/A')}")
    if result["flags"]:
        print(f"\n  Flags:")
        for flag in result["flags"]:
            print(f"    ▸ {flag}")
    else:
        print(f"\n  No suspicious indicators found.")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    test_cases = [
        # Expected SAFE
        "youtube.com",
        "https://www.google.com",
        "accounts.google.com/signin",
        "github.com/user/repo",
        "https://www.amazon.in/products",
        "mail.yahoo.co.in",
        # Expected SUSPICIOUS / MALICIOUS
        "http://192.168.1.1/login?user=admin@bank.com",
        "https://paypal-secure-login.xyz/update/password?verify=true",
        "http://bit.ly/3xFreeGift",
        "http://amazon-account-recover.tk/seed-phrase",
        "https://xkd8hs9jf2.ml/credential",
    ]

    print("PRE-CHECK ENGINE v2 — FULL TEST\n")
    for item in test_cases:
        result = analyse(item)
        print_result(result)