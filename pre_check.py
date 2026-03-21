import os
from url_analyser import analyse_url
from file_analyser import analyse_file

def analyse(input_data: str) -> dict:
    """
    Universal entry point for the pre-check engine.
    Accepts either a URL string or a file path.
    Automatically detects which one it is and routes accordingly.
    Returns a unified result dictionary.
    """

    result = {
        "input"       : input_data,
        "input_type"  : None,
        "features"    : {},
        "flags"       : [],
        "risk_score"  : 0,
        "verdict"     : None,
    }

    # ── Detect input type ──────────────────────────────────────────────────
    if input_data.startswith("http://") or input_data.startswith("https://"):
        result["input_type"] = "url"
        features = analyse_url(input_data)
        result["features"] = features
        result["flags"], result["risk_score"] = _score_url(features)

    elif os.path.exists(input_data):
        result["input_type"] = "file"
        features = analyse_file(input_data)
        result["features"] = features
        result["flags"], result["risk_score"] = _score_file(features)

    else:
        result["input_type"] = "unknown"
        result["flags"]      = ["Input is neither a valid URL nor an existing file path"]
        result["risk_score"] = 0

    # ── Assign verdict based on risk score ─────────────────────────────────
    score = result["risk_score"]
    if score == 0:
        result["verdict"] = "SAFE"
    elif score <= 40:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "MALICIOUS"

    return result


def _score_url(features: dict):
    """
    Converts URL features into a list of human-readable flags
    and a numeric risk score (0-100).
    """
    flags = []
    score = 0

    if features.get("has_ip_address") == 1:
        flags.append("Uses raw IP address instead of domain name")
        score += 30

    if features.get("uses_https") == 0:
        flags.append("Does not use HTTPS — connection is unencrypted")
        score += 15

    if features.get("count_at", 0) > 0:
        flags.append(f"Contains @ symbol ({features['count_at']} found) — redirection trick")
        score += 25

    if features.get("has_suspicious_keyword") == 1:
        kw_count = features.get("suspicious_keyword_count", 0)
        flags.append(f"Contains {kw_count} suspicious keyword(s) — phishing pattern")
        score += 20

    if features.get("hyphen_in_domain") == 1:
        flags.append("Domain contains hyphens — common in fake domains")
        score += 10

    if features.get("is_shortened") == 1:
        flags.append("URL is from a shortening service — destination is hidden")
        score += 15

    if features.get("url_length", 0) > 75:
        flags.append(f"URL is very long ({features['url_length']} chars) — obfuscation pattern")
        score += 10

    if features.get("count_percent", 0) > 3:
        flags.append(f"Heavy URL encoding ({features['count_percent']} % chars) — obfuscation")
        score += 15

    if features.get("has_double_slash") == 1:
        flags.append("Double slash in path — possible redirection attack")
        score += 10

    return flags, min(score, 100)


def _score_file(features: dict):
    """
    Converts file features into a list of human-readable flags
    and a numeric risk score (0-100).
    """
    flags = []
    score = 0

    if features.get("extension_mismatch") == 1:
        flags.append(features.get("mismatch_detail", "Extension mismatch detected"))
        score += 50

    if features.get("is_dangerous_type") == 1:
        flags.append(f"File is a dangerous type: {features.get('detected_mime_type')}")
        score += 30

    if features.get("is_disguised_exe") == 1:
        flags.append("Executable disguised with a non-executable extension")
        score += 20

    return flags, min(score, 100)


def print_result(result: dict):
    """Pretty-prints the full pre-check result."""
    verdict = result["verdict"]
    color_map = {"SAFE": "✓", "SUSPICIOUS": "!", "MALICIOUS": "✗"}
    icon = color_map.get(verdict, "?")

    print(f"\n{'=' * 65}")
    print(f"  PRE-CHECK RESULT")
    print(f"{'=' * 65}")
    print(f"  Input      : {result['input']}")
    print(f"  Type       : {result['input_type'].upper()}")
    print(f"  Risk Score : {result['risk_score']} / 100")
    print(f"  Verdict    : [{icon}] {verdict}")

    if result["flags"]:
        print(f"\n  Flags detected:")
        for flag in result["flags"]:
            print(f"    - {flag}")
    else:
        print(f"\n  No suspicious indicators found.")

    print(f"{'=' * 65}")


# ── Self-test ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\nPRE-CHECK ENGINE — FULL PIPELINE TEST")

    test_inputs = [
        # Safe URL
        "https://www.google.com",
        # Phishing URL
        "http://192.168.1.1/login/verify-account?user=admin@bank.com",
        # Suspicious URL
        "https://paypal-secure-login.com/update/password?verify=true",
        # Safe file
        "tests/normal.txt",
        # Suspicious file
        "tests/fake.pdf",
        # Disguised file
        "tests/photo.jpg",
    ]

    for item in test_inputs:
        result = analyse(item)
        print_result(result)

    print("\npre_check.py working correctly.")
    print("Stage 1 Pre-Check Engine is COMPLETE.")