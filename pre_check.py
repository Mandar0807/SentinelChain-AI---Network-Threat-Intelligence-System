import os
from url_analyser  import analyse_url
from file_analyser import analyse_file


def analyse(input_data: str) -> dict:
    """
    Universal entry point for the pre-check engine.
    Accepts a URL string or a file path.
    Returns a unified result dictionary.
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

    if input_data.startswith("http://") or \
       input_data.startswith("https://"):
        result["input_type"] = "url"
        _analyse_url(input_data, result)

    elif os.path.exists(input_data):
        result["input_type"] = "file"
        _analyse_file(input_data, result)

    else:
        result["input_type"] = "unknown"
        result["flags"]      = ["Not a valid URL or existing file path"]
        result["verdict"]    = "UNKNOWN"

    return result


def _analyse_url(url: str, result: dict):
    features           = analyse_url(url)
    result["features"] = features

    try:
        from model import predict
        prediction           = predict(features)
        result["verdict"]    = prediction["verdict"]
        result["confidence"] = prediction["confidence"]
        result["risk_score"] = prediction["phishing_pct"]
        result["source"]     = "AI model"
    except Exception:
        flags, score         = _rule_based_url(features)
        result["flags"]      = flags
        result["risk_score"] = score
        result["source"]     = "Rule-based"
        if score == 0:
            result["verdict"]    = "SAFE"
            result["confidence"] = 95
        elif score <= 40:
            result["verdict"]    = "SUSPICIOUS"
            result["confidence"] = 60
        else:
            result["verdict"]    = "MALICIOUS"
            result["confidence"] = 85

    flags, _       = _rule_based_url(features)
    result["flags"] = flags


def _analyse_file(filepath: str, result: dict):
    features             = analyse_file(filepath)
    result["features"]   = features
    flags, score         = _rule_based_file(features)
    result["flags"]      = flags
    result["risk_score"] = score
    result["source"]     = "Rule-based"

    if score == 0:
        result["verdict"]    = "SAFE"
        result["confidence"] = 95
    elif score <= 40:
        result["verdict"]    = "SUSPICIOUS"
        result["confidence"] = 60
    else:
        result["verdict"]    = "MALICIOUS"
        result["confidence"] = 85


def _rule_based_url(features: dict):
    flags = []
    score = 0
    if features.get("has_ip_address") == 1:
        flags.append("Uses raw IP address instead of domain name")
        score += 30
    if features.get("uses_https") == 0:
        flags.append("Does not use HTTPS")
        score += 15
    if features.get("count_at", 0) > 0:
        flags.append("Contains @ symbol — redirection trick")
        score += 25
    if features.get("has_suspicious_keyword") == 1:
        kw = features.get("suspicious_keyword_count", 0)
        flags.append(f"Contains {kw} suspicious keyword(s)")
        score += 20
    if features.get("hyphen_in_domain") == 1:
        flags.append("Hyphens in domain name")
        score += 10
    if features.get("is_shortened") == 1:
        flags.append("URL shortening service used")
        score += 15
    if features.get("url_length", 0) > 75:
        flags.append("Unusually long URL")
        score += 10
    if features.get("count_percent", 0) > 3:
        flags.append("Heavy URL encoding — obfuscation pattern")
        score += 15
    if features.get("has_double_slash") == 1:
        flags.append("Double slash in path — redirection attack")
        score += 10
    return flags, min(score, 100)


def _rule_based_file(features: dict):
    flags = []
    score = 0
    if features.get("extension_mismatch") == 1:
        flags.append(features.get("mismatch_detail", "Extension mismatch"))
        score += 50
    if features.get("is_dangerous_type") == 1:
        flags.append(f"Dangerous file type: "
                     f"{features.get('detected_mime_type')}")
        score += 30
    if features.get("is_disguised_exe") == 1:
        flags.append("Executable disguised with safe extension")
        score += 20
    return flags, min(score, 100)


def print_result(result: dict):
    icon = {"SAFE": "✓", "SUSPICIOUS": "!", "MALICIOUS": "✗"}.get(
        result["verdict"], "?")
    print(f"\n{'=' * 60}")
    print(f"  PRE-CHECK RESULT")
    print(f"{'=' * 60}")
    print(f"  Input      : {result['input']}")
    print(f"  Type       : {result['input_type'].upper()}")
    print(f"  Verdict    : [{icon}] {result['verdict']}")
    print(f"  Confidence : {result.get('confidence', 0)}%")
    print(f"  Risk Score : {result['risk_score']} / 100")
    print(f"  Source     : {result.get('source', 'N/A')}")
    if result["flags"]:
        print(f"\n  Flags:")
        for flag in result["flags"]:
            print(f"    - {flag}")
    else:
        print(f"\n  No suspicious indicators found.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    test_inputs = [
        "https://www.google.com",
        "http://192.168.1.1/login/verify-account?user=admin@bank.com",
        "https://paypal-secure-login.com/update/password?verify=true",
        "https://github.com/user/repo",
        "tests/normal.txt",
        "tests/fake.pdf",
    ]

    print("PRE-CHECK ENGINE — AI MODEL INTEGRATION TEST")
    for item in test_inputs:
        result = analyse(item)
        print_result(result)

    print("\nStage 1 complete — AI model integrated successfully.")