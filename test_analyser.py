"""Comprehensive edge case test for the URL analyzer v2."""
from pre_check import analyse

tests = [
    # Genuine sites that MUST be SAFE
    ("youtube.com",                                   "SAFE",     "Bare domain no scheme"),
    ("https://www.google.com",                        "SAFE",     "Full URL with www"),
    ("accounts.google.com/signin",                    "SAFE",     "Google subdomain with /signin path"),
    ("https://www.paypal.com",                        "SAFE",     "Real PayPal"),
    ("https://login.microsoftonline.com",             "SAFE",     "Microsoft 365 login"),
    ("https://www.hdfc.com",                          "SAFE",     "Indian bank"),
    ("https://mail.google.com",                       "SAFE",     "Gmail"),
    ("https://www.amazon.in/dp/B09G34NNHQ",           "SAFE",     "Amazon product URL with numbers"),
    ("https://stackoverflow.com/questions/12345",     "SAFE",     "Dev site with path"),
    ("https://www.linkedin.com/in/someone",           "SAFE",     "LinkedIn profile"),
    ("https://www.apple.com/shop/buy-iphone",         "SAFE",     "Apple with 'buy' in path"),
    ("https://github.com/login",                      "SAFE",     "GitHub login page"),
    ("https://www.facebook.com/login",                "SAFE",     "Facebook login page"),

    # MALICIOUS that MUST be caught
    ("http://192.168.1.1/login?user=admin@bank.com",  "MALICIOUS","IP + @ symbol + keywords"),
    ("https://paypal-secure-login.tk/verify",         "MALICIOUS","Brand impersonation + .tk TLD"),
    ("https://amazon-account-suspended.xyz/recover",  "MALICIOUS","Brand impersonation + .xyz"),
    ("https://secure-hdfc-bank-login.ml/validate",    "MALICIOUS","Bank impersonation + .ml"),
    ("http://www.g00gle-login.com/signin",            "MALICIOUS","Typosquatting google"),
]

print("=" * 72)
print("  URL ANALYZER v2 -- COMPREHENSIVE EDGE CASE TEST")
print("=" * 72)

passed = 0
failed = 0
for url, expected, note in tests:
    r = analyse(url)
    verdict = r["verdict"]
    ok = verdict == expected
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    marker = "[OK]" if ok else "[!!]"
    print(f"{marker} [{status}] {url[:50]:<50} -> {verdict:<10} | {note}")
    if not ok:
        src = r.get("source", "?")
        score = r.get("risk_score", "?")
        print(f"       Expected: {expected} | Source: {src} | Score: {score}")
        for flag in r.get("flags", []):
            print(f"       FLAG: {flag}")

print("=" * 72)
total = len(tests)
pct = round(passed / total * 100, 1)
print(f"  Result: {passed}/{total} passed ({pct}%) | {failed} failed")
if failed == 0:
    print("  STATUS: ALL TESTS PASSED - URL analyzer is ready!")
else:
    print("  STATUS: Some tests failed - review above.")
print("=" * 72)
