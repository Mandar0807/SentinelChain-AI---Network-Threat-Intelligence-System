import sys

print("=" * 50)
print("ENVIRONMENT VERIFICATION")
print("=" * 50)

# Python version
print(f"\nPython version: {sys.version}")

# Test all imports
modules = {
    "scapy": "from scapy.all import IP, sniff",
    "requests": "import requests",
    "python-magic": "import magic",
    "scikit-learn": "import sklearn",
    "web3": "from web3 import Web3",
    "flask": "import flask",
    "pandas": "import pandas",
    "numpy": "import numpy",
    "joblib": "import joblib",
}

all_ok = True
for name, imp in modules.items():
    try:
        exec(imp)
        print(f"  OK   {name}")
    except ImportError as e:
        print(f"  FAIL {name}  -->  {e}")
        all_ok = False

# Test Ganache connection
print("\nTesting Ganache connection...")
try:
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
    if w3.is_connected():
        accounts = w3.eth.accounts
        print(f"  OK   Ganache connected — {len(accounts)} accounts found")
        print(f"       First account: {accounts[0]}")
    else:
        print("  FAIL Ganache not connected — is Ganache running?")
        all_ok = False
except Exception as e:
    print(f"  FAIL Ganache error: {e}")
    all_ok = False

print("\n" + "=" * 50)
if all_ok:
    print("ALL CHECKS PASSED — Day 1 complete!")
else:
    print("SOME CHECKS FAILED — fix errors above before Day 2")
print("=" * 50)