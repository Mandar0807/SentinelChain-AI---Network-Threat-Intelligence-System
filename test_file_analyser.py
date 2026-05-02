import os
import zipfile
import random
from pre_check import analyse

def create_test_files():
    # 1. Normal Text File
    with open("test_safe.txt", "w") as f:
        f.write("This is a normal text file with low entropy.")

    # 2. Disguised Executable (MZ header but .pdf extension)
    with open("test_disguised.pdf", "wb") as f:
        # Standard DOS MZ executable header
        f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00")
        f.write(b"This program cannot be run in DOS mode.\r\r\n$")
        f.write(b"\x00" * 100)

    # 3. Packed Executable (MZ header + highly random data for high entropy)
    with open("test_packed.exe", "wb") as f:
        f.write(b"MZ\x90\x00")
        f.write(os.urandom(1024 * 50)) # 50KB of random bytes (high entropy)

    # 4. Safe ZIP Archive
    with zipfile.ZipFile("test_safe.zip", "w") as zf:
        zf.writestr("document.txt", "This is a safe document inside a zip.")
        zf.writestr("image.png", b"\x89PNG\r\n\x1a\n")

    # 5. Malicious ZIP Archive (Contains .vbs)
    with zipfile.ZipFile("test_malicious.zip", "w") as zf:
        zf.writestr("invoice.pdf", "Fake PDF data")
        zf.writestr("hidden_script.vbs", "MsgBox 'You are hacked'")

def cleanup():
    files = ["test_safe.txt", "test_disguised.pdf", "test_packed.exe", "test_safe.zip", "test_malicious.zip"]
    for f in files:
        if os.path.exists(f):
            os.remove(f)

def run_tests():
    create_test_files()
    
    tests = [
        ("test_safe.txt", "SAFE"),
        ("test_disguised.pdf", "MALICIOUS"),
        ("test_packed.exe", "MALICIOUS"),
        ("test_safe.zip", "SAFE"),
        ("test_malicious.zip", "MALICIOUS"),
    ]
    
    print("=" * 70)
    print("  FILE ANALYZER OVERHAUL -- FUNCTIONAL TEST")
    print("=" * 70)
    
    passed = 0
    for file, expected in tests:
        result = analyse(file)
        verdict = result["verdict"]
        score = result["risk_score"]
        flags = result["flags"]
        
        ok = verdict == expected
        if ok: passed += 1
        status = "[PASS]" if ok else "[FAIL]"
        
        print(f"{status} {file:<25} -> {verdict:<10} (Score: {score})")
        for flag in flags:
            print(f"       FLAG: {flag}")
    
    print("=" * 70)
    print(f"  Result: {passed}/{len(tests)} passed.")
    print("=" * 70)
    
    cleanup()

if __name__ == "__main__":
    run_tests()
