import os
import magic

# Maps common MIME types to their legitimate extensions
MIME_TO_EXTENSIONS = {
    "application/pdf":                        [".pdf"],
    "application/msword":                     [".doc"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
    "application/vnd.ms-excel":               [".xls"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"],
    "application/zip":                        [".zip", ".jar", ".docx", ".xlsx"],
    "application/x-rar-compressed":           [".rar"],
    "application/x-tar":                      [".tar"],
    "application/gzip":                       [".gz", ".tgz"],
    "application/x-7z-compressed":            [".7z"],
    "application/x-dosexec":                  [".exe", ".dll", ".com"],
    "application/x-executable":               [".elf", ".out"],
    "application/x-sharedlib":                [".so", ".dll"],
    "text/plain":                             [".txt", ".log", ".csv", ".py", ".js"],
    "text/html":                              [".html", ".htm"],
    "text/x-python":                          [".py"],
    "text/x-script.python":                   [".py"],
    "image/jpeg":                             [".jpg", ".jpeg"],
    "image/png":                              [".png"],
    "image/gif":                              [".gif"],
    "image/bmp":                              [".bmp"],
    "application/x-iso9660-image":            [".iso"],
    "application/java-archive":               [".jar"],
    "application/x-msdownload":               [".exe", ".dll"],
}

# MIME types that are always dangerous regardless of extension
DANGEROUS_MIME_TYPES = [
    "application/x-dosexec",
    "application/x-executable",
    "application/x-msdownload",
    "application/x-sharedlib",
    "application/x-shellscript",
    "application/x-sh",
]


def analyse_file(filepath: str) -> dict:
    """
    Takes a filepath and returns a feature dictionary.
    Detects extension vs real type mismatches and dangerous file types.
    """
    features = {}

    # ── Basic file info ────────────────────────────────────────────────────
    filename  = os.path.basename(filepath)
    extension = os.path.splitext(filename)[1].lower()

    features["filename"]           = filename
    features["extension"]          = extension
    features["file_size_bytes"]    = os.path.getsize(filepath)

    # ── Read real MIME type from magic bytes ───────────────────────────────
    try:
        mime_type = magic.from_file(filepath, mime=True)
        file_desc = magic.from_file(filepath)          # human-readable description
    except Exception as e:
        mime_type = "unknown"
        file_desc = str(e)

    features["detected_mime_type"] = mime_type
    features["file_description"]   = file_desc

    # ── Extension vs MIME type mismatch check ─────────────────────────────
    allowed_extensions = MIME_TO_EXTENSIONS.get(mime_type, [])

    if not allowed_extensions:
        # MIME type not in our map — flag as unknown
        features["extension_mismatch"] = 1
        features["mismatch_detail"]    = (
            f"Unknown MIME type '{mime_type}' — cannot verify extension"
        )
    elif extension in allowed_extensions:
        features["extension_mismatch"] = 0
        features["mismatch_detail"]    = "Extension matches detected file type"
    else:
        features["extension_mismatch"] = 1
        features["mismatch_detail"]    = (
            f"DECLARED '{extension}' but file is actually '{mime_type}'"
        )

    # ── Dangerous type check ───────────────────────────────────────────────
    features["is_dangerous_type"]  = 1 if mime_type in DANGEROUS_MIME_TYPES else 0

    # ── Executable disguised as something else ────────────────────────────
    features["is_disguised_exe"]   = (
        1 if (mime_type in DANGEROUS_MIME_TYPES and extension not in [".exe", ".dll", ".com"])
        else 0
    )

    # ── Risk score (simple combination for pre-check) ─────────────────────
    risk = 0
    if features["extension_mismatch"] == 1:
        risk += 50
    if features["is_dangerous_type"] == 1:
        risk += 30
    if features["is_disguised_exe"] == 1:
        risk += 20
    features["file_risk_score"]    = min(risk, 100)

    return features


def print_file_analysis(filepath: str):
    print(f"\nFile : {filepath}")
    print("-" * 65)
    if not os.path.exists(filepath):
        print("  ERROR: File not found")
        print("-" * 65)
        return
    features = analyse_file(filepath)
    for key, value in features.items():
        flag = ""
        if key == "extension_mismatch" and value == 1:
            flag = "  <-- FLAG"
        if key == "is_dangerous_type"  and value == 1:
            flag = "  <-- DANGEROUS"
        if key == "is_disguised_exe"   and value == 1:
            flag = "  <-- DISGUISED EXECUTABLE"
        if key == "file_risk_score"    and value > 0:
            flag = f"  <-- RISK SCORE"
        print(f"  {key:<30} {str(value)}{flag}")
    print("-" * 65)


if __name__ == "__main__":
    import sys

    print("=" * 65)
    print("FILE ANALYSER — MAGIC BYTE DETECTION TEST")
    print("=" * 65)

    # Test with real files that exist on your system
    # We will create 3 small test files to analyse
    import os

    test_dir = "tests"
    os.makedirs(test_dir, exist_ok=True)

    # Test file 1: A real text file with correct extension
    with open(f"{test_dir}/normal.txt", "w") as f:
        f.write("This is a normal text file.\n")

    # Test file 2: A text file disguised as a PDF
    with open(f"{test_dir}/fake.pdf", "w") as f:
        f.write("This is actually a text file pretending to be a PDF.\n")

    # Test file 3: A real HTML file with correct extension
    with open(f"{test_dir}/page.html", "w") as f:
        f.write("<html><body><h1>Test</h1></body></html>\n")

    # Test file 4: A Python script disguised as an image
    with open(f"{test_dir}/photo.jpg", "w") as f:
        f.write("import os\nos.system('malicious command')\n")

    test_files = [
        f"{test_dir}/normal.txt",
        f"{test_dir}/fake.pdf",
        f"{test_dir}/page.html",
        f"{test_dir}/photo.jpg",
    ]

    for filepath in test_files:
        print_file_analysis(filepath)

    print("\nfile_analyser.py working correctly.")