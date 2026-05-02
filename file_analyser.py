import os
import magic
import math
import zipfile
import tarfile
from collections import Counter

# ── Massively Expanded MIME to Extension Mapping ──────────────────────────
MIME_TO_EXTENSIONS = {
    # Documents
    "application/pdf":                        [".pdf"],
    "application/msword":                     [".doc"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
    "application/vnd.ms-excel":               [".xls"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"],
    "application/vnd.ms-powerpoint":          [".ppt"],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": [".pptx"],
    "application/rtf":                        [".rtf"],
    "application/epub+zip":                   [".epub"],
    
    # Archives
    "application/zip":                        [".zip", ".jar", ".docx", ".xlsx", ".pptx", ".apk"],
    "application/x-rar-compressed":           [".rar"],
    "application/x-rar":                      [".rar"],
    "application/x-tar":                      [".tar"],
    "application/gzip":                       [".gz", ".tgz"],
    "application/x-7z-compressed":            [".7z"],
    "application/x-bzip2":                    [".bz2"],
    "application/x-iso9660-image":            [".iso"],
    "application/java-archive":               [".jar"],
    
    # Executables & Libraries
    "application/x-dosexec":                  [".exe", ".dll", ".com", ".scr", ".sys"],
    "application/x-executable":               [".elf", ".out", ".bin"],
    "application/x-sharedlib":                [".so", ".dll"],
    "application/x-msdownload":               [".exe", ".dll", ".msi"],
    "application/x-mach-binary":              [".macho", ".dylib"],
    "application/vnd.microsoft.portable-executable": [".exe", ".dll"],
    
    # Text & Code
    "text/plain":                             [".txt", ".log", ".csv", ".py", ".js", ".md", ".ini", ".conf", ".json"],
    "text/html":                              [".html", ".htm"],
    "text/css":                               [".css"],
    "text/csv":                               [".csv"],
    "text/x-python":                          [".py", ".pyw"],
    "text/x-script.python":                   [".py"],
    "text/javascript":                        [".js", ".mjs"],
    "application/javascript":                 [".js"],
    "application/json":                       [".json"],
    "text/x-shellscript":                     [".sh", ".bash", ".zsh"],
    "text/x-php":                             [".php"],
    "text/x-ruby":                            [".rb"],
    "text/x-c":                               [".c", ".h"],
    "text/x-c++":                             [".cpp", ".hpp", ".cc", ".cxx"],
    
    # Images
    "image/jpeg":                             [".jpg", ".jpeg", ".jpe"],
    "image/png":                              [".png"],
    "image/gif":                              [".gif"],
    "image/bmp":                              [".bmp"],
    "image/webp":                             [".webp"],
    "image/svg+xml":                          [".svg"],
    "image/tiff":                             [".tiff", ".tif"],
    "image/x-icon":                           [".ico"],
    
    # Audio
    "audio/mpeg":                             [".mp3"],
    "audio/wav":                              [".wav"],
    "audio/x-wav":                            [".wav"],
    "audio/ogg":                              [".ogg"],
    "audio/midi":                             [".mid", ".midi"],
    "audio/webm":                             [".weba"],
    
    # Video
    "video/mp4":                              [".mp4"],
    "video/x-msvideo":                        [".avi"],
    "video/x-matroska":                       [".mkv"],
    "video/webm":                             [".webm"],
    "video/quicktime":                        [".mov"],
}

# ── Dangerous Types & Extensions ──────────────────────────────────────────
DANGEROUS_MIME_TYPES = [
    "application/x-dosexec",
    "application/x-executable",
    "application/x-msdownload",
    "application/vnd.microsoft.portable-executable",
    "application/x-sharedlib",
    "application/x-shellscript",
    "application/x-sh",
    "application/x-mach-binary",
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".com", ".scr", ".pif", ".bat", ".cmd", 
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", 
    ".msi", ".msp", ".hta", ".jar", ".py"
}

# ── Analysis Functions ────────────────────────────────────────────────────

def _calculate_entropy(filepath: str) -> float:
    """
    Calculates the Shannon entropy of a file to detect packing/encryption.
    Reads in chunks to handle very large files efficiently.
    Scale: 0.0 to 8.0. Normal files: 4.0-6.0. Packed/Encrypted: > 7.2.
    """
    try:
        counts = Counter()
        total_bytes = 0
        with open(filepath, 'rb') as f:
            while chunk := f.read(65536): # 64KB chunks
                counts.update(chunk)
                total_bytes += len(chunk)
                
        if total_bytes == 0:
            return 0.0
            
        entropy = 0.0
        for count in counts.values():
            p_x = count / total_bytes
            entropy += - p_x * math.log2(p_x)
            
        return round(entropy, 3)
    except Exception:
        return 0.0

def _inspect_archive(filepath: str, mime_type: str) -> dict:
    """
    Peeks inside ZIP or TAR archives without extracting them.
    Checks if there are any dangerous executables hiding inside.
    """
    archive_info = {
        "is_archive": 0,
        "file_count": 0,
        "contains_dangerous_file": 0,
        "dangerous_files_found": []
    }
    
    # Check ZIP
    if mime_type in ["application/zip", "application/epub+zip", "application/java-archive"] or zipfile.is_zipfile(filepath):
        archive_info["is_archive"] = 1
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                filenames = zf.namelist()
                archive_info["file_count"] = len(filenames)
                for name in filenames:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in DANGEROUS_EXTENSIONS:
                        archive_info["contains_dangerous_file"] = 1
                        archive_info["dangerous_files_found"].append(name)
        except Exception:
            pass # Corrupted or password-protected zip
            
    # Check TAR / TAR.GZ
    elif mime_type in ["application/x-tar", "application/gzip", "application/x-bzip2"] or tarfile.is_tarfile(filepath):
        archive_info["is_archive"] = 1
        try:
            with tarfile.open(filepath, 'r:*') as tf:
                # Use getnames() but limit to prevent memory exhaustion on malicious huge tars
                filenames = tf.getnames()
                if len(filenames) > 10000:
                    filenames = filenames[:10000]
                    
                archive_info["file_count"] = len(filenames)
                for name in filenames:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in DANGEROUS_EXTENSIONS:
                        archive_info["contains_dangerous_file"] = 1
                        archive_info["dangerous_files_found"].append(name)
        except Exception:
            pass

    return archive_info

def analyse_file(filepath: str) -> dict:
    """
    Takes a filepath and returns a comprehensive feature dictionary.
    Includes magic byte detection, entropy analysis, and deep archive inspection.
    """
    features = {}

    # ── Basic file info ────────────────────────────────────────────────────
    filename  = os.path.basename(filepath)
    extension = os.path.splitext(filename)[1].lower()

    features["filename"]           = filename
    features["extension"]          = extension
    
    try:
        features["file_size_bytes"] = os.path.getsize(filepath)
    except OSError:
        features["file_size_bytes"] = 0

    # ── Read real MIME type from magic bytes ───────────────────────────────
    try:
        mime_type = magic.from_file(filepath, mime=True)
        file_desc = magic.from_file(filepath)          # human-readable description
    except Exception as e:
        mime_type = "unknown"
        file_desc = str(e)

    features["detected_mime_type"] = mime_type
    features["file_description"]   = file_desc

    # ── Entropy Analysis ───────────────────────────────────────────────────
    entropy = _calculate_entropy(filepath)
    features["entropy"] = entropy
    features["is_highly_entropic"] = 1 if entropy > 7.2 else 0

    # ── Extension vs MIME type mismatch check ─────────────────────────────
    allowed_extensions = MIME_TO_EXTENSIONS.get(mime_type, [])

    if not allowed_extensions:
        # MIME type not in our map — flag as unknown but don't penalize heavily
        features["extension_mismatch"] = 0
        features["mismatch_detail"]    = (
            f"Unknown MIME type '{mime_type}' — cannot verify extension"
        )
    elif extension in allowed_extensions:
        features["extension_mismatch"] = 0
        features["mismatch_detail"]    = "Extension matches detected file type"
    else:
        # Check if the file is just an empty file which often gets identified weirdly
        if features["file_size_bytes"] == 0:
            features["extension_mismatch"] = 0
            features["mismatch_detail"] = "Empty file"
        else:
            features["extension_mismatch"] = 1
            features["mismatch_detail"]    = (
                f"DECLARED '{extension}' but file is actually '{mime_type}'"
            )

    # ── Dangerous type check ───────────────────────────────────────────────
    features["is_dangerous_type"]  = 1 if mime_type in DANGEROUS_MIME_TYPES else 0
    features["has_dangerous_ext"]  = 1 if extension in DANGEROUS_EXTENSIONS else 0

    # ── Executable disguised as something else ────────────────────────────
    features["is_disguised_exe"]   = (
        1 if (features["is_dangerous_type"] == 1 and features["has_dangerous_ext"] == 0)
        else 0
    )
    
    # ── Packed Malware Detection ───────────────────────────────────────────
    features["is_packed_executable"] = (
        1 if (features["is_dangerous_type"] == 1 and features["is_highly_entropic"] == 1)
        else 0
    )

    # ── Deep Archive Inspection ────────────────────────────────────────────
    archive_info = _inspect_archive(filepath, mime_type)
    features.update(archive_info)

    return features

if __name__ == "__main__":
    print("=" * 65)
    print("FILE ANALYSER — COMPREHENSIVE DETECTION TEST")
    print("=" * 65)
    print("This module is meant to be called by pre_check.py.")
    print("Run `python test_file_analyser.py` for full verification.")
    print("file_analyser.py successfully loaded.")