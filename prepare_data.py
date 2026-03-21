import pandas as pd
import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from url_analyser import analyse_url

PHISHING_CSV = "data/phishing.csv"
SAFE_CSV     = "data/safe.csv"
OUTPUT_CSV   = "data/dataset.csv"

MAX_PHISHING = 3000
MAX_SAFE     = 3000


def load_phishing_urls(filepath: str) -> list:
    print(f"\n[1/4] Loading phishing URLs from {filepath}...")
    try:
        df = pd.read_csv(filepath, on_bad_lines="skip")
        print(f"      Columns found: {list(df.columns)}")

        url_col = None
        for col in df.columns:
            if col.strip().lower() == "url":
                url_col = col
                break

        if url_col is None:
            url_col = df.columns[0]
            print(f"      'url' column not found, using: {url_col}")

        urls = df[url_col].dropna().tolist()
        urls = [str(u).strip() for u in urls if str(u).startswith("http")]
        print(f"      Loaded {len(urls)} phishing URLs")
        return urls[:MAX_PHISHING]

    except Exception as e:
        print(f"      ERROR: {e}")
        return []


def load_safe_urls(filepath: str) -> list:
    print(f"\n[2/4] Loading safe URLs from {filepath}...")
    try:
        df = pd.read_csv(filepath, on_bad_lines="skip")
        print(f"      Columns found: {list(df.columns)}")

        # Majestic Million has a 'Domain' column
        domain_col = None
        for col in df.columns:
            if col.strip().lower() == "domain":
                domain_col = col
                break

        if domain_col is None:
            # fallback to last column
            domain_col = df.columns[-1]
            print(f"      'Domain' column not found, using: {domain_col}")

        domains = df[domain_col].dropna().tolist()
        urls = [f"https://{str(d).strip()}"
                for d in domains if str(d).strip() and "." in str(d)]
        print(f"      Loaded {len(urls)} safe URLs")
        return urls[:MAX_SAFE]

    except Exception as e:
        print(f"      ERROR: {e}")
        return []


def extract_features(urls: list, label: int, label_name: str) -> list:
    rows   = []
    errors = 0
    total  = len(urls)
    step   = 3 if label == 1 else 4

    print(f"\n[{step}/4] Extracting features from {total} {label_name} URLs...")

    for i, url in enumerate(urls):
        if (i + 1) % 250 == 0 or (i + 1) == total:
            print(f"      Progress: {i+1}/{total}", end="\r")
        try:
            features        = analyse_url(url)
            features["label"] = label
            features["url"]   = url
            rows.append(features)
        except Exception:
            errors += 1
            continue

    print(f"\n      Done — {len(rows)} rows, {errors} errors skipped")
    return rows


def main():
    print("=" * 60)
    print("DATA PREPARATION — BUILDING TRAINING DATASET")
    print("=" * 60)

    start = time.time()

    # ── Load ───────────────────────────────────────────────────
    phishing_urls = load_phishing_urls(PHISHING_CSV)
    safe_urls     = load_safe_urls(SAFE_CSV)

    if not phishing_urls:
        print("\nERROR: No phishing URLs loaded.")
        print("Make sure data/phishing.csv exists and has a 'url' column.")
        return

    if not safe_urls:
        print("\nERROR: No safe URLs loaded.")
        print("Make sure data/safe.csv exists and has a 'Domain' column.")
        return

    # ── Extract features ───────────────────────────────────────
    phishing_rows = extract_features(phishing_urls, label=1,
                                     label_name="phishing")
    safe_rows     = extract_features(safe_urls,     label=0,
                                     label_name="safe")

    # ── Combine and save ───────────────────────────────────────
    all_rows   = phishing_rows + safe_rows
    df         = pd.DataFrame(all_rows)
    df_train   = df.drop(columns=["url"])
    df_inspect = df.copy()

    os.makedirs("data", exist_ok=True)
    df_train.to_csv(OUTPUT_CSV,                    index=False)
    df_inspect.to_csv("data/dataset_with_urls.csv", index=False)

    elapsed = round(time.time() - start, 1)

    # ── Summary ────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"DATASET SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total rows      : {len(df)}")
    print(f"  Phishing (1)    : {len(phishing_rows)}")
    print(f"  Safe (0)        : {len(safe_rows)}")
    print(f"  Features        : {len(df_train.columns) - 1}  (+1 label column)")
    print(f"  Output file     : {OUTPUT_CSV}")
    print(f"  Time taken      : {elapsed}s")
    print(f"\n  Columns in dataset:")
    for col in df_train.columns:
        print(f"    - {col}")
    print(f"{'=' * 60}")
    print(f"\nData preparation COMPLETE. Ready for model training.")


if __name__ == "__main__":
    main()
    