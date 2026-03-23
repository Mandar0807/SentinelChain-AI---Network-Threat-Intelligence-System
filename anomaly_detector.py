import numpy as np
import joblib
import os
import time
from sklearn.ensemble import IsolationForest

MODEL_PATH = "models/anomaly_model.pkl"

# ── Feature extraction from traffic summary ────────────────────────────────
def extract_features(summary: dict) -> list:
    """
    Converts a traffic summary dictionary from monitor.py
    into a flat feature vector for the IsolationForest model.
    """
    return [
        summary.get("total_packets",    0),
        summary.get("total_bytes",      0),
        summary.get("unique_dst_ips",   0),
        summary.get("bytes_per_second", 0),
        summary.get("packets_per_sec",  0),
    ]


# ── Generate synthetic normal traffic samples ──────────────────────────────
def generate_normal_samples(n: int = 1000) -> np.ndarray:
    """
    Creates synthetic examples of what normal background traffic looks like.
    Based on the real values we observed in Day 5:
      - 186 packets in 15 seconds (~12 packets/sec)
      - 27,001 bytes (~1800 bytes/sec)
      - 28 unique destination IPs

    We model normal traffic as low-volume, low-IP-count, steady rate.
    """
    np.random.seed(42)

    samples = []
    for _ in range(n):
        # Normal: low packet rate, few unique IPs, moderate bytes
        total_packets    = np.random.randint(5,   200)
        total_bytes      = np.random.randint(500, 30000)
        unique_dst_ips   = np.random.randint(1,   30)
        bytes_per_second = np.random.uniform(100, 3000)
        packets_per_sec  = np.random.uniform(0.5, 15)

        samples.append([
            total_packets,
            total_bytes,
            unique_dst_ips,
            bytes_per_second,
            packets_per_sec,
        ])

    return np.array(samples)


# ── Train the IsolationForest ──────────────────────────────────────────────
def train(n_samples: int = 1000):
    """
    Train IsolationForest on synthetic normal traffic samples.
    Save model to disk.
    """
    print("[anomaly] Generating normal traffic samples...")
    X_normal = generate_normal_samples(n_samples)

    print(f"[anomaly] Training IsolationForest on {n_samples} samples...")
    model = IsolationForest(
        n_estimators  = 100,
        contamination = 0.05,   # expect 5% anomalies in real data
        random_state  = 42,
    )
    model.fit(X_normal)

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[anomaly] Model saved to {MODEL_PATH}")
    return model


def load_model():
    """Load trained IsolationForest from disk."""
    if not os.path.exists(MODEL_PATH):
        print("[anomaly] No model found — training now...")
        return train()
    return joblib.load(MODEL_PATH)


# ── Threshold-based rules (layer 2 check) ─────────────────────────────────
def _rule_based_check(summary: dict) -> tuple:
    """
    Hard rules that flag obviously malicious traffic
    regardless of what the ML model says.
    Returns (is_suspicious, reason)
    """
    reasons = []

    bps  = summary.get("bytes_per_second", 0)
    pps  = summary.get("packets_per_sec",  0)
    ips  = summary.get("unique_dst_ips",   0)
    pkts = summary.get("total_packets",    0)

    # Exfiltration signature: very high outgoing data rate
    if bps > 50000:
        reasons.append(
            f"High data rate: {round(bps/1000, 1)} KB/s outgoing "
            f"(threshold: 50 KB/s)"
        )

    # Scanning / C2 signature: too many unique IPs
    if ips > 50:
        reasons.append(
            f"Contacting {ips} unique IPs "
            f"(threshold: 50) — possible scanning or C2 traffic"
        )

    # Burst traffic: very high packet rate
    if pps > 100:
        reasons.append(
            f"Packet burst: {round(pps, 1)} packets/sec "
            f"(threshold: 100) — possible flood"
        )

    # Sustained high volume
    if pkts > 2000:
        reasons.append(
            f"High packet volume: {pkts} packets captured — "
            f"sustained abnormal activity"
        )

    is_suspicious = len(reasons) > 0
    return is_suspicious, reasons


# ── Main prediction function ───────────────────────────────────────────────
def analyse_traffic(summary: dict) -> dict:
    """
    Main function called by monitor.py and Flask app.
    Takes a traffic summary dict, returns a threat assessment.
    """
    result = {
        "verdict"         : "NORMAL",
        "is_anomaly"      : False,
        "anomaly_score"   : 0.0,
        "confidence"      : 0,
        "flags"           : [],
        "ml_verdict"      : "NORMAL",
        "rule_verdict"    : "NORMAL",
    }

    if summary.get("total_packets", 0) == 0:
        result["verdict"]    = "NO DATA"
        result["confidence"] = 0
        return result

    # ── Layer 1: ML model ──────────────────────────────────────────────────
    try:
        model          = load_model()
        features       = extract_features(summary)
        X              = np.array([features])

        ml_prediction  = model.predict(X)[0]        # 1=normal, -1=anomaly
        anomaly_score  = model.score_samples(X)[0]  # lower = more anomalous

        # Normalize score to 0-100 (higher = more suspicious)
        normalized     = round((1 - (anomaly_score + 0.5)) * 100, 1)
        normalized     = max(0, min(100, normalized))

        result["anomaly_score"] = normalized
        result["ml_verdict"]    = "ANOMALY" if ml_prediction == -1 else "NORMAL"

    except Exception as e:
        print(f"[anomaly] ML error: {e}")
        result["ml_verdict"] = "UNKNOWN"

    # ── Layer 2: Rule-based check ──────────────────────────────────────────
    rule_suspicious, rule_reasons = _rule_based_check(summary)
    result["rule_verdict"] = "ANOMALY" if rule_suspicious else "NORMAL"
    result["flags"]        = rule_reasons

    # ── Final verdict: either layer can trigger alert ──────────────────────
    if result["ml_verdict"] == "ANOMALY" or result["rule_verdict"] == "ANOMALY":
        result["is_anomaly"] = True
        result["verdict"]    = "ANOMALY DETECTED"
        result["confidence"] = round(result["anomaly_score"], 1)
    else:
        result["is_anomaly"] = False
        result["verdict"]    = "NORMAL"
        result["confidence"] = round(100 - result["anomaly_score"], 1)

    return result


def print_result(summary: dict, result: dict):
    """Pretty print the anomaly detection result."""
    icon = "✗" if result["is_anomaly"] else "✓"
    print(f"\n{'=' * 55}")
    print(f"  ANOMALY DETECTION RESULT")
    print(f"{'=' * 55}")
    print(f"  Verdict        : [{icon}] {result['verdict']}")
    print(f"  ML verdict     : {result['ml_verdict']}")
    print(f"  Rule verdict   : {result['rule_verdict']}")
    print(f"  Anomaly score  : {result['anomaly_score']} / 100")
    print(f"  Confidence     : {result['confidence']}%")
    print(f"\n  Traffic stats:")
    print(f"    Packets      : {summary.get('total_packets', 0)}")
    print(f"    Bytes        : {summary.get('total_bytes', 0):,}")
    print(f"    Unique IPs   : {summary.get('unique_dst_ips', 0)}")
    print(f"    Bytes/sec    : {summary.get('bytes_per_second', 0)}")
    print(f"    Packets/sec  : {summary.get('packets_per_sec', 0)}")
    if result["flags"]:
        print(f"\n  Flags:")
        for flag in result["flags"]:
            print(f"    - {flag}")
    print(f"{'=' * 55}")


# ── Self test ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  ANOMALY DETECTOR — TRAINING + SELF TEST")
    print("=" * 55)

    # Train the model
    train()

    print("\n--- Test 1: Normal background traffic ---")
    normal_summary = {
        "total_packets"   : 186,
        "total_bytes"     : 27001,
        "unique_dst_ips"  : 28,
        "bytes_per_second": 1071.94,
        "packets_per_sec" : 7.38,
    }
    result = analyse_traffic(normal_summary)
    print_result(normal_summary, result)

    print("\n--- Test 2: Simulated data exfiltration ---")
    exfil_summary = {
        "total_packets"   : 3500,
        "total_bytes"     : 850000,
        "unique_dst_ips"  : 75,
        "bytes_per_second": 95000,
        "packets_per_sec" : 180,
    }
    result = analyse_traffic(exfil_summary)
    print_result(exfil_summary, result)

    print("\n--- Test 3: Borderline suspicious traffic ---")
    suspicious_summary = {
        "total_packets"   : 450,
        "total_bytes"     : 75000,
        "unique_dst_ips"  : 55,
        "bytes_per_second": 8000,
        "packets_per_sec" : 25,
    }
    result = analyse_traffic(suspicious_summary)
    print_result(suspicious_summary, result)

    print("\nanomalY_detector.py working correctly.")