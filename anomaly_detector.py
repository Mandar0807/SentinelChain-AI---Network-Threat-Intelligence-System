import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest

MODEL_PATH = "models/anomaly_model.pkl"

# ── Feature extraction from traffic summary ────────────────────────────────
def extract_features(summary: dict) -> list:
    return [
        summary.get("total_packets",    0),
        summary.get("total_bytes",      0),
        summary.get("unique_dst_ips",   0),
        summary.get("bytes_per_second", 0),
        summary.get("packets_per_sec",  0),
        summary.get("tcp_syn_count",    0),
        summary.get("avg_packet_size",  0),
    ]


# ── Generate synthetic normal traffic samples ──────────────────────────────
def generate_normal_samples(n: int = 1000) -> np.ndarray:
    np.random.seed(42)
    samples = []
    for _ in range(n):
        # Normal web browsing simulation
        total_packets    = np.random.randint(5,   500)
        total_bytes      = np.random.randint(500, 500000)
        unique_dst_ips   = np.random.randint(1,   50)
        bytes_per_second = np.random.uniform(100, 50000)
        packets_per_sec  = np.random.uniform(0.5, 50)
        tcp_syn_count    = np.random.randint(0,   int(total_packets * 0.1) + 1) # Normal is < 10% SYN
        avg_packet_size  = np.random.randint(40,  1500)

        samples.append([
            total_packets,
            total_bytes,
            unique_dst_ips,
            bytes_per_second,
            packets_per_sec,
            tcp_syn_count,
            avg_packet_size
        ])

    return np.array(samples)


# ── Train the IsolationForest ──────────────────────────────────────────────
def train(n_samples: int = 1000):
    print("[anomaly] Generating normal traffic samples...")
    X_normal = generate_normal_samples(n_samples)

    print(f"[anomaly] Training IsolationForest on {n_samples} samples...")
    model = IsolationForest(
        n_estimators  = 100,
        contamination = 0.05,
        random_state  = 42,
    )
    model.fit(X_normal)

    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[anomaly] Model saved to {MODEL_PATH}")
    return model


def load_model():
    if not os.path.exists(MODEL_PATH):
        print("[anomaly] No model found — training now...")
        return train()
    return joblib.load(MODEL_PATH)


# ── Smart Attack Detection Rules ─────────────────────────────────────────
def _rule_based_check(summary: dict) -> tuple:
    """
    Looks for specific attack signatures: Port Scans, SYN Floods, Exfiltration.
    """
    reasons = []
    is_suspicious = False

    pkts = summary.get("total_packets", 0)
    syns = summary.get("tcp_syn_count", 0)
    avg_size = summary.get("avg_packet_size", 0)
    connections = summary.get("active_connections", [])

    # 1. SYN Flood Detection (DDoS)
    # If a large burst of traffic is mostly just TCP SYN connection requests
    if pkts > 100 and (syns / pkts) > 0.5:
        reasons.append(f"SYN Flood Detected: {syns} SYN packets out of {pkts} total packets. The website may be trying to launch a DDoS attack.")
        is_suspicious = True

    # 2. Port Scan Detection
    # If the website hits 10+ different ports on a SINGLE server, that's a scan.
    for conn in connections:
        if conn.get("port_count", 0) > 10:
            reasons.append(f"Port Scan Detected: Scanning {conn['port_count']} different ports on {conn['hostname']} ({conn['ip']}).")
            is_suspicious = True

    # 3. Data Exfiltration
    # If the website is secretly uploading massive amounts of data at maximum packet size
    bps = summary.get("bytes_per_second", 0)
    if avg_size > 1300 and bps > 500000: # Sustained 500 KB/s of max-size packets
        reasons.append(f"Possible Data Exfiltration: Uploading large blocks of data ({round(bps/1000)} KB/s, Avg packet size: {avg_size} bytes).")
        is_suspicious = True

    # 4. Connection Spam
    # Too many unique background servers contacted rapidly (e.g. Botnet / Scanner)
    ips = summary.get("unique_dst_ips", 0)
    if ips > 100:
        reasons.append(f"Suspicious Networking: Contacted {ips} unique servers in a short time. Possible network scanner or ad-fraud.")
        is_suspicious = True

    return is_suspicious, reasons


# ── Main prediction function ───────────────────────────────────────────────
def analyse_traffic(summary: dict) -> dict:
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

        # Normalize score
        normalized     = round((1 - (anomaly_score + 0.5)) * 100, 1)
        normalized     = max(0, min(100, normalized))

        result["anomaly_score"] = normalized
        result["ml_verdict"]    = "ANOMALY" if ml_prediction == -1 else "NORMAL"

    except Exception as e:
        print(f"[anomaly] ML error: {e}")
        # If shape error (from old model), retrain instantly
        if "shape" in str(e).lower() or "features" in str(e).lower():
            train()
            return analyse_traffic(summary)
        result["ml_verdict"] = "UNKNOWN"

    # ── Layer 2: Rule-based attack signatures ──────────────────────────────
    rule_suspicious, rule_reasons = _rule_based_check(summary)
    result["rule_verdict"] = "ANOMALY" if rule_suspicious else "NORMAL"
    result["flags"]        = rule_reasons

    # ── Final verdict ──────────────────────────────────────────────────────
    if result["ml_verdict"] == "ANOMALY" or result["rule_verdict"] == "ANOMALY":
        result["is_anomaly"] = True
        result["verdict"]    = "THREAT DETECTED" if rule_suspicious else "ANOMALY DETECTED"
        result["confidence"] = 99 if rule_suspicious else round(result["anomaly_score"], 1)
    else:
        result["is_anomaly"] = False
        result["verdict"]    = "NORMAL"
        result["confidence"] = round(100 - result["anomaly_score"], 1)

    return result