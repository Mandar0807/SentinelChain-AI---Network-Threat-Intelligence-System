import os
import hashlib
import threading
from flask import (Flask, render_template, request,
                   redirect, url_for, jsonify)

from pre_check       import analyse
from monitor         import (start_monitoring, stop_monitoring,
                              get_status, get_traffic_summary)
from anomaly_detector import analyse_traffic
from blockchain      import log_threat, get_all_logs, get_log_count

app = Flask(__name__)
app.secret_key = "threatdetection2024"

# Folder for uploaded files
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Store last scan result in memory (simple approach)
last_result = {}


# ── Page 1: Scan / Home ────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ── Page 2: Analyse URL or File ────────────────────────────────────────────
@app.route("/analyse", methods=["POST"])
def analyse_input():
    global last_result

    input_type = request.form.get("input_type", "url")

    if input_type == "url":
        url = request.form.get("url", "").strip()
        if not url:
            return redirect(url_for("index"))
        result = analyse(url)

    else:
        # File upload
        if "file" not in request.files:
            return redirect(url_for("index"))
        file = request.files["file"]
        if file.filename == "":
            return redirect(url_for("index"))

        # Save uploaded file
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        result = analyse(filepath)

    # Auto-log to blockchain if malicious or suspicious
    if result.get("verdict") in ["MALICIOUS", "SUSPICIOUS"]:
        try:
            threat_type = "URL_THREAT" if result["input_type"] == "url" \
                          else "FILE_THREAT"
            log_threat(
                threat_type = threat_type,
                source      = result["input"],
                verdict     = result["verdict"],
                risk_score  = int(result.get("risk_score", 0))
            )
        except Exception as e:
            print(f"[app] Blockchain log failed: {e}")

    last_result = result
    return render_template("result.html", result=result)


# ── Page 3: Monitor ────────────────────────────────────────────────────────
@app.route("/monitor")
def monitor_page():
    return render_template("monitor.html")


@app.route("/monitor/start", methods=["POST"])
def monitor_start():
    start_monitoring()
    return jsonify({"status": "started"})


@app.route("/monitor/stop", methods=["POST"])
def monitor_stop():
    stop_monitoring()
    # Analyse final traffic and log if anomaly
    summary = get_traffic_summary()
    result  = analyse_traffic(summary)
    if result["is_anomaly"]:
        try:
            log_threat(
                threat_type = "NETWORK_ANOMALY",
                source      = "Runtime network monitor",
                verdict     = "ANOMALY DETECTED",
                risk_score  = int(result.get("anomaly_score", 75))
            )
        except Exception as e:
            print(f"[app] Blockchain log failed: {e}")
    return jsonify({"status": "stopped", "anomaly": result["is_anomaly"]})


@app.route("/monitor/status")
def monitor_status():
    status  = get_status()
    summary = get_traffic_summary()
    result  = analyse_traffic(summary)
    return jsonify({
        **status,
        "verdict"      : result["verdict"],
        "is_anomaly"   : result["is_anomaly"],
        "anomaly_score": result["anomaly_score"],
        "flags"        : result["flags"],
        "top_ips"      : summary.get("top_destinations", []),
    })


# ── Page 4: Blockchain Logs ────────────────────────────────────────────────
@app.route("/logs")
def logs_page():
    try:
        logs  = get_all_logs()
        count = get_log_count()
    except Exception as e:
        logs  = []
        count = 0
        print(f"[app] Blockchain error: {e}")
    return render_template("logs.html", logs=logs, count=count)


if __name__ == "__main__":
    app.run(debug=True, port=5000)