# ThreatShield — AI + Blockchain Threat Detection System

A cybersecurity web application that detects malicious URLs and files
using machine learning and monitors network traffic for data exfiltration
in real time. All threat events are permanently logged to an Ethereum
blockchain for tamper-proof forensic integrity.

![ThreatShield Dashboard](screenshots/scan.png)

---

## Features

- **AI-Powered URL Analysis** — Decision Tree classifier trained on
  PhishTank dataset with 99.4% accuracy
- **File Threat Detection** — Magic byte analysis detects disguised
  executables regardless of file extension
- **Live Network Monitoring** — Scapy-based packet capture with
  IsolationForest anomaly detection
- **Blockchain Logging** — All threats logged to Ethereum smart contract
  (Ganache) — immutable, tamper-proof records
- **Responsive Dashboard** — Dark-themed Bootstrap 5 web interface

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, Flask |
| Machine Learning | scikit-learn (Decision Tree, IsolationForest) |
| Packet Capture | Scapy |
| Blockchain | Solidity, web3.py, Ganache |
| Frontend | Bootstrap 5, JavaScript |
| File Analysis | python-magic |

---

## Project Structure
```
threat_detection/
├── app.py                  # Flask web application
├── pre_check.py            # Pre-execution engine (Stage 1)
├── url_analyser.py         # URL feature extraction
├── file_analyser.py        # File magic byte analysis
├── model.py                # Decision Tree training and prediction
├── monitor.py              # Live packet capture (Stage 2)
├── anomaly_detector.py     # IsolationForest anomaly detection
├── blockchain.py           # Ethereum blockchain logging
├── contract_config.py      # Deployed contract address and ABI
├── prepare_data.py         # Dataset preparation script
├── contracts/
│   └── ThreatLog.sol       # Solidity smart contract
├── models/
│   ├── threat_model.pkl    # Trained Decision Tree model
│   └── anomaly_model.pkl   # Trained IsolationForest model
├── data/                   # Training datasets (not in repo)
├── templates/              # Flask HTML templates
└── static/                 # CSS and JavaScript
```

---

## Setup Instructions

### Prerequisites
- Python 3.10+
- Ganache Desktop — https://trufflesuite.com/ganache/
- Npcap (Windows) — https://npcap.com/#download
- Run VS Code / terminal as Administrator

### Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/threat-detection-system.git
cd threat-detection-system

# Install dependencies
pip install scapy requests python-magic scikit-learn web3 flask pandas numpy joblib

# Windows only
pip install python-magic-bin
```

### Dataset Preparation
```bash
# Download PhishTank dataset to data/phishing.csv
# Download Majestic Million to data/safe.csv
# Then run:
python prepare_data.py
python model.py
```

### Blockchain Setup

1. Open Ganache → Quickstart Ethereum
2. Open Remix IDE → https://remix.ethereum.org
3. Load `contracts/ThreatLog.sol`
4. Compile with Solidity 0.8.0, EVM version: paris
5. Deploy using Dev - Ganache Provider
6. Copy contract address to `contract_config.py`

### Run the Application
```bash
# Must run as Administrator for packet capture
python app.py
```

Open browser at `http://localhost:5000`

---

## Screenshots

### Scan Page
![Scan](screenshots/scan.png)

### Result Page
![Result](screenshots/result.png)

### Monitor Page
![Monitor](screenshots/monitor.png)

### Blockchain Logs
![Logs](screenshots/logs.png)

---

## How It Works

### Stage 1 — Pre-Execution Analysis
1. User submits a URL or file
2. Feature extractor pulls 18 security signals from the URL
3. Trained Decision Tree classifies as Safe / Suspicious / Malicious
4. If threat detected → auto-logged to blockchain

### Stage 2 — Runtime Monitoring
1. User starts the network monitor
2. Scapy captures all outgoing packets in a background thread
3. Traffic aggregated every 10 seconds
4. IsolationForest detects anomalies vs normal baseline
5. If anomaly detected → alert shown + logged to blockchain

### Blockchain Logging
Every detected threat is written to a Solidity smart contract on
a local Ethereum blockchain. Records include file hash, threat type,
source, verdict, risk score, and timestamp. Records are permanent
and cannot be altered.

---

## Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | 99.42% |
| Precision | 99.83% |
| Recall | 99.00% |
| F1 Score | 99.41% |

Trained on 10,000 URLs — 5,000 phishing (PhishTank) +
5,000 legitimate (Majestic Million).

---

## Future Enhancements

- Browser extension integration
- Cloud deployment (AWS / Heroku)
- Advanced deep learning models
- Real-time dashboard charts
- Email alerts for detected threats