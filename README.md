# DIODESHIELD 🛡️

> **AI-Based Cyber-Threat Detection for Unidirectional IP Traffic across Hardware Data Diodes**  
> *Smart India Hackathon PS-26145 | Organization: NTRO (National Technical Research Organisation)*

---

## 1. Executive Summary

**DIODESHIELD** is a passive, receive-side cyber-threat detection engine tailored specifically for Operational Technology (OT) and Industrial Control System (ICS) networks protected by a **hardware data diode** (one-way physical boundary).

In a strict data diode deployment:
* **Zero Transmission (Zero-TX)**: The receive network cannot send any packets back (no ACKs, no handshake, no ARP/ICMP probing, no return channel).
* **Metadata & Flow Analysis**: Threat detection must operate purely on unidirectional packet metadata and payload signatures arriving at the receiver.
* **Tamper-Evident Evidence**: Every detection must form an auditable, cryptographically chained evidence trail.

DIODESHIELD implements a **5-branch multi-model AI ensemble** with real-time **TreeSHAP explainability**, an **unbroken SHA-256 cryptographic evidence hash chain**, a **universal live packet capture engine** that monitors host/laptop IP flows without requiring administrative privileges, and an interactive **Web SOC Dashboard**.

---

## 2. System Architecture

```
                                  DATA DIODE BOUNDARY
                                (Strictly Unidirectional)
   [ OT Network (Tx) ] =====================================> [ DIODESHIELD Receiver (Rx) ]
   - Modbus / DNP3 / S7                                              |
   - Industrial Sensors                                              v
   - SCADA Telemetry                           +-----------------------------------------------+
                                               |             Live Ingestion Engine             |
                                               |  - Host/Laptop IP Traffic Sniffer (psutil)    |
                                               |  - Localhost UDP Diode Socket (:19001)        |
                                               |  - Baseline Modbus Polling Stream             |
                                               |  - Optional TShark / Wireshark Adapter        |
                                               +-----------------------------------------------+
                                                                     |
                                                                     v
                                               +-----------------------------------------------+
                                               |         Feature Engineering (32-dim)          |
                                               |  - Volumetric, Temporal, Spatial, Modbus OT   |
                                               +-----------------------------------------------+
                                                                     |
                                                                     v
                                               +-----------------------------------------------+
                                               |         5-Branch Multi-Model Ensemble         |
                                               |  1. XGBoost (Supervised Decision Trees)       |
                                               |  2. PyTorch LSTM (Temporal Sequence Anomaly)  |
                                               |  3. Spectral FFT (Beaconing / Frequency)      |
                                               |  4. Kitsune (Adaptive Baseline Autoencoder)   |
                                               |  5. Isolation Forest (Unsupervised Outlier)   |
                                               +-----------------------------------------------+
                                                                     |
                                                                     v
                                               +-----------------------------------------------+
                                               |            Ensemble Fusion & Risk             |
                                               |  - Dynamic Consensus & Disagreement Metric    |
                                               |  - TreeSHAP Feature Attribution Waterfall     |
                                               +-----------------------------------------------+
                                                                     |
                                                                     v
                                               +-----------------------------------------------+
                                               |      SHA-256 Tamper-Evident Hash Chain        |
                                               |  - Immutable Append-Only SQLite Evidence DB   |
                                               +-----------------------------------------------+
                                                                     |
                                                                     v
                                               +-----------------------------------------------+
                                               |            SOC Web Dashboard & API            |
                                               |  - Real-time WebSocket Feed                   |
                                               |  - One-Click Threat Injection Control Bar     |
                                               |  - Live Threat Inspector & Flow Analysis      |
                                               +-----------------------------------------------+
```

---

## 3. Key Capabilities

### A. 5-Branch AI Detection Ensemble
* **XGBoost Decision Trees**: Supervised classifier trained to detect rapid volumetric spikes, identity anomalies, and protocol deviations.
* **PyTorch LSTM Neural Network**: Temporal recurrent architecture tracking inter-arrival times ($IAT$), sequence patterns, and behavioral drift.
* **Spectral FFT Frequency Analyzer**: Discrete Fourier transforms identify periodic beacon rhythms (e.g. C2 beaconing) distinct from normal OT polling.
* **Kitsune Online Autoencoder**: Adapted KitNET neural network computing continuous reconstruction error against baseline feature distributions.
* **Isolation Forest**: High-dimensional ensemble isolating anomalous network feature combinations.

### B. TreeSHAP Explainability
* Live execution of TreeSHAP on tree ensembles provides mathematical feature attributions ($+$ positive contribution driving alert, $-$ negative contribution dampening risk).
* Guaranteed visibility into *why* the model made a determination (e.g. `packets_per_sec: +2.16`, `udp_burst_score: +0.20`).

### C. Universal Live Capture (Works on Any Machine)
* **Real Laptop/Host IP Monitoring**: Uses `psutil` socket sampling to capture real active network flows (TCP, UDP, web, DNS) on your laptop without requiring administrator rights or Npcap drivers.
* **Loopback UDP Diode Receiver**: Listens on port `19001` with `SO_REUSEADDR` to receive simulated hardware diode bursts.
* **Baseline OT Stream**: Synthesizes continuous Modbus/TCP polling frames (`10.0.0.7` &rarr; `10.0.0.8:502`) to maintain normal industrial baseline telemetry.
* **TShark Adapter**: Seamlessly activates if TShark/Wireshark is detected.

### D. Cryptographic SHA-256 Hash Chain
* Every alert computes:
  $$\text{Evidence Hash} = \text{SHA256}(\text{previous\_hash} + \text{canonical\_payload} + \text{timestamp})$$
* Any retroactive tampering or deletion of alert records breaks the cryptographic hash link and triggers instant tampering detection in `/api/integrity`.

### E. Interactive Web SOC Dashboard
* **One-Click Threat Injection**: Directly test threat categories from the dashboard header (`[⚡ UDP Flood]`, `[⚡ IP Spoof]`, `[⚡ Alteration]`, `[⚡ C2 Beacon]`, `[⚡ OT Recon]`).
* **Live Threat Inspector**: Auto-tracks incoming alerts with 5-model voting bars, TreeSHAP waterfall charts, policy reasons, and verification badges.
* **Flow Analysis**: Real-time table of live network flows and anomaly scores.
* **Zero External CDNs**: Pure HTML5/Canvas/CSS running offline without external dependencies.

---

## 4. Prerequisites

* **Python 3.10, 3.11, 3.12, 3.13, or 3.14**
* Windows (PowerShell), Linux, or macOS
* Modern web browser (Chrome, Edge, Firefox, Safari)

---

## 5. Step-by-Step Setup & Running Guide

### Step 1: Clone the Repository
```bash
git clone https://github.com/Puneeth-S88/diodeshield-demo-artifacts.git
cd diodeshield-demo-artifacts
```

### Step 2: Create and Activate Virtual Environment
**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS (Bash):**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
pip install -e .
```
*(Or use `uv pip install -r requirements.txt` for ultra-fast package installation).*

### Step 4: Calibrate & Train Model Artifacts
Generate model weights and calibration metadata:
```bash
python training/train_all_models.py --synthetic
```
*Output*: Generates calibrated model files in `models/` (`xgboost.json`, `lstm.pt`, `fft.json`, `kitsune.json`, `isolation_forest.joblib`, `provenance.json`).

---

## 6. Running the System

### Option A: Launch the Full Web SOC Dashboard (Recommended)

Start the DIODESHIELD backend and live packet capture service:
```powershell
# Windows PowerShell
.\.venv\Scripts\python.exe -m uvicorn diodeshield.api.main:app --host 0.0.0.0 --port 8000
```
```bash
# Linux / macOS
uvicorn diodeshield.api.main:app --host 0.0.0.0 --port 8000
```

Open your browser at:
```
http://localhost:8000/dashboard/
```

#### What you will see:
1. **`● LIVE CAPTURE ACTIVE`** green badge ticking upward with live packet ingest counters.
2. Real laptop/host network flows populating under the **Flow Analysis** tab.
3. Click any **One-Click Threat Injection** button (`[⚡ UDP Flood]`, `[⚡ IP Spoof]`, `[⚡ Alteration]`, `[⚡ C2 Beacon]`, `[⚡ OT Recon]`):
   * An alert immediately appears at the top of the table.
   * The **Live Threat Inspector** on the right automatically displays model consensus, TreeSHAP feature attributions, and SHA-256 evidence chain verification.

---

### Option B: One-Command 90-Second Live Replay Demo

To run an automated sequence evaluating normal baseline, C2 beaconing, industrial reconnaissance, Modbus protocol anomalies, and cryptographic hash verification:

**Windows PowerShell:**
```powershell
powershell -ExecutionPolicy Bypass -File demo.ps1
```

**Linux / macOS:**
```bash
chmod +x demo.sh
./demo.sh
```

---

### Option C: Threat Evaluation Lab Scripts

You can run individual attack simulation scripts from a separate terminal while the dashboard is running:

#### 1. UDP Volumetric Flood Burst:
```powershell
python scripts/udp_flood_lab.py --packets 500 --rate 250
```
*Simulates high-rate datagram bursts over loopback socket (`127.0.0.1:19001`).*

#### 2. IP Identity Spoofing:
```powershell
python scripts/offline_threat_lab.py --scenario spoof --count 1500 --batch-size 250
```
*Evaluates detection of virtual source identity rotation across unidirectional boundaries.*

#### 3. Packet / Checksum Alteration:
```powershell
python scripts/offline_threat_lab.py --scenario altered --count 1500 --batch-size 250
```
*Evaluates payload tampering and checksum integrity detection.*

#### 4. Volumetric Flood (Metadata Stream):
```powershell
python scripts/offline_threat_lab.py --scenario flood --count 1500 --batch-size 250
```

#### 5. Verify Database Cryptographic Hash Chain:
```powershell
python -c "from diodeshield.db import Repository; print(Repository().verify_integrity())"
```

---

## 7. Verification & Automated Test Suites

Run the complete test suite to verify code quality, model inference, and tamper detection:

```powershell
# 1. Pytest Unit & Integration Tests (14 passing tests)
pytest -q

# 2. Master End-to-End Validation
python tests/validate_all.py

# 3. Determinism & Regression Suite
python tests/regression.py
```

---

## 8. REST API Reference

The interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | System sensor availability, model training status, and DB state |
| `GET` | `/api/capture-status` | Live packet capture state, mode, packet counter, and error state |
| `GET` | `/api/alerts` | Paginated alerts with severity, category, and IP filtering |
| `GET` | `/api/alerts/{id}/validation` | Full alert detail, 5-model votes, TreeSHAP attributions, hash verification |
| `GET` | `/api/traffic` | Real-time unidirectional network flow telemetry |
| `GET` | `/api/models` | Metadata and status of the 5 AI model branches |
| `GET` | `/api/integrity` | Verifies unbroken continuity of the SHA-256 evidence chain |
| `POST` | `/api/simulator/inject` | Injects synthetic or threat scenarios (`flood`, `spoof`, `altered`, `beacon`, `recon`) |
| `POST` | `/api/simulator/toggle_capture` | Toggles live packet capture on/off |
| `WS` | `/ws/alerts` | Real-time WebSocket push feed for alerts and heartbeat telemetry |

---

## 9. Project Directory Structure

```
diodeshield-demo-artifacts/
├── configs/
│   └── default.yaml               # Engine configuration (window size, fusion weights, thresholds)
├── dashboard/
│   └── index.html                 # Standalone SOC Web Dashboard (Vanilla JS, Canvas, CSS)
├── data/
│   └── diodeshield.db             # SQLite WAL-mode evidence repository & hash chain
├── demo.ps1                       # Windows 90-second automated demo script
├── demo.sh                        # Linux/macOS automated demo script
├── diodeshield/
│   ├── api/main.py                # FastAPI REST & WebSocket server
│   ├── capture/live.py            # Multi-mode live capture (psutil, UDP socket, TShark)
│   ├── db.py                      # SQLite Repository with WAL mode & auto-migration
│   ├── explainability.py          # TreeSHAP & feature attribution engine
│   ├── features/builder.py        # 32-dimensional OT feature extractor
│   ├── fusion.py                  # Weighted multi-branch score fusion
│   ├── integrity.py               # SHA-256 tamper-evident hash chain implementation
│   ├── models/                    # Model adapters (XGBoost, LSTM, FFT, Kitsune, IsoForest)
│   ├── pipeline.py                # Core detection pipeline orchestration
│   └── risk.py                    # Dual-consensus risk evaluation & policy rules
├── models/                        # Serialized model weights & provenance manifest
├── requirements.txt               # Complete dependencies specification
├── pyproject.toml                 # Package configuration
├── scripts/
│   ├── offline_threat_lab.py      # Offline threat scenario evaluation harness
│   └── udp_flood_lab.py           # Loopback socket UDP flood simulation harness
├── tests/                         # Pytest suite, regression tests, and full validator
└── training/                      # Multi-model training and synthetic generation scripts
```

---

## 10. Operational Constraints & Ethics

* **Passive Observation**: DIODESHIELD strictly adheres to data diode boundaries. It never transmits packets into protected industrial zones.
* **Controlled Mitigation**: Automated host firewall actions are disabled by default. If enabled on Windows (`DIODESHIELD_FIREWALL_BLOCKING=true`), explicit confirmation (`confirm=true`) is required and all actions are recorded to an append-only audit log.
* **Synthetic Evaluation Notice**: Built-in baseline models are trained on reproducible evaluation datasets for demonstration. Production training uses a fail-closed schema contract (`training/DATASET_CONTRACT.md`) that rejects unverified datasets.

---

## 11. License

Apache 2.0. Developed for the Smart India Hackathon (SIH0145 / NTRO PS-26145).


