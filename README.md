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

## 1.1 Update History

### 2026-09-16 22:45 IST

* Pushed the complete live-capture and dashboard refactor to the
  `rudreshark-rebuild-network-dashboard` branch.
* Added Scapy/Npcap receive-only capture with `sniff(store=False, prn=...)`,
  bounded queue processing, packet counters, byte counters, drop counters, and
  capture engine status.
* Added a native Windows-compatible fallback using a non-blocking
  `select.select()` loop with multiple UDP listeners and a TCP server/client
  event path.
* Unified Scapy packets and native socket buffers into the same `TrafficEvent`
  schema, including timestamps, endpoints, protocol, packet length, payload
  metadata, and direction.
* Rebuilt the dashboard around live packet metrics, alerts, flows, model
  consensus, evidence-chain status, AI explanations, speech controls, and
  printable reports using the white SOC theme.
* Removed offensive/demo traffic generators and simulator scripts from the
  runtime and documentation.
* Added capture configuration variables:
  `DIODESHIELD_CAPTURE_ENGINE`, `DIODESHIELD_NATIVE_BIND_HOST`,
  `DIODESHIELD_NATIVE_UDP_PORTS`, and `DIODESHIELD_NATIVE_TCP_PORT`.
* Verified the implementation with live UDP/TCP native-capture checks and the
  existing 49-test regression suite.
* Confirmed Npcap is installed and running on the development Windows host;
  Scapy is capturing from a real `\\Device\\NPF_*` interface.

### 2026-09-16 23:42 IST

* Retrained all five existing model branches without changing application
  source code, project structure, feature definitions, or runtime interfaces.
* Training corpus: 1,000 rows from the repository's verified public embedded
  network anomaly dataset, 568 benign windows extracted from the supplied
  `4SICS-GeekLounge-151020.pcap`, and 200 labeled BENIGN/DDoS flows from the
  public CIC-IDS2017 subset at
  `https://huggingface.co/datasets/NGCong/CI-CIDS2017`.
* Final corpus size: 1,768 rows and 60 existing numeric feature columns.
* Dataset checksum recorded in the model report:
  `e7be00cb46de3893fb8918c336dc126b5b18862b51f9ab7cff82fbe63fd1a6d0`.
* Updated only the generated artifacts in `models/`: XGBoost, LSTM, FFT,
  Kitsune, Isolation Forest, provenance, and the production training report.
* Final held-out metrics: XGBoost ROC-AUC `0.8523` and precision `0.6552`;
  LSTM ROC-AUC `0.7486`; FFT precision `0.2857`; Kitsune precision `0.4286`;
  Isolation Forest precision `0.2895`.
* All five trained artifacts were loaded successfully after training.
  Metrics are validation results, not a guarantee of production detection
  accuracy; additional representative labeled traffic is required before
  relying on the ensemble for operational decisions.

### 2026-09-17 01:16 IST

* Added category-aware live severity gating: only a strong UDP flood or
  repeated source-identity mismatch can produce `CRITICAL`; model disagreement,
  periodicity, fan-out, and protocol irregularities are capped at `WARNING`.
* Suppressed non-persistent `INFO`/`LOW` windows from becoming stored alerts,
  reducing normal-live-traffic noise while retaining persistent warnings.
* Retrained XGBoost, LSTM, FFT, Kitsune, and Isolation Forest using the
  verified 1,768-row corpus and preserved the existing 60-feature schema.
* Latest validation metrics: XGBoost ROC-AUC `0.8523` / F1 `0.5672`;
  LSTM ROC-AUC `0.7150` / F1 `0.4444`; FFT ROC-AUC `0.5793`;
  Kitsune ROC-AUC `0.5079`; Isolation Forest ROC-AUC `0.5493`.
* Training remained metadata-only and defensive; no packet generation,
  injection, exploit script, or application structure change was introduced.

### 2026-09-17 01:26 IST

* Added a dashboard capture control that calls the existing receive-only
  `/api/capture/start` and `/api/capture/stop` endpoints; it can pause and
  resume live capture and analysis without generating traffic.
* Changed severity policy so IP spoofing is `HIGH`, while confirmed high-rate
  UDP flooding is the only category eligible for `CRITICAL`.
* Overview `HIGH` and `CRITICAL` KPI counts now deduplicate repeated alerts by
  source IP; individual alert records and evidence remain preserved.

### 2026-09-17 01:31 IST

* Normalized legacy dashboard read-model severity values to the current policy:
  persisted non-UDP-flood `CRITICAL` rows now display as `WARNING`, legacy
  IP-spoofing rows display as `HIGH`, and only `UDP_FLOOD` remains `CRITICAL`.
* Original stored alert evidence and database rows were preserved; this is a
  presentation/triage correction for historical records.

### 2026-09-17 01:40 IST

* Repositioned the live data-diode animation into one centered horizontal
  pipeline: local interfaces → red packet pipe → DIODESHIELD AI sensor → blue
  packet pipe → analysis layer.
* Kept the animation limited to the data-diode boundary card; no capture,
  detection, model, or dashboard behavior was changed.

### 2026-09-17 03:41 IST

* Added explicit analyst-controlled `Block IP` and `Unblock` actions to alert
  rows and connected them to Windows Firewall rule management.
* Actions validate IPv4/IPv6 input, reject loopback/unspecified/multicast
  addresses, use deterministic DIODESHIELD rule names, and write audit events.
* Firewall actions are never automatic. They require
  `DIODESHIELD_FIREWALL_BLOCKING=true` and an administrator-launched API; the
  safe default returns a clear permission error instead of changing network
  state.

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
                                               |  - Scapy/Npcap live interface capture        |
                                               |  - Native UDP/TCP select-loop fallback       |
                                               |  - Unified TrafficEvent normalization        |
                                               |  - Optional TShark / Zeek ingestion          |
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
                                               |  - Live Threat Inspector & Flow Analysis      |
                                               |  - AI explanations and printable reports     |
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
* **Scapy/Npcap engine**: Captures live packets from the selected Windows, Linux, or macOS interface with `store=False`.
* **Native fallback engine**: Uses non-blocking UDP/TCP listeners when a raw packet provider is unavailable.
* **No generated traffic**: Runtime analytics consume observed traffic only; no attack payloads or traffic generators are included.
* **TShark/Zeek compatibility**: Existing ingestion adapters can be used for deployments that standardize on those tools.

### D. Cryptographic SHA-256 Hash Chain
* Every alert computes:
  $$\text{Evidence Hash} = \text{SHA256}(\text{previous\_hash} + \text{canonical\_payload} + \text{timestamp})$$
* Any retroactive tampering or deletion of alert records breaks the cryptographic hash link and triggers instant tampering detection in `/api/integrity`.

### E. Interactive Web SOC Dashboard
* **Live Threat Inspector**: Auto-tracks incoming alerts with model voting, TreeSHAP feature attributions, policy reasons, and verification badges.
* **Flow Analysis**: Real-time table of live network flows and anomaly scores.
* **AI and reporting**: Explain observed alerts through the configured Groq endpoint,
  use browser speech synthesis, and generate print-ready HTML security reports.
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
git clone https://github.com/rudreshark/sih24hrs.git
cd sih24hrs
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
1. **`● LIVE CAPTURE ACTIVE`** green badge with live packet ingest counters.
2. Real observed interface traffic populating the **Packet telemetry** and **Flow analysis** views.
3. The **Live Threat Inspector** displays model consensus, TreeSHAP feature attributions,
   AI explanations, and SHA-256 evidence-chain verification for persisted detections.

If Npcap is unavailable on Windows, the service automatically uses the native
UDP/TCP fallback. For full host-wide packet visibility, install Npcap and
restart the service:

```powershell
Get-Service npcap
python -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))"
```

---

### Option B: Standalone Capture Counter

Run the capture engine directly and print live counters every five seconds:

```powershell
python -m diodeshield.capture.sniffer
```

This command remains passive and receive-only. Stop it with `Ctrl+C`.

---

### Option C: Verify Database Cryptographic Hash Chain
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
| `POST` | `/api/capture/start` | Starts receive-only live packet capture |
| `POST` | `/api/capture/stop` | Stops receive-only live packet capture |
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
│   ├── capture/sniffer.py         # Scapy/Npcap receive-only live packet capture
│   ├── decoder/packet.py          # Scapy packet metadata decoder
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
│   └── (no traffic-generation or exploit scripts)
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
