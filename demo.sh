#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo " DIODESHIELD: OT Threat Detection Prototype Live Demo"
echo "============================================================"

# 1. Calibrate models if needed
if [ ! -f "models/xgboost.json" ] || [ ! -f "models/lstm.pt" ]; then
    echo "[1/4] Calibrating models on synthetic evaluation data..."
    python training/train_all_models.py --synthetic
else
    echo "[1/4] ML model artifacts verified in models/."
fi

# 2. Run traffic scenarios
echo ""
echo "[2/4] Running OT Traffic Scenarios..."
python -m diodeshield.cli --scenario normal --count 30
python -m diodeshield.cli --scenario beacon --count 40
python -m diodeshield.cli --scenario recon --count 30
python -m diodeshield.cli --scenario protocol --count 30

# 3. Cryptographic integrity check
echo ""
echo "[3/4] Verifying SHA-256 Hash Chain Integrity..."
python -c "from diodeshield.db import Repository; res = Repository().verify_integrity(); print('  Chain Verified:', res.get('valid'), '| Head Seq:', res.get('head_sequence'), '| Total:', res.get('count'))"

# 4. Launch instructions
echo ""
echo "[4/4] Demonstration Complete! Start the API with:"
echo "  uvicorn diodeshield.api.main:app --host 0.0.0.0 --port 8000"
echo "Then open: http://localhost:8000/dashboard/"
