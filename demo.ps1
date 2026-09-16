# DIODESHIELD 90-Second Demonstration Script (Windows PowerShell)
# Passive OT Threat Detection over Data Diode Boundary

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " DIODESHIELD: OT Threat Detection Prototype Live Demo" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$PYTHON = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }

# 1. Check or calibrate models
if (-not (Test-Path "models/xgboost.json") -or -not (Test-Path "models/lstm.pt")) {
    Write-Host "`n[1/4] Calibrating 5-branch ML models on synthetic data..." -ForegroundColor Yellow
    & $PYTHON training/train_all_models.py --synthetic
} else {
    Write-Host "`n[1/4] ML model artifacts verified in models/." -ForegroundColor Green
}

# 2. Run demonstration traffic scenarios
Write-Host "`n[2/4] Running OT Traffic Scenarios..." -ForegroundColor Yellow
Write-Host "  -> Scenario A: Baseline Normal OT Polling (expect 0 alerts)" -ForegroundColor Gray
& $PYTHON -m diodeshield.cli --scenario normal --count 30

Write-Host "  -> Scenario B: C2 Beaconing (expect CRITICAL alerts + TreeSHAP)" -ForegroundColor Gray
& $PYTHON -m diodeshield.cli --scenario beacon --count 40

Write-Host "  -> Scenario C: Industrial Reconnaissance (expect HIGH alerts)" -ForegroundColor Gray
& $PYTHON -m diodeshield.cli --scenario recon --count 30

Write-Host "  -> Scenario D: Modbus Protocol Anomaly (expect CRITICAL alerts)" -ForegroundColor Gray
& $PYTHON -m diodeshield.cli --scenario protocol --count 30

# 3. Cryptographic integrity check
Write-Host "`n[3/4] Cryptographic Hash Chain Verification..." -ForegroundColor Yellow
& $PYTHON -c "from diodeshield.db import Repository; res = Repository().verify_integrity(); print('  Chain Verified:', res.get('valid'), '| Head Seq:', res.get('head_sequence'), '| Total Verified:', res.get('count'))"

# 4. Launch instructions
Write-Host "`n[4/4] Demonstration Complete!" -ForegroundColor Green
Write-Host "  To launch the SOC web dashboard, run:" -ForegroundColor White
Write-Host "    & $PYTHON -m uvicorn diodeshield.api.main:app --host 0.0.0.0 --port 8000" -ForegroundColor Cyan
Write-Host "  Then open: http://localhost:8000/dashboard/ in your browser.`n" -ForegroundColor White
