# Start the receive-only DIODESHIELD dashboard.
$PYTHON = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
Write-Host "Starting passive live packet capture and dashboard..." -ForegroundColor Cyan
Start-Process "http://localhost:8000/dashboard/"
& $PYTHON -m uvicorn diodeshield.api.main:app --host 0.0.0.0 --port 8000
