# Model card

## Training status (2026-09-14)

All five model branches (`xgboost`, `lstm`, `isolation_forest`, `kitsune`, and `fft`)
have been trained on the verified **Network Traffic Anomaly Detection Dataset (Embedded Systems)**
([Kaggle](https://www.kaggle.com/datasets/ziya07/network-traffic-anomaly-detection-dataset), CC0 Public Domain,
SHA-256: `aafb5de7a8c8d4578d57c4203ff92733240387411f702fc112c7474452ccd584`) using the reference
XGBoost architecture from [kvamshi04](https://www.kaggle.com/code/kvamshi04/network-traffic-anomaly-detection-xgboost).

Model artifacts and integrity metadata are serialized in `models/`:
- `models/xgboost.json` and `models/xgboost_artifact.json`: Trained XGBoost classifier (`xgboost-300.0.0`)
- `models/lstm.pt` and `models/lstm.json`: PyTorch temporal sequence neural network (`lstm-pytorch-1.0.0`)
- `models/isolation_forest.joblib` and `models/isolation_forest.json`: Scikit-Learn Isolation Forest (`isolation-forest-100.0.0`)
- `models/kitsune.json`: KitNET-adapted baseline statistical anomaly detector (`diodeshield-adapted-kitnet-1.0.0`)
- `models/fft.json`: Calibrated spectral FFT frequency-domain detector (`signal-fft-calibrated-1.0.0`)
- `models/provenance.json`: Cross-model health and cryptographic SHA-256 integrity evidence

## Reproducible training

`training/train_all_models.py` runs through the verified open-data contract in `training/dataset_manifest.json`.
The manifest identifies the downloadable source, CC0-1.0 license, checksum, numeric schema,
and deterministic stratified split. The command writes artifacts only after schema checks, calibration,
threshold selection, and test metrics (ROC-AUC, PR-AUC, precision, recall, F1, and latency) succeed.
See `training/DATASET_CONTRACT.md`.

## Intended use and limitations

Inference accepts the same bounded feature dictionaries emitted by the
streaming feature builder. Model agreement is evidence, not a calibrated
probability unless a verified artifact is loaded. The system is passive: it
does not craft packets, probe assets, or block traffic automatically.
