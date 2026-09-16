"""PyTorch LSTM sequence model for DIODESHIELD temporal threat detection."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    import torch
    from torch import nn
except ImportError:
    torch = None
    nn = None


if nn is not None:
    class LSTMTemporalNet(nn.Module):
        """Lightweight LSTM sequence classifier for temporal OT threat patterns."""

        def __init__(self, input_dim: int = 43, hidden_dim: int = 16):
            super().__init__()
            self.input_dim = input_dim
            self.hidden_dim = hidden_dim
            self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True)
            self.fc = nn.Sequential(
                nn.Linear(hidden_dim, 8),
                nn.ReLU(),
                nn.Linear(8, 1),
                nn.Sigmoid(),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            if x.dim() == 2:
                x = x.unsqueeze(1)
            _, (hn, _) = self.lstm(x)
            return self.fc(hn[-1]).squeeze(-1)
else:
    class LSTMTemporalNet:  # type: ignore
        pass


def train_lstm_synthetic(
    output_dir: Path,
    X_train: Any,
    y_train: Any,
    feature_names: list[str],
    epochs: int = 30,
) -> dict[str, Any]:
    """Train PyTorch LSTM sequence model on synthetic OT features."""
    if torch is None:
        return {"status": "skipped", "reason": "torch not installed"}

    net = LSTMTemporalNet(input_dim=len(feature_names))
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(net.parameters(), lr=0.01)

    x_tensor = torch.from_numpy(X_train).float()
    y_tensor = torch.from_numpy(y_train).float()

    net.train()
    loss_val = 0.0
    for _ in range(epochs):
        optimizer.zero_grad()
        preds = net(x_tensor)
        loss = criterion(preds, y_tensor)
        loss.backward()
        optimizer.step()
        loss_val = float(loss.item())

    net.eval()
    output_dir.mkdir(parents=True, exist_ok=True)
    pt_path = output_dir / "lstm.pt"
    torch.save(net.state_dict(), pt_path)

    metadata: dict[str, Any] = {
        "model_name": "lstm",
        "model_version": "lstm-pytorch-1.0.0",
        "feature_schema_version": "1.0.0",
        "feature_columns": feature_names,
        "backend": "pytorch",
        "training_status": "trained",
        "streaming_compatible": True,
        "loss": round(loss_val, 4),
        "samples": len(X_train),
        "weights_file": "lstm.pt",
        "provenance": {
            "dataset_name": "synthetic_lab_evaluation",
            "license": "CC0-1.0",
            "training_mode": "prototype_trained_on_synthetic_data",
        },
    }
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    metadata["integrity"] = {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}
    (output_dir / "lstm.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Train PyTorch LSTM sequence model")
    parser.add_argument("--output-dir", type=Path, default=Path("models"))
    args = parser.parse_args()
    print("LSTM training script ready; use train_all_models.py --synthetic to train across all branches.")


if __name__ == "__main__":
    main()
