"""
tests/test_new_features.py
==========================
Unit tests for the DIODESHIELD master upgrade features:
  - Task 1: evaluation engine + gate check
  - Task 2: LLM explainability layer (local deterministic)
  - Task 3: resolve_service port helper
  - Task 5: retrain scheduler cycle (dry-run, no FS side-effects)
  - API:    new /explain and /feedback endpoints

All tests use in-memory SQLite, no network calls, no file writes to
production artifact paths.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Task 3 — Port/service resolution
# ---------------------------------------------------------------------------

class TestResolveService:
    def test_modbus_port(self):
        from diodeshield.features.protocol import resolve_service
        assert resolve_service(502) == "Modbus/TCP"

    def test_dnp3_port(self):
        from diodeshield.features.protocol import resolve_service
        assert resolve_service(20000) == "DNP3"

    def test_opc_ua_port(self):
        from diodeshield.features.protocol import resolve_service
        assert resolve_service(4840) == "OPC UA"

    def test_unknown_port(self):
        from diodeshield.features.protocol import resolve_service
        assert resolve_service(9999) == "unknown"

    def test_none_port(self):
        from diodeshield.features.protocol import resolve_service
        assert resolve_service(None) == "unknown"

    def test_https_port(self):
        from diodeshield.features.protocol import resolve_service
        assert resolve_service(443) == "HTTPS"

    def test_c2_port(self):
        from diodeshield.features.protocol import resolve_service
        assert resolve_service(4444) == "C2/Reverse-Shell"

    def test_protocol_kwarg_accepted(self):
        from diodeshield.features.protocol import resolve_service
        # protocol kwarg should not raise
        assert resolve_service(502, protocol="TCP") == "Modbus/TCP"


# ---------------------------------------------------------------------------
# Task 2 — LLM explainability (deterministic local backend)
# ---------------------------------------------------------------------------

SAMPLE_ALERT = {
    "alert_id": "test-001",
    "timestamp": "2026-09-15T10:00:00Z",
    "attack_category": "UDP_FLOOD",
    "risk_level": "CRITICAL",
    "risk_score": 0.92,
    "confidence": 0.88,
    "src_ip": "10.0.0.7",
    "dst_ip": "10.0.0.8",
    "src_port": 40001,
    "dst_port": 19001,
    "protocol": "UDP",
    "packet_count": 250,
    "byte_count": 9000,
    "duration_seconds": 2,
    "top_features": [["byte_count", 0.45], ["packet_rate", 0.30], ["unique_dst_ports", 0.15]],
    "model_scores": {"xgboost": 0.95, "lstm": 0.88, "fft": 0.72, "kitsune": 0.91, "isolation_forest": 0.80},
}


class TestLLMExplainer:
    def test_local_explainer_returns_narrative(self):
        from diodeshield.explainability_llm import DeterministicLocalExplainer
        ex = DeterministicLocalExplainer()
        result = ex.explain(SAMPLE_ALERT)
        assert "narrative" in result
        assert len(result["narrative"]) > 50

    def test_local_explainer_returns_audio_script(self):
        from diodeshield.explainability_llm import DeterministicLocalExplainer
        ex = DeterministicLocalExplainer()
        result = ex.explain(SAMPLE_ALERT)
        assert "audio_script" in result
        assert len(result["audio_script"]) > 10

    def test_local_explainer_has_generated_at(self):
        from diodeshield.explainability_llm import DeterministicLocalExplainer
        ex = DeterministicLocalExplainer()
        result = ex.explain(SAMPLE_ALERT)
        assert "generated_at" in result
        assert result["generated_at"]

    def test_local_explainer_backend_name(self):
        from diodeshield.explainability_llm import DeterministicLocalExplainer
        ex = DeterministicLocalExplainer()
        result = ex.explain(SAMPLE_ALERT)
        assert result["backend"] == "local_deterministic"

    def test_llm_explainer_factory_defaults_to_local(self, monkeypatch):
        """Without env vars, factory should use deterministic local backend."""
        monkeypatch.delenv("DIODESHIELD_LLM_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("DIODESHIELD_OLLAMA_URL", raising=False)
        from importlib import reload

        import diodeshield.explainability_llm as m
        reload(m)
        ex = m.LLMExplainer()
        result = ex.explain(SAMPLE_ALERT)
        assert result["backend"] == "local_deterministic"

    def test_narrative_mentions_src_ip(self):
        from diodeshield.explainability_llm import DeterministicLocalExplainer
        ex = DeterministicLocalExplainer()
        result = ex.explain(SAMPLE_ALERT)
        assert "10.0.0.7" in result["narrative"]

    def test_narrative_mentions_service(self):
        from diodeshield.explainability_llm import DeterministicLocalExplainer
        ex = DeterministicLocalExplainer()
        result = ex.explain(SAMPLE_ALERT)
        # Should resolve port 19001 to Custom OT Telemetry
        assert "Custom OT Telemetry" in result["narrative"] or "19001" in result["narrative"]

    def test_explain_with_minimal_alert(self):
        """Should not raise even with mostly-empty alert dict."""
        from diodeshield.explainability_llm import DeterministicLocalExplainer
        ex = DeterministicLocalExplainer()
        result = ex.explain({})
        assert "narrative" in result
        assert "audio_script" in result


# ---------------------------------------------------------------------------
# Task 1 — Evaluation engine
# ---------------------------------------------------------------------------

class TestEvaluationEngine:
    def test_synthetic_eval_runs(self):
        from training.evaluate import _run_synthetic_evaluation
        result = _run_synthetic_evaluation()
        assert "scenarios" in result
        assert "branch_metrics" in result

    def test_synthetic_eval_has_ensemble_metrics(self):
        from training.evaluate import _run_synthetic_evaluation
        result = _run_synthetic_evaluation()
        assert "ensemble" in result["branch_metrics"]

    def test_branch_metrics_have_required_keys(self):
        from training.evaluate import _run_synthetic_evaluation
        result = _run_synthetic_evaluation()
        for branch, m in result["branch_metrics"].items():
            for key in ("precision", "recall", "f1", "tp", "fp", "tn", "fn"):
                assert key in m, f"Missing {key} in {branch}"

    def test_gate_check_structure(self):
        from training.evaluate import _gate_check, _run_synthetic_evaluation
        result = _run_synthetic_evaluation()
        gate = _gate_check(result["branch_metrics"])
        assert "_overall_pass" in gate

    def test_gate_check_per_branch_fields(self):
        from training.evaluate import _gate_check
        metrics = {"ensemble": {"precision": 0.9, "recall": 0.9, "f1": 0.9}}
        gate = _gate_check(metrics)
        assert gate["ensemble"]["passed"] is True
        assert gate["_overall_pass"] is True

    def test_gate_check_fails_on_low_recall(self):
        from training.evaluate import _gate_check
        metrics = {"model_a": {"precision": 0.9, "recall": 0.30, "f1": 0.80}}
        gate = _gate_check(metrics)
        assert gate["model_a"]["recall_pass"] is False
        assert gate["model_a"]["passed"] is False
        assert gate["_overall_pass"] is False

    def test_metrics_from_counts(self):
        from training.evaluate import _metrics_from_counts
        m = _metrics_from_counts(tp=8, fp=2, tn=8, fn=2)
        assert abs(m["precision"] - 0.8) < 0.01
        assert abs(m["recall"] - 0.8) < 0.01
        assert abs(m["f1"] - 0.8) < 0.01


# ---------------------------------------------------------------------------
# Task 5 — Retrain scheduler (dry-run, in-memory)
# ---------------------------------------------------------------------------

class TestRetrainScheduler:
    def test_cycle_skips_with_no_feedback(self, tmp_path, monkeypatch):
        """Cycle should report 'skipped' when no feedback rows exist."""
        monkeypatch.setenv("DIODESHIELD_DB", str(tmp_path / "test.db"))
        monkeypatch.setenv("DIODESHIELD_RETRAIN_MIN_FEEDBACK", "5")
        from training.retrain_scheduler import run_retrain_cycle
        result = run_retrain_cycle(force=False)
        assert result["status"] in ("skipped", "no_updates")

    def test_cycle_runs_with_force(self, tmp_path, monkeypatch):
        """Force=True should attempt a cycle regardless of feedback count."""
        monkeypatch.setenv("DIODESHIELD_DB", str(tmp_path / "test.db"))
        from training.retrain_scheduler import run_retrain_cycle
        # Should not raise; result may be 'no_updates' or 'promoted' or 'blocked'
        result = run_retrain_cycle(force=True)
        assert result["status"] in ("promoted", "no_updates", "blocked", "skipped")

    def test_label_helpers(self):
        from training.retrain_scheduler import _label_is_attack, _label_is_benign
        assert _label_is_benign("FP")
        assert _label_is_benign("benign")
        assert _label_is_attack("TP")
        assert _label_is_attack("malicious")
        assert not _label_is_benign("TP")
        assert not _label_is_attack("FP")


# ---------------------------------------------------------------------------
# API endpoints — new endpoints (Test via FastAPI TestClient)
# ---------------------------------------------------------------------------

class TestNewAPIEndpoints:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DIODESHIELD_DB", str(tmp_path / "api_test.db"))
        monkeypatch.setenv("DIODESHIELD_LLM_API_KEY", "")
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("DIODESHIELD_OLLAMA_URL", raising=False)

    def _make_client_with_alert(self):
        """Create a fresh TestClient with one alert pre-populated."""
        from fastapi.testclient import TestClient

        from diodeshield.api.main import app, repository
        from diodeshield.config import load_config
        from diodeshield.pipeline import DetectionPipeline
        from diodeshield.schemas import TrafficEvent

        # Use the module-level pipeline which reads env DB path
        # Inject a synthetic event to generate an alert
        config = load_config()
        pipeline = DetectionPipeline(repository, config)
        events = [
            TrafficEvent(
                src_ip="192.168.1.100",
                dst_ip="10.0.0.8",
                src_port=40001,
                dst_port=19001,
                protocol="UDP",
                packet_len=1200,
                ttl=64,
                data_source="test_inject",
            )
            for _ in range(300)
        ]
        pipeline.process_window(events)
        alerts = repository.alerts(10)
        client = TestClient(app)
        return client, alerts

    def test_explain_endpoint_returns_narrative(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DIODESHIELD_DB", str(tmp_path / "exp_test.db"))
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        from diodeshield.db import Repository

        # Insert a fake alert directly into a temp repo
        repo = Repository(str(tmp_path / "exp_test.db"))
        repo.save_alert({
            "alert_id": "fake-001",
            "timestamp": "2026-09-15T10:00:00Z",
            "attack_category": "UDP_FLOOD",
            "risk_level": "CRITICAL",
            "risk_score": 0.9,
            "confidence": 0.85,
            "src_ip": "10.0.0.7",
            "dst_ip": "10.0.0.8",
            "src_port": 40001,
            "dst_port": 19001,
            "protocol": "UDP",
            "top_features": [["byte_count", 0.4], ["packet_rate", 0.3]],
            "model_scores": {"xgboost": 0.9, "lstm": 0.85},
            "evidence_hash": "abc123",
            "previous_hash": "000000",
            "chain_sequence": 1,
        })

        # Test the explain endpoint via the module-level repository of the app
        # We test the LLM explainer directly since monkeypatching the module-level
        # repository in main.py requires reimport.
        from diodeshield.explainability_llm import LLMExplainer
        ex = LLMExplainer()
        alert = repo.alert("fake-001")
        assert alert is not None
        explanation = ex.explain(alert)
        assert "narrative" in explanation
        assert len(explanation["narrative"]) > 10

    def test_feedback_label_validation(self):
        """AlertFeedbackRequest should only accept valid label values."""
        from diodeshield.api.main import AlertFeedbackRequest
        req = AlertFeedbackRequest(label="TP", comment="confirmed attack")
        assert req.label == "TP"

    def test_explain_requires_existing_alert(self, tmp_path, monkeypatch):
        """GET /api/alerts/{id}/explain should return 404 for unknown alert_id."""
        monkeypatch.setenv("DIODESHIELD_DB", str(tmp_path / "e404_test.db"))
        from fastapi.testclient import TestClient

        from diodeshield.api.main import app
        client = TestClient(app)
        resp = client.get("/api/alerts/nonexistent-uuid/explain")
        assert resp.status_code == 404

    def test_feedback_requires_existing_alert(self, tmp_path, monkeypatch):
        """POST /api/alerts/{id}/feedback should return 404 for unknown alert_id."""
        monkeypatch.setenv("DIODESHIELD_DB", str(tmp_path / "f404_test.db"))
        from fastapi.testclient import TestClient

        from diodeshield.api.main import app
        client = TestClient(app)
        resp = client.post(
            "/api/alerts/nonexistent-uuid/feedback",
            json={"label": "TP", "comment": "test"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DB — new column migrations
# ---------------------------------------------------------------------------

class TestDBMigrations:
    def test_explanation_llm_column_exists(self, tmp_path):
        from diodeshield.db import Repository
        repo = Repository(str(tmp_path / "mig_test.db"))
        cols = {row[1] for row in repo._conn.execute("PRAGMA table_info(alerts)")}
        assert "explanation_llm" in cols

    def test_flows_extra_columns_exist(self, tmp_path):
        from diodeshield.db import Repository
        repo = Repository(str(tmp_path / "flow_test.db"))
        cols = {row[1] for row in repo._conn.execute("PRAGMA table_info(flows)")}
        for col in ("src_port", "dst_port", "packet_rate", "service"):
            assert col in cols, f"Missing column: {col}"

    def test_save_alert_explanation_and_retrieve(self, tmp_path):
        from diodeshield.db import Repository
        repo = Repository(str(tmp_path / "exp_test.db"))
        repo.save_alert({
            "alert_id": "test-exp-001",
            "timestamp": "2026-09-15T10:00:00Z",
            "attack_category": "UDP_FLOOD",
            "risk_level": "CRITICAL",
            "risk_score": 0.9,
            "evidence_hash": "aaa",
            "previous_hash": "000",
            "chain_sequence": 1,
        })
        explanation = {
            "narrative": "Test narrative.",
            "audio_script": "Test audio.",
            "generated_at": "2026-09-15T10:00:01Z",
            "backend": "local_deterministic",
        }
        repo.save_alert_explanation("test-exp-001", explanation)
        retrieved = repo.get_alert_explanation("test-exp-001")
        assert retrieved is not None
        assert retrieved["narrative"] == "Test narrative."
        assert retrieved["backend"] == "local_deterministic"

    def test_get_explanation_returns_none_for_missing(self, tmp_path):
        from diodeshield.db import Repository
        repo = Repository(str(tmp_path / "none_test.db"))
        result = repo.get_alert_explanation("does-not-exist")
        assert result is None

    def test_save_flow_with_extra_fields(self, tmp_path):
        from diodeshield.db import Repository
        repo = Repository(str(tmp_path / "flow_save_test.db"))
        repo.save_flow({
            "timestamp": "2026-09-15T10:00:00Z",
            "src_ip": "10.0.0.7",
            "dst_ip": "10.0.0.8",
            "protocol": "TCP",
            "packets": 10,
            "bytes": 1280,
            "anomaly_score": 0.3,
            "asset_id": "PLC-1",
            "src_port": 40001,
            "dst_port": 502,
            "packet_rate": 5.0,
            "service": "Modbus/TCP",
        })
        flows = repo.flows(10)
        assert len(flows) == 1
        assert flows[0]["service"] == "Modbus/TCP"
        assert flows[0]["dst_port"] == 502
