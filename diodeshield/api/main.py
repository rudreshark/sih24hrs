from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.responses import JSONResponse

from diodeshield.capture.live import LiveCaptureWorker
from diodeshield.config import load_config
from diodeshield.db import Repository
from diodeshield.explainability_llm import LLMExplainer
from diodeshield.firewall import block_ip
from diodeshield.integrity import verify_alert
from diodeshield.pipeline import DetectionPipeline
from diodeshield.schemas import BlockRequest, ConfigUpdate, Feedback, TrafficEvent

config = load_config()
repository = Repository()
pipeline = DetectionPipeline(repository, config)
llm_explainer = LLMExplainer()
event_queues: set[asyncio.Queue[dict[str, Any]]] = set()
main_loop: asyncio.AbstractEventLoop | None = None


def publish(alert: dict[str, Any]) -> None:
    payload = {"event_type": "alert", **alert}
    for queue in list(event_queues):
        if main_loop and main_loop.is_running():
            try:
                main_loop.call_soon_threadsafe(queue.put_nowait, payload)
            except Exception:
                pass
        else:
            try:
                queue.put_nowait(payload)
            except Exception:
                pass


def _publish_explanation(alert_id: str, explanation: dict[str, Any]) -> None:
    """Broadcast an alert_explanation event over all active WebSocket channels."""
    payload = {
        "event_type": "alert_explanation",
        "alert_id": alert_id,
        "explanation": explanation,
    }
    for queue in list(event_queues):
        if main_loop and main_loop.is_running():
            try:
                main_loop.call_soon_threadsafe(queue.put_nowait, payload)
            except Exception:
                pass
        else:
            try:
                queue.put_nowait(payload)
            except Exception:
                pass


pipeline.subscribe(publish)
live_capture: LiveCaptureWorker | None = None


async def _watch_db_alerts() -> None:
    last_known_seq = 0
    while True:
        try:
            await asyncio.sleep(1.0)
            rows = repository.alerts(1)
            if rows:
                seq = int(rows[0].get("chain_sequence") or 0)
                if last_known_seq == 0:
                    last_known_seq = seq
                elif seq > last_known_seq:
                    last_known_seq = seq
                    publish(rows[0])
        except asyncio.CancelledError:
            break
        except Exception:
            pass


@asynccontextmanager
async def lifespan(_: FastAPI):
    global live_capture, main_loop
    main_loop = asyncio.get_running_loop()
    db_watcher = asyncio.create_task(_watch_db_alerts())
    if config.get("system", {}).get("live_capture"):
        interface = os.getenv("DIODESHIELD_INTERFACE", "auto")
        live_capture = LiveCaptureWorker(pipeline, interface,
                                         os.getenv("DIODESHIELD_TSHARK", "tshark"))
        live_capture.start()
    yield
    db_watcher.cancel()
    if live_capture:
        live_capture.stop()


app = FastAPI(title="DIODESHIELD", version="0.1.0", lifespan=lifespan)
origins = [x.strip() for x in os.getenv("DIODESHIELD_CORS_ORIGINS", "http://localhost:5173,http://localhost:8000").split(",")]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["*"])
if os.path.isdir("dashboard"):
    app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")


@app.middleware("http")
async def optional_api_key(request, call_next):
    if config.get("security", {}).get("api_key_required") and request.url.path.startswith("/api/"):
        expected = os.getenv("DIODESHIELD_API_KEY", "")
        if not expected or request.headers.get("X-API-Key") != expected:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
    return await call_next(request)


@app.get("/health")
def health() -> dict[str, Any]:
    from diodeshield.startup import CaptureConfig
    tools = CaptureConfig.validate_capture_tools()
    training_status = {name: adapter.get_metadata().get("training_status", "not_trained")
                       for name, adapter in pipeline.adapters.items()}
    return {
        "status": "ok",
        "service": "diodeshield",
        "zeek_available": tools.get("zeek", False),
        "tshark_available": tools.get("tshark", False),
        "fallback_ready": True,
        "training_status": training_status,
        **repository.health(),
    }


@app.get("/health/detailed")
def detailed_health() -> dict[str, Any]:
    return {"status": "ok", "components": {"database": repository.health(), "pipeline": pipeline.latest_health,
                                            "models": {name: adapter.get_metadata() for name, adapter in pipeline.adapters.items()}}}


@app.get("/api/capture-status")
def capture_status() -> dict[str, Any]:
    enabled = bool(config.get("system", {}).get("live_capture"))
    worker = live_capture
    running = bool(worker and ((worker.process and worker.process.poll() is None) or (worker.thread and worker.thread.is_alive())))
    health = pipeline.latest_health
    return {
        "enabled": enabled,
        "running": running,
        "interface": health.get("interface") or getattr(worker, "interface", None),
        "mode": health.get("mode", "tshark" if worker and worker.process else "native_loopback_stream"),
        "tshark": getattr(worker, "command", os.getenv("DIODESHIELD_TSHARK", "tshark")),
        "visibility": health.get("visibility", "unknown"),
        "packets_captured": health.get("packets_captured", 0),
        "remote_packets_captured": health.get("remote_packets_captured", 0),
        "last_capture_time": health.get("last_capture_time"),
        "last_event": health.get("last_event"),
        "data_source": health.get("data_source"),
        "error": health.get("capture_error"),
    }


@app.get("/api/alerts")
def alerts(
    limit: int = 100, severity: str | None = None, category: str | None = None,
    source: str | None = None, destination: str | None = None,
) -> list[dict[str, Any]]:
    rows = repository.alerts(limit)
    return [
        row for row in rows
        if (not severity or row.get("risk_level") == severity)
        and (not category or row.get("attack_category") == category)
        and (not source or row.get("src_ip") == source)
        and (not destination or row.get("dst_ip") == destination)
    ]


@app.get("/api/alerts/{alert_id}")
def alert(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    return result


@app.get("/api/features/{alert_id}")
def features(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    return result.get("feature_values", {})


@app.get("/api/explanation/{alert_id}")
def explanation(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    return {"top_features": result.get("top_features", []),
            "explanation": result.get("explanation", {}),
            "reasons": result.get("reasons", []),
            "calibration": "not validated; confidence is model agreement, not probability"}


@app.get("/api/alerts/{alert_id}/validation")
def validate_alert(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    features = result.get("feature_values") or {}
    dst_port = result.get("dst_port")
    src_port = result.get("src_port")
    # Resolve service names for context
    try:
        from diodeshield.features.protocol import resolve_service as _rs
        dst_service = _rs(dst_port)
        src_service = _rs(src_port)
    except Exception:
        dst_service = src_service = "unknown"
    return {
        "alert": result,
        "verdict": {"category": result.get("attack_category"), "risk_level": result.get("risk_level"),
                    "risk_score": result.get("risk_score"), "confidence": result.get("confidence")},
        "why": result.get("reasons", []),
        "evidence": {"top_features": result.get("top_features", []),
                     "protocol": result.get("protocol_evidence", {}),
                     "source": result.get("src_ip"), "destination": result.get("dst_ip"),
                     "src_port": src_port, "dst_port": dst_port,
                     "src_service": src_service, "dst_service": dst_service,
                     "feature_values": features},
        "models": result.get("model_scores", {}),
        "integrity": {"evidence_hash": result.get("evidence_hash"),
                      "previous_hash": result.get("previous_hash"),
                      "chain_sequence": result.get("chain_sequence"),
                      "verified": verify_alert(result)},
        "limitations": ["This is an evidence-based triage verdict, not proof of compromise.",
                        "Packet alteration and spoofing require trusted capture metadata or baselines."],
    }


@app.get("/api/alerts/{alert_id}/explain")
async def explain_alert(alert_id: str) -> dict[str, Any]:
    """Return LLM-generated plain-English narrative for an alert.

    If a cached explanation exists it is returned immediately.  Otherwise
    one is generated asynchronously (LLM call is off-loaded to a thread so
    it never stalls the async event loop) and cached for future requests.
    """
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    # Return cached explanation if available
    cached = repository.get_alert_explanation(alert_id)
    if cached:
        return cached
    # Generate in thread to avoid blocking event loop
    explanation = await asyncio.to_thread(llm_explainer.explain, result)
    repository.save_alert_explanation(alert_id, explanation)
    # Broadcast over WebSocket so dashboards update live
    _publish_explanation(alert_id, explanation)
    return explanation


class AlertFeedbackRequest(BaseModel):
    label: str  # TP | FP | benign | malicious
    comment: str | None = None


@app.post("/api/alerts/{alert_id}/feedback")
def alert_feedback(alert_id: str, request: AlertFeedbackRequest) -> dict[str, Any]:
    """Record analyst triage feedback for a specific alert.

    Persists label ('TP', 'FP', 'benign', 'malicious') and optional comment
    to the feedback table so the retrain scheduler can use confirmed labels
    for incremental model improvement.
    """
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    allowed_labels = {"TP", "FP", "benign", "malicious"}
    label = str(request.label).upper() if request.label.upper() in {"TP", "FP"} else request.label.lower()
    if label not in allowed_labels:
        raise HTTPException(400, f"label must be one of {sorted(allowed_labels)}")
    repository.feedback({
        "alert_id": alert_id,
        "label": label,
        "comment": request.comment,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return {"status": "stored", "alert_id": alert_id, "label": label}

@app.get("/api/traffic")
def traffic(limit: int = 100) -> list[dict[str, Any]]:
    return repository.flows(limit)


@app.get("/api/assets")
def assets() -> list[dict[str, Any]]:
    return repository.assets()


@app.get("/api/models")
def models() -> list[dict[str, Any]]:
    return [adapter.get_metadata() for adapter in pipeline.adapters.values()]


@app.get("/api/model-health")
def model_health() -> dict[str, Any]:
    """Operational model metadata for the dashboard without changing /api/models."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "streaming_compatible": True,
        "models": [adapter.get_metadata() for adapter in pipeline.adapters.values()],
        "pipeline": pipeline.latest_health,
    }


@app.get("/api/training/provenance")
def training_provenance() -> dict[str, Any]:
    return {
        "models": [adapter.get_metadata() for adapter in pipeline.adapters.values()],
        "registered_versions": repository.model_versions(),
        "synthetic_evaluation": {
            "allowed": "evaluation_only",
            "production_training": False,
            "report": "reports/synthetic_training_report.json",
        },
    }


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    return repository.metrics()


@app.get("/api/dashboard-summary")
def dashboard_summary(
    start: str | None = None, end: str | None = None, severity: str | None = None,
    category: str | None = None, source: str | None = None, destination: str | None = None,
) -> dict[str, Any]:
    return repository.dashboard_summary(start=start, end=end, severity=severity, category=category,
                                       source=source, destination=destination)


@app.get("/api/diode-status")
def diode_status() -> dict[str, Any]:
    return pipeline.latest_health


@app.get("/api/heatmap")
def heatmap(start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
    return repository.heatmap(start, end)


@app.get("/api/model-timeseries")
def model_timeseries(limit: int = 100) -> list[dict[str, Any]]:
    return repository.model_timeseries(limit)


@app.get("/api/evidence-chain")
def evidence_chain(limit: int = 100) -> list[dict[str, Any]]:
    return repository.evidence_chain(limit)


@app.get("/api/integrity")
def integrity() -> dict[str, Any]:
    return repository.verify_integrity()


@app.get("/api/report")
def report(start: str | None = None, end: str | None = None,
           category: str | None = None) -> JSONResponse:
    rows = repository.alerts(1000)
    filtered = [
        row for row in rows
        if (not start or str(row.get("timestamp", "")) >= start)
        and (not end or str(row.get("timestamp", "")) <= end)
        and (not category or row.get("attack_category") == category)
    ]
    counts: dict[str, int] = {}
    for row in filtered:
        key = str(row.get("attack_category") or "UNKNOWN")
        counts[key] = counts.get(key, 0) + 1
    return JSONResponse({"generated_at": datetime.now(timezone.utc).isoformat(),
                         "filters": {"start": start, "end": end, "category": category},
                         "alert_count": len(filtered), "categories": counts,
                         "risk_levels": {level: sum(1 for row in filtered if row.get("risk_level") == level)
                                         for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
                         "alerts": filtered})


@app.post("/api/ingest")
def ingest(event: TrafficEvent) -> dict[str, Any]:
    return {"alerts": pipeline.ingest(event)}


@app.post("/api/config")
def update_config(update: ConfigUpdate) -> dict[str, Any]:
    config.update(update.values)
    return {"status": "updated", "config": config}


@app.post("/api/feedback")
def feedback(item: Feedback) -> dict[str, str]:
    repository.feedback(item.model_dump())
    return {"status": "stored"}


@app.post("/api/alerts/{alert_id}/block")
def block_alert_ip(alert_id: str, request: BlockRequest) -> dict[str, Any]:
    alert = repository.alert(alert_id)
    if alert is None:
        raise HTTPException(404, "alert not found")
    if not request.confirm:
        return {"status": "confirmation_required", "ip": alert.get("src_ip"),
                "message": "Set confirm=true only after validating this alert"}
    ip = alert.get("src_ip")
    if not ip:
        raise HTTPException(400, "alert has no source IP")
    try:
        result = block_ip(str(ip), alert_id, request.reason)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    repository.audit("firewall_block", {"alert_id": alert_id, "ip": ip, **result})
    return result


@app.post("/api/simulator/inject")
def inject_threat(payload: dict[str, Any]) -> dict[str, Any]:
    from datetime import timedelta
    scenario = str(payload.get("scenario", "flood")).lower()
    count = int(payload.get("count", 250))
    count = max(1, min(count, 5000))
    start = datetime.now(timezone.utc)
    batch: list[TrafficEvent] = []

    for i in range(count):
        if scenario == "spoof":
            ttl, protocol, length, port = 64, "UDP", 256, 19001
            source = f"198.18.0.{(i % 32) + 1}"
            dest = "10.0.0.8"
            meta = {"virtual_identity": True}
        elif scenario == "altered":
            ttl, source, protocol, length, port = 64, "10.0.0.7", "TCP", 180, 502
            dest = "10.0.0.8"
            meta = {"payload_altered": True}
        elif scenario == "beacon":
            ttl, source, protocol, length, port = 64, "10.0.0.7", "TCP", 64, 4444
            dest = "198.18.0.50"
            meta = {"beacon": True}
        elif scenario == "recon":
            ttl, source, protocol, length = 64, "10.0.0.7", "TCP", 64
            dest = f"10.0.1.{(i % 16) + 1}"
            port = 502 + (i % 8)
            meta = {"scan": True}
        elif scenario == "normal":
            ttl, source, protocol, length, port = 64, "10.0.0.7", "TCP", 128, 502
            dest = "10.0.0.8"
            meta = {"stream": "normal_polling"}
        else:  # flood
            ttl, source, protocol, length, port = 64, "10.0.0.7", "UDP", 1200, 19001
            dest = "10.0.0.8"
            meta = {"flood": True}

        batch.append(
            TrafficEvent(
                timestamp=start + timedelta(milliseconds=i * 2),
                src_ip=source,
                dst_ip=dest,
                src_port=40000 + (i % 50),
                dst_port=port,
                protocol=protocol,
                packet_len=length,
                ttl=ttl,
                data_source=f"simulator_{scenario}",
                metadata=meta,
            )
        )

    alerts = []
    result = pipeline.process_window(batch)
    if result:
        alerts.append(result)
        publish(result)
    return {
        "status": "injected",
        "scenario": scenario,
        "packets": count,
        "alerts_generated": len(alerts),
        "latest_alert": alerts[0] if alerts else None,
    }


@app.post("/api/simulator/toggle_capture")
def toggle_capture() -> dict[str, Any]:
    global live_capture
    if live_capture and live_capture.thread and live_capture.thread.is_alive():
        live_capture.stop()
        running = False
    else:
        interface = os.getenv("DIODESHIELD_INTERFACE", "auto")
        live_capture = LiveCaptureWorker(pipeline, interface, os.getenv("DIODESHIELD_TSHARK", "tshark"))
        live_capture.start()
        running = True
    return {"status": "ok", "running": running}


async def stream(queue: asyncio.Queue[dict[str, Any]], websocket: WebSocket) -> None:
    while True:
        await websocket.send_text(json.dumps(await queue.get(), default=str))


@app.websocket("/ws/{channel}")
async def websocket_channel(websocket: WebSocket, channel: str) -> None:
    await websocket.accept()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
    event_queues.add(queue)
    try:
        await websocket.send_json({"event_type": "connected", "channel": channel})
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=3.0)
                await websocket.send_json(item)
            except asyncio.TimeoutError:
                await websocket.send_json({
                    "event_type": "heartbeat",
                    "channel": channel,
                    "health": pipeline.latest_health,
                })
    except Exception:
        pass
    finally:
        event_queues.discard(queue)
