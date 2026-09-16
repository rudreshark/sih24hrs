"""FastAPI application for passive live packet monitoring.

The dashboard reads from the same Scapy capture worker that feeds the
detection pipeline. Capture remains receive-only; optional analyst-approved
firewall endpoints can enforce a validated IP block on the host.
"""
from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse

from diodeshield.capture.sniffer import LiveNetworkCapture, list_network_interfaces
from diodeshield.config import load_config
from diodeshield.db import Repository
from diodeshield.integrity import verify_alert
from diodeshield.pipeline import DetectionPipeline
from diodeshield.firewall import block_ip, unblock_ip
from pydantic import BaseModel, Field

from diodeshield.schemas import ConfigUpdate, Feedback, InterfaceSelectRequest, TrafficEvent


class AlertFeedbackRequest(BaseModel):
    label: str = Field(pattern="^(TP|FP|BENIGN|UNKNOWN)$")
    comment: str = ""


class FirewallIPRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=39)
    alert_id: str = ""
    reason: str = ""


class ExplainAlertRequest(BaseModel):
    alert_id: str = Field(min_length=1)
    alert_type: str = Field(min_length=1)
    src_ip: str = Field(min_length=1)
    dst_ip: str = Field(min_length=1)
    protocol: str = Field(min_length=1)
    port: int | None = None
    src_port: int | None = None
    dst_port: int | None = None
    packet_summary: str = Field(min_length=1)
    model_scores: dict[str, float] = Field(default_factory=dict)
    model_votes: dict[str, str] = Field(default_factory=dict)
    feature_values: dict[str, Any] = Field(default_factory=dict)
    destination_context: dict[str, Any] = Field(default_factory=dict)
    historical_context: dict[str, Any] = Field(default_factory=dict)


class ExplainAlertResponse(BaseModel):
    observed: str
    why_flagged: str
    context: str
    confidence: str
    recommendation: str
    summary_line: str
    # Backward-compatible fields used by the current dashboard speech panel.
    summary: str
    severity: str
    spoken_text: str
    root_cause: str
    recommended_action: str

config = load_config()
repository = Repository()
pipeline = DetectionPipeline(repository, config)
live_capture: LiveNetworkCapture | None = None
subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
event_loop: asyncio.AbstractEventLoop | None = None


def _publish(alert: dict[str, Any]) -> None:
    payload = {"event_type": "alert", **alert}
    for queue in tuple(subscribers):
        try:
            if event_loop and event_loop.is_running():
                event_loop.call_soon_threadsafe(queue.put_nowait, payload)
            else:
                queue.put_nowait(payload)
        except asyncio.QueueFull:
            continue


pipeline.subscribe(_publish)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global event_loop, live_capture
    event_loop = asyncio.get_running_loop()
    if config["system"].get("live_capture", True):
        live_capture = LiveNetworkCapture(
            interface=os.getenv("DIODESHIELD_INTERFACE", "auto"),
            queue_maxsize=int(os.getenv("DIODESHIELD_CAPTURE_QUEUE", "20000")),
            bpf_filter=os.getenv("DIODESHIELD_BPF_FILTER", ""),
            on_event_callback=pipeline.ingest,
            engine=os.getenv("DIODESHIELD_CAPTURE_ENGINE", "auto"),
            native_bind_host=os.getenv("DIODESHIELD_NATIVE_BIND_HOST", "0.0.0.0"),
            native_udp_ports=tuple(
                int(port.strip())
                for port in os.getenv("DIODESHIELD_NATIVE_UDP_PORTS", "502,102,2404").split(",")
                if port.strip().isdigit()
            ),
            native_tcp_port=int(os.getenv("DIODESHIELD_NATIVE_TCP_PORT", "502")),
        )
        live_capture.start()
    yield
    if live_capture:
        live_capture.stop()
    event_loop = None


app = FastAPI(title="DIODESHIELD Passive Network Monitor", version="2.0.0", lifespan=lifespan)
origins = [origin.strip() for origin in os.getenv(
    "DIODESHIELD_CORS_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000",
).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
dashboard_dir = Path(__file__).resolve().parents[2] / "dashboard"
if dashboard_dir.is_dir():
    app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/dashboard/")


def _capture_stats() -> dict[str, Any]:
    return live_capture.stats.to_dict() if live_capture else {
        "status": "STOPPED", "interface": "none", "current_pps": 0.0,
        "current_bps": 0.0, "total_packets_received": 0,
        "total_packets_processed": 0, "total_packets_dropped": 0,
        "total_bytes_received": 0, "queue_depth": 0,
    }


@app.get("/health")
def health() -> dict[str, Any]:
    stats = _capture_stats()
    return {
        "status": "HEALTHY" if stats["status"] != "ERROR" else "DEGRADED",
        "service": "diodeshield-passive-monitor",
        "version": app.version,
        "live_capture_active": stats["status"] == "RUNNING",
        "capture_interface": stats["interface"],
        "current_pps": stats["current_pps"],
        "current_bps": stats["current_bps"],
        "total_packets_received": stats["total_packets_received"],
        "database": repository.health(),
    }


@app.get("/health/detailed")
def detailed_health() -> dict[str, Any]:
    return {
        "status": health()["status"],
        "capture": _capture_stats(),
        "pipeline": pipeline.latest_health,
        "models": [adapter.get_metadata() for adapter in pipeline.adapters.values()],
        "database": repository.health(),
    }


@app.get("/api/interfaces")
def interfaces() -> list[dict[str, Any]]:
    return list_network_interfaces()


@app.get("/api/capture-status")
def capture_status() -> dict[str, Any]:
    stats = _capture_stats()
    return {
        "enabled": bool(config["system"].get("live_capture", True)),
        "running": stats["status"] == "RUNNING",
        "mode": stats.get("engine", "scapy"),
        "interface": stats["interface"],
        "packets_captured": stats["total_packets_received"],
        "packets_processed": stats["total_packets_processed"],
        "packets_dropped": stats["total_packets_dropped"],
        "bytes_captured": stats["total_bytes_received"],
        "current_pps": stats["current_pps"],
        "current_bps": stats["current_bps"],
        "last_capture_time": stats["last_packet_time"],
        "error": stats["error_message"],
    }


@app.get("/api/capture/stats")
def capture_stats() -> dict[str, Any]:
    return _capture_stats()


def _new_capture(interface: str) -> LiveNetworkCapture:
    udp_ports = tuple(
        int(port.strip())
        for port in os.getenv("DIODESHIELD_NATIVE_UDP_PORTS", "502,102,2404").split(",")
        if port.strip().isdigit()
    )
    return LiveNetworkCapture(
        interface=interface,
        queue_maxsize=int(os.getenv("DIODESHIELD_CAPTURE_QUEUE", "20000")),
        bpf_filter=os.getenv("DIODESHIELD_BPF_FILTER", ""),
        on_event_callback=pipeline.ingest,
        engine=os.getenv("DIODESHIELD_CAPTURE_ENGINE", "auto"),
        native_bind_host=os.getenv("DIODESHIELD_NATIVE_BIND_HOST", "0.0.0.0"),
        native_udp_ports=udp_ports,
        native_tcp_port=int(os.getenv("DIODESHIELD_NATIVE_TCP_PORT", "502")),
    )


@app.post("/api/capture/start")
def start_capture() -> dict[str, Any]:
    global live_capture
    if live_capture is None:
        live_capture = _new_capture(os.getenv("DIODESHIELD_INTERFACE", "auto"))
    live_capture.start()
    return capture_status()


@app.post("/api/capture/stop")
def stop_capture() -> dict[str, Any]:
    if live_capture:
        live_capture.stop()
    return capture_status()


@app.post("/api/capture/select")
def select_interface(request: InterfaceSelectRequest) -> dict[str, Any]:
    global live_capture
    if live_capture:
        live_capture.stop()
    live_capture = _new_capture(request.interface_id)
    live_capture.start()
    return capture_status()


@app.get("/api/alerts")
def alerts(limit: int = 100, severity: str | None = None,
           category: str | None = None, source: str | None = None) -> list[dict[str, Any]]:
    rows = repository.alerts(limit)
    return [row for row in rows if
            (not severity or row.get("risk_level") == severity) and
            (not category or row.get("attack_category") == category) and
            (not source or row.get("src_ip") == source)]


@app.get("/api/alerts/{alert_id}")
def alert(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    return result


@app.post("/api/firewall/block")
def firewall_block(request: FirewallIPRequest) -> dict[str, Any]:
    try:
        result = block_ip(request.ip, request.alert_id, request.reason)
    except (ValueError, PermissionError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    repository.audit("firewall_block", result)
    return result


@app.post("/api/firewall/unblock")
def firewall_unblock(request: FirewallIPRequest) -> dict[str, Any]:
    try:
        result = unblock_ip(request.ip)
    except (ValueError, PermissionError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    repository.audit("firewall_unblock", result)
    return result


@app.get("/api/alerts/{alert_id}/validation")
def validate_alert(alert_id: str) -> dict[str, Any]:
    result = alert(alert_id)
    return {
        "alert": result,
        "verdict": {key: result.get(key) for key in ("attack_category", "risk_level", "risk_score", "confidence")},
        "why": result.get("reasons", []),
        "evidence": {"top_features": result.get("top_features", []), "feature_values": result.get("feature_values", {})},
        "models": result.get("model_scores", {}),
        "integrity": {"verified": verify_alert(result), "evidence_hash": result.get("evidence_hash")},
    }


@app.get("/api/alerts/{alert_id}/explain")
def explain_alert(alert_id: str) -> dict[str, Any]:
    result = alert(alert_id)
    return {
        "alert_id": alert_id,
        "narrative": result.get("explanation", {}),
        "top_features": result.get("top_features", []),
        "reasons": result.get("reasons", []),
    }


@app.post("/api/explain-alert", response_model=ExplainAlertResponse)
def explain_alert_with_ai(request: ExplainAlertRequest) -> ExplainAlertResponse:
    """Explain one observed alert using Groq without affecting capture."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise HTTPException(500, "GROQ_API_KEY is not configured")
    try:
        from groq import Groq

        client = Groq(api_key=api_key)
        stored_alert = repository.alert(request.alert_id) or {}
        supplied = {
            "alert_id": request.alert_id,
            "timestamp": stored_alert.get("timestamp"),
            "severity": stored_alert.get("risk_level"),
            "category": request.alert_type,
            "source": {"ip": request.src_ip, "port": request.src_port},
            "destination": {"ip": request.dst_ip, "port": request.dst_port or request.port},
            "protocol": request.protocol,
            "packet_summary": request.packet_summary,
            "model_scores": request.model_scores or stored_alert.get("model_scores", {}),
            "model_votes": request.model_votes,
            "feature_values": request.feature_values or stored_alert.get("feature_values", {}),
            "destination_context": request.destination_context,
            "historical_context": request.historical_context,
            "stored_reasons": stored_alert.get("reasons", []),
        }
        prompt = (
            "You are a defensive network intrusion detection analyst. Analyze only the "
            "JSON evidence supplied below. Do not invent values, thresholds, packets, "
            "reputation, ASN, software, or intent. If a field is absent, explicitly say "
            "that it is missing or not enriched. Explain model disagreement. Mention exact "
            "feature values and configured thresholds only when they are present in the "
            "evidence; otherwise say the threshold is unavailable. Use cautious language "
            "such as 'consistent with' rather than claiming confirmed malicious activity.\n\n"
            "Return valid JSON only with exactly these keys:\n"
            '{"observed":"...", "why_flagged":"...", "context":"...", '
            '"confidence":"High|Medium|Low", "recommendation":"...", '
            '"summary_line":"...", "summary":"...", "severity":"Low|Medium|High|Critical", '
            '"spoken_text":"...", "root_cause":"...", "recommended_action":"..."}\n'
            "The observed and summary_line values must be concise. The other explanation "
            "fields should identify evidence, benign alternatives, and a concrete analyst "
            "next step. The severity is a triage label, not proof of compromise.\n\n"
            f"Evidence JSON:\n{json.dumps(supplied, default=str, sort_keys=True)}"
        )
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            temperature=0.1,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": "You are a defensive network traffic analyst."},
                {"role": "user", "content": prompt},
            ],
        )
        content = completion.choices[0].message.content or ""
        data = json.loads(content)
        allowed = {"Low", "Medium", "High", "Critical"}
        if data.get("severity") not in allowed:
            raise ValueError("AI returned an invalid severity")
        required = {
            "observed", "why_flagged", "context", "confidence",
            "recommendation", "summary_line", "summary", "spoken_text",
            "root_cause", "recommended_action",
        }
        missing = sorted(key for key in required if not isinstance(data.get(key), str))
        if data.get("confidence") not in {"High", "Medium", "Low"}:
            missing.append("confidence")
        if missing:
            raise ValueError(f"AI response missing valid fields: {', '.join(missing)}")
        return ExplainAlertResponse.model_validate(data)
    except HTTPException:
        raise
    except (ImportError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(500, f"AI explanation failed: {exc}") from exc
    except Exception as exc:
        raise HTTPException(500, "AI explanation service unavailable") from exc


@app.post("/api/alerts/{alert_id}/feedback")
def alert_feedback(alert_id: str, item: AlertFeedbackRequest) -> dict[str, str]:
    result = alert(alert_id)
    label = {"TP": "TRUE_POSITIVE", "FP": "FALSE_POSITIVE"}.get(item.label, item.label)
    repository.feedback({"alert_id": result["alert_id"], "label": label, "comment": item.comment})
    return {"status": "stored"}


@app.get("/api/flows")
@app.get("/api/traffic")
def flows(limit: int = 100) -> list[dict[str, Any]]:
    return repository.flows(limit)


@app.get("/api/dashboard-summary")
def dashboard_summary(start: str | None = None, end: str | None = None,
                      severity: str | None = None, category: str | None = None,
                      source: str | None = None, destination: str | None = None) -> dict[str, Any]:
    summary = repository.dashboard_summary(
        start=start, end=end, severity=severity, category=category,
        source=source, destination=destination,
    )
    stats = _capture_stats()
    summary.update({
        "current_pps": stats["current_pps"],
        "current_bps": stats["current_bps"],
        "total_packets": stats["total_packets_received"],
        "active_flows": summary["kpis"]["flows"],
    })
    return summary


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    return {**repository.metrics(), "capture": _capture_stats()}


@app.get("/api/diode-status")
def diode_status() -> dict[str, Any]:
    return {**pipeline.latest_health, **capture_status()}


@app.get("/api/models")
def models() -> list[dict[str, Any]]:
    return [adapter.get_metadata() for adapter in pipeline.adapters.values()]


@app.get("/api/model-health")
def model_health() -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "streaming_compatible": True,
        "models": models(),
        "pipeline": pipeline.latest_health,
    }


@app.get("/api/training/provenance")
def provenance() -> dict[str, Any]:
    return {"models": models(), "registered_versions": repository.model_versions()}


@app.get("/api/model-timeseries")
def model_timeseries(limit: int = 100) -> list[dict[str, Any]]:
    return repository.model_timeseries(limit)


@app.get("/api/evidence-chain")
def evidence_chain(limit: int = 100) -> list[dict[str, Any]]:
    return repository.evidence_chain(limit)


@app.get("/api/integrity")
def integrity() -> dict[str, Any]:
    return repository.verify_integrity()


@app.get("/api/assets")
def assets() -> list[dict[str, Any]]:
    return repository.assets()


@app.get("/api/heatmap")
def heatmap(start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
    return repository.heatmap(start, end)


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


@app.websocket("/ws/{channel}")
async def websocket_channel(websocket: WebSocket, channel: str) -> None:
    await websocket.accept()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
    subscribers.add(queue)
    try:
        await websocket.send_json({"event_type": "connected", "channel": channel})
        while True:
            try:
                await websocket.send_json(await asyncio.wait_for(queue.get(), timeout=2))
            except asyncio.TimeoutError:
                await websocket.send_json({"event_type": "heartbeat", "capture": _capture_stats()})
    except WebSocketDisconnect:
        pass
    finally:
        subscribers.discard(queue)
