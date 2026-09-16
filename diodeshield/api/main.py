"""Production REST and WebSocket API for real-time network security monitoring."""
from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse, RedirectResponse

from diodeshield.authentication.rbac import Role, create_access_token, require_role
from diodeshield.capture.sniffer import LiveNetworkCapture, list_network_interfaces
from diodeshield.configuration.settings import load_app_config
from diodeshield.db import Repository
from diodeshield.firewall import block_ip
from diodeshield.integrity import verify_alert
from diodeshield.monitoring.system import SystemMonitor
from diodeshield.pipeline import DetectionPipeline
from diodeshield.schemas import (
    BlockRequest,
    ConfigUpdate,
    Feedback,
    InterfaceSelectRequest,
    TokenRequest,
    TokenResponse,
    TrafficEvent,
)

app_config = load_app_config()
repository = Repository(app_config.database_path)
pipeline = DetectionPipeline(repository)
system_monitor = SystemMonitor()

event_queues: set[asyncio.Queue[dict[str, Any]]] = set()
main_loop: asyncio.AbstractEventLoop | None = None
live_capture: LiveNetworkCapture | None = None


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


pipeline.subscribe(publish)


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

    if app_config.system.live_capture:
        iface = app_config.system.capture_interface
        live_capture = LiveNetworkCapture(
            interface=iface,
            queue_maxsize=app_config.system.capture_queue_size,
            bpf_filter=app_config.system.bpf_filter,
            on_event_callback=pipeline.ingest,
        )
        live_capture.start()

    yield

    db_watcher.cancel()
    if live_capture:
        live_capture.stop()


app = FastAPI(title="DIODESHIELD Production SOC", version="1.0.0", lifespan=lifespan)

origins = [
    x.strip()
    for x in os.getenv("DIODESHIELD_CORS_ORIGINS", "http://localhost:5173,http://localhost:8000,http://127.0.0.1:8000").split(",")
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

if os.path.isdir("dashboard"):
    app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")


@app.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")


# --- Authentication Endpoints ---

@app.post("/api/auth/token", response_model=TokenResponse)
def login(request: TokenRequest) -> TokenResponse:
    # Basic operator authentication; configured via environment
    admin_pw = os.getenv("DIODESHIELD_ADMIN_PASSWORD", "admin")
    if request.username == "admin" and request.password == admin_pw:
        token = create_access_token(subject=request.username, role=Role.ADMIN)
        return TokenResponse(access_token=token, role="ADMIN")
    elif request.username == "analyst":
        token = create_access_token(subject=request.username, role=Role.ANALYST)
        return TokenResponse(access_token=token, role="ANALYST")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")


# --- Health & Status Endpoints ---

@app.get("/health")
def health() -> dict[str, Any]:
    cap_stats = live_capture.stats.to_dict() if live_capture else {}
    return {
        "status": "HEALTHY",
        "service": "diodeshield-soc",
        "version": app_config.system.sensor_version,
        "mode": app_config.system.mode,
        "live_capture_active": live_capture.stats.status == "RUNNING" if live_capture else False,
        "capture_interface": live_capture.resolved_interface if live_capture else "none",
        "current_pps": cap_stats.get("current_pps", 0.0),
        "current_bps": cap_stats.get("current_bps", 0.0),
        "total_packets_received": cap_stats.get("total_packets_received", 0),
        "database": repository.health(),
    }


@app.get("/health/detailed")
def detailed_health() -> dict[str, Any]:
    cap_stats = live_capture.stats.to_dict() if live_capture else {}
    return {
        "status": "HEALTHY",
        "system": system_monitor.get_metrics(cap_stats),
        "capture": cap_stats,
        "flow_engine": pipeline.flow_tracker.get_flow_stats(),
        "threat_intel": pipeline.detection_engine.threat_intel.get_provider_status(),
        "anomaly_engine": pipeline.detection_engine.anomaly.get_summary(),
        "ml_engine": pipeline.detection_engine.ml.get_health_report(),
        "database": repository.health(),
    }


# --- Network Interface & Capture Control Endpoints ---

@app.get("/api/interfaces")
def get_interfaces() -> list[dict[str, Any]]:
    return list_network_interfaces()


@app.get("/api/capture/stats")
def get_capture_stats() -> dict[str, Any]:
    if live_capture:
        return live_capture.stats.to_dict()
    return {
        "status": "STOPPED",
        "current_pps": 0.0,
        "current_bps": 0.0,
        "total_packets_received": 0,
        "total_packets_dropped": 0,
        "queue_depth": 0,
    }


@app.get("/api/capture-status")
def capture_status() -> dict[str, Any]:
    running = bool(live_capture and live_capture.stats.status == "RUNNING")
    cap_stats = live_capture.stats.to_dict() if live_capture else {}
    health = pipeline.latest_health
    return {
        "enabled": app_config.system.live_capture,
        "running": running,
        "interface": (live_capture.resolved_interface if live_capture else None) or health.get("interface"),
        "mode": health.get("mode", "live_pcap_sniffer"),
        "current_pps": cap_stats.get("current_pps", 0.0),
        "current_bps": cap_stats.get("current_bps", 0.0),
        "packets_captured": max(cap_stats.get("total_packets_received", 0), health.get("packets_captured", 0)),
        "packets_dropped": cap_stats.get("total_packets_dropped", 0),
        "remote_packets_captured": health.get("remote_packets_captured", 0),
        "last_capture_time": cap_stats.get("last_packet_time") or health.get("last_capture_time"),
        "last_event": health.get("last_event"),
        "data_source": health.get("data_source"),
        "visibility": health.get("visibility", "unknown"),
        "error": cap_stats.get("error_message") or health.get("capture_error"),
    }


@app.post("/api/capture/select")
def select_interface(
    req: InterfaceSelectRequest,
    user: dict[str, Any] = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    global live_capture
    if live_capture:
        live_capture.stop()

    live_capture = LiveNetworkCapture(
        interface=req.interface_id,
        queue_maxsize=app_config.system.capture_queue_size,
        bpf_filter=app_config.system.bpf_filter,
        on_event_callback=pipeline.ingest,
    )
    live_capture.start()
    repository.audit("interface_selected", {"interface": req.interface_id, "user": user.get("sub")})
    return {"status": "ok", "interface": req.interface_id, "capture_running": True}


@app.post("/api/capture/start")
def start_capture(user: dict[str, Any] = Depends(require_role(Role.ADMIN))) -> dict[str, Any]:
    global live_capture
    if not live_capture:
        live_capture = LiveNetworkCapture(
            interface=app_config.system.capture_interface,
            queue_maxsize=app_config.system.capture_queue_size,
            on_event_callback=pipeline.ingest,
        )
    live_capture.start()
    repository.audit("capture_started", {"user": user.get("sub")})
    return {"status": "ok", "running": True, "interface": live_capture.resolved_interface}


@app.post("/api/capture/stop")
def stop_capture(user: dict[str, Any] = Depends(require_role(Role.ADMIN))) -> dict[str, Any]:
    global live_capture
    if live_capture:
        live_capture.stop()
    repository.audit("capture_stopped", {"user": user.get("sub")})
    return {"status": "ok", "running": False}


# --- Network Flows & Traffic Endpoints ---

@app.get("/api/flows")
def get_flows(limit: int = 100) -> list[dict[str, Any]]:
    # Returns real active bidirectional flows from FlowTracker
    active = pipeline.flow_tracker.get_active_flows(limit)
    if active:
        return active
    return repository.flows(limit)


@app.get("/api/traffic")
def traffic(limit: int = 100) -> list[dict[str, Any]]:
    active = pipeline.flow_tracker.get_active_flows(limit)
    if active:
        return active
    return repository.flows(limit)


# --- Threat Intelligence Endpoints ---

@app.get("/api/threat-intel/lookup/{ip}")
def lookup_ip_reputation(ip: str) -> dict[str, Any]:
    return pipeline.detection_engine.threat_intel.check_ip(ip)


@app.get("/api/threat-intel/status")
def threat_intel_status() -> dict[str, Any]:
    return pipeline.detection_engine.threat_intel.get_provider_status()


# --- Detection Rules & Signatures Endpoints ---

@app.get("/api/rules")
def get_signature_rules() -> list[dict[str, Any]]:
    return pipeline.detection_engine.signatures.list_rules()


# --- Alerts & Explainability Endpoints ---

@app.get("/api/alerts")
def alerts(
    limit: int = 100,
    severity: str | None = None,
    category: str | None = None,
    source: str | None = None,
    destination: str | None = None,
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
    return {
        "top_features": result.get("top_features", []),
        "explanation": result.get("explanation", {}),
        "reasons": result.get("reasons", []),
        "evidence": result.get("evidence", []),
        "detection_method": result.get("detection_method", "Multi-Layer Engine"),
        "recommended_action": result.get("recommended_action", "Review alert evidence"),
    }


@app.get("/api/alerts/{alert_id}/validation")
def validate_alert(alert_id: str) -> dict[str, Any]:
    result = repository.alert(alert_id)
    if result is None:
        raise HTTPException(404, "alert not found")
    feat = result.get("feature_values") or {}
    return {
        "alert": result,
        "verdict": {
            "category": result.get("attack_category"),
            "risk_level": result.get("risk_level"),
            "risk_score": result.get("risk_score"),
            "confidence": result.get("confidence"),
        },
        "why": result.get("reasons", []) or result.get("evidence", []),
        "evidence": {
            "top_features": result.get("top_features", []),
            "protocol": result.get("protocol_evidence", {}),
            "source": result.get("src_ip"),
            "destination": result.get("dst_ip"),
            "feature_values": feat,
        },
        "models": result.get("model_scores", {}),
        "integrity": {
            "evidence_hash": result.get("evidence_hash"),
            "previous_hash": result.get("previous_hash"),
            "chain_sequence": result.get("chain_sequence"),
            "verified": verify_alert(result),
        },
    }


# --- Model Health & Telemetry Endpoints ---

@app.get("/api/models")
def models() -> list[dict[str, Any]]:
    return [adapter.get_metadata() for adapter in pipeline.adapters.values()]


@app.get("/api/model-health")
def model_health() -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "streaming_compatible": True,
        "models": [adapter.get_metadata() for adapter in pipeline.adapters.values()],
        "manager": pipeline.detection_engine.ml.get_health_report(),
        "pipeline": pipeline.latest_health,
    }


@app.get("/api/training/provenance")
def training_provenance() -> dict[str, Any]:
    return {
        "models": [adapter.get_metadata() for adapter in pipeline.adapters.values()],
        "registered_versions": repository.model_versions(),
        "ml_manager": pipeline.detection_engine.ml.get_health_report(),
    }


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    cap_stats = live_capture.stats.to_dict() if live_capture else {}
    return {
        **repository.metrics(),
        "capture": cap_stats,
        "active_flows": len(pipeline.flow_tracker.active_flows),
    }


@app.get("/api/system/metrics")
def system_metrics() -> dict[str, Any]:
    cap_stats = live_capture.stats.to_dict() if live_capture else {}
    return system_monitor.get_metrics(cap_stats)


@app.get("/api/dashboard-summary")
def dashboard_summary(
    start: str | None = None,
    end: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    source: str | None = None,
    destination: str | None = None,
) -> dict[str, Any]:
    summary = repository.dashboard_summary(
        start=start, end=end, severity=severity, category=category, source=source, destination=destination
    )
    cap_stats = live_capture.stats.to_dict() if live_capture else {}
    summary["current_pps"] = cap_stats.get("current_pps", 0.0)
    summary["current_bps"] = cap_stats.get("current_bps", 0.0)
    summary["total_packets"] = cap_stats.get("total_packets_received", 0)
    summary["active_flows"] = len(pipeline.flow_tracker.active_flows)
    return summary


@app.get("/api/diode-status")
def diode_status() -> dict[str, Any]:
    cap_stats = live_capture.stats.to_dict() if live_capture else {}
    return {
        **pipeline.latest_health,
        **cap_stats,
    }


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


@app.get("/api/assets")
def assets() -> list[dict[str, Any]]:
    return repository.assets()


@app.get("/api/report")
def report(
    start: str | None = None,
    end: str | None = None,
    category: str | None = None,
) -> JSONResponse:
    rows = repository.alerts(1000)
    filtered = [
        row for row in rows
        if (not start or str(row.get("timestamp", "")) >= start)
        and (not end or str(row.get("timestamp", "")) <= end)
        and (not category or row.get("attack_category") == category)
    ]
    counts: dict[str, int] = {}
    for row in filtered:
        k = str(row.get("attack_category") or "UNKNOWN")
        counts[k] = counts.get(k, 0) + 1
    return JSONResponse({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "filters": {"start": start, "end": end, "category": category},
        "alert_count": len(filtered),
        "categories": counts,
        "risk_levels": {
            level: sum(1 for row in filtered if row.get("risk_level") == level)
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        },
        "alerts": filtered,
    })


# --- Operational & Ingestion Endpoints ---

@app.post("/api/ingest")
def ingest(event: TrafficEvent) -> dict[str, Any]:
    return {"alerts": pipeline.ingest(event)}


@app.post("/api/config")
def update_config(
    update: ConfigUpdate,
    user: dict[str, Any] = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    pipeline.config.update(update.values)
    repository.audit("config_updated", {"values": update.values, "user": user.get("sub")})
    return {"status": "updated", "config": pipeline.config}


@app.post("/api/feedback")
def feedback(item: Feedback) -> dict[str, str]:
    repository.feedback(item.model_dump())
    return {"status": "stored"}


@app.post("/api/alerts/{alert_id}/block")
def block_alert_ip(
    alert_id: str,
    request: BlockRequest,
    user: dict[str, Any] = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    alert_data = repository.alert(alert_id)
    if alert_data is None:
        raise HTTPException(404, "alert not found")
    if not request.confirm:
        return {
            "status": "confirmation_required",
            "ip": alert_data.get("src_ip"),
            "message": "Set confirm=true only after validating this alert",
        }
    ip = alert_data.get("src_ip")
    if not ip:
        raise HTTPException(400, "alert has no source IP")
    try:
        result = block_ip(str(ip), alert_id, request.reason)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    repository.audit("firewall_block", {"alert_id": alert_id, "ip": ip, "user": user.get("sub"), **result})
    return result


# --- Real-Time Streaming WebSocket ---

@app.websocket("/ws/{channel}")
async def websocket_channel(websocket: WebSocket, channel: str) -> None:
    await websocket.accept()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
    event_queues.add(queue)
    try:
        await websocket.send_json({"event_type": "connected", "channel": channel})
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=2.0)
                await websocket.send_json(item)
            except asyncio.TimeoutError:
                cap_stats = live_capture.stats.to_dict() if live_capture else {}
                await websocket.send_json({
                    "event_type": "heartbeat",
                    "channel": channel,
                    "capture": cap_stats,
                    "health": pipeline.latest_health,
                })
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        event_queues.discard(queue)
