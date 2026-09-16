from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
 alert_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, first_seen TEXT, last_seen TEXT,
 src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, protocol TEXT,
 asset_id TEXT, asset_criticality REAL, attack_category TEXT, risk_score REAL,
 risk_level TEXT, confidence REAL, model_disagreement REAL, model_scores TEXT,
 protocol_evidence TEXT, baseline_deviation REAL, feature_values TEXT,
 top_features TEXT, threat_intel TEXT, vulnerability_context TEXT,
 gateway_context TEXT, diode_health TEXT, model_version TEXT,
 feature_schema_version TEXT, configuration_version TEXT, sensor_version TEXT,
 evidence_hash TEXT, previous_hash TEXT, chain_sequence INTEGER, incident_id TEXT,
 explanation TEXT
);
CREATE TABLE IF NOT EXISTS alert_evidence (alert_id TEXT PRIMARY KEY, evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assets (
 asset_id TEXT PRIMARY KEY, hostname TEXT, ip TEXT, mac TEXT, vendor TEXT,
 device_type TEXT, firmware TEXT, software_version TEXT, protocols TEXT,
 criticality REAL, authorized_peers TEXT
);
CREATE TABLE IF NOT EXISTS flows (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src_ip TEXT, dst_ip TEXT,
 protocol TEXT, packets INTEGER, bytes INTEGER, anomaly_score REAL, asset_id TEXT
);
CREATE TABLE IF NOT EXISTS features (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, asset_id TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS model_scores (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, alert_id TEXT, scores TEXT
);
CREATE TABLE IF NOT EXISTS model_versions (
 model_name TEXT PRIMARY KEY, model_version TEXT, feature_schema_version TEXT,
 training_dataset TEXT, training_timestamp TEXT, metrics TEXT, hyperparameters TEXT
);
CREATE TABLE IF NOT EXISTS feedback (
 id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, label TEXT, comment TEXT, timestamp TEXT
);
CREATE TABLE IF NOT EXISTS baseline_profiles (profile_key TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS protocol_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, protocol TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS threat_intel (indicator TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS vulnerabilities (asset_id TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS diode_health (timestamp TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS system_metrics (timestamp TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, event TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS idx_alert_time ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_asset ON alerts(asset_id);
CREATE INDEX IF NOT EXISTS idx_alert_level ON alerts(risk_level);
CREATE INDEX IF NOT EXISTS idx_flow_time ON flows(timestamp);
"""


class Repository:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or os.getenv("DIODESHIELD_DB", "data/diodeshield.db"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 30000")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.executescript(SCHEMA)
        # Keep existing prototype databases usable when a new evidence field is
        # introduced; SQLite's CREATE TABLE IF NOT EXISTS does not migrate it.
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(alerts)")}
        if "explanation" not in columns:
            self._conn.execute("ALTER TABLE alerts ADD COLUMN explanation TEXT")
        if "reasons" not in columns:
            self._conn.execute("ALTER TABLE alerts ADD COLUMN reasons TEXT")
        if "explanation_llm" not in columns:
            self._conn.execute("ALTER TABLE alerts ADD COLUMN explanation_llm TEXT")
        # flows table extra columns (Task 3)
        flow_cols = {row[1] for row in self._conn.execute("PRAGMA table_info(flows)")}
        if "src_port" not in flow_cols:
            self._conn.execute("ALTER TABLE flows ADD COLUMN src_port INTEGER")
        if "dst_port" not in flow_cols:
            self._conn.execute("ALTER TABLE flows ADD COLUMN dst_port INTEGER")
        if "packet_rate" not in flow_cols:
            self._conn.execute("ALTER TABLE flows ADD COLUMN packet_rate REAL")
        if "service" not in flow_cols:
            self._conn.execute("ALTER TABLE flows ADD COLUMN service TEXT")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _write(self, query: str, values: tuple[Any, ...] = ()) -> None:
        with self._lock:
            self._conn.execute(query, values)
            self._conn.commit()

    def _rows(self, query: str, values: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._conn.execute(query, values).fetchall()]

    def save_alert(self, alert: dict[str, Any]) -> None:
        columns = [
            "alert_id", "timestamp", "first_seen", "last_seen", "src_ip", "dst_ip", "src_port",
            "dst_port", "protocol", "asset_id", "asset_criticality", "attack_category", "risk_score",
            "risk_level", "confidence", "model_disagreement", "model_scores", "protocol_evidence",
            "baseline_deviation", "feature_values", "top_features", "threat_intel",
            "vulnerability_context", "gateway_context", "diode_health", "model_version",
            "feature_schema_version", "configuration_version", "sensor_version", "evidence_hash",
            "previous_hash", "chain_sequence", "incident_id", "explanation", "reasons",
        ]
        vals = tuple(json.dumps(alert.get(c), default=str) if isinstance(alert.get(c), (dict, list)) else alert.get(c) for c in columns)
        self._write(
            f"INSERT OR REPLACE INTO alerts ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            vals,
        )
        self._write("INSERT OR REPLACE INTO alert_evidence(alert_id,evidence) VALUES(?,?)",
                    (alert["alert_id"], json.dumps(alert, default=str)))

    def alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._rows("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 1000)),))
        for row in rows:
            for key in ("model_scores", "protocol_evidence", "feature_values", "top_features",
                        "threat_intel", "vulnerability_context", "gateway_context", "diode_health",
                        "explanation", "reasons", "explanation_llm"):
                if isinstance(row.get(key), str):
                    try:
                        row[key] = json.loads(row[key])
                    except json.JSONDecodeError:
                        pass
        return rows

    def save_alert_explanation(self, alert_id: str, explanation: dict[str, Any]) -> None:
        """Persist LLM-generated explanation for an alert (idempotent upsert)."""
        self._write(
            "UPDATE alerts SET explanation_llm = ? WHERE alert_id = ?",
            (json.dumps(explanation, default=str), alert_id),
        )

    def get_alert_explanation(self, alert_id: str) -> dict[str, Any] | None:
        """Return cached LLM explanation for an alert, or None if not yet generated."""
        rows = self._rows(
            "SELECT explanation_llm FROM alerts WHERE alert_id = ?", (alert_id,)
        )
        if not rows or rows[0].get("explanation_llm") is None:
            return None
        raw = rows[0]["explanation_llm"]
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return None
        return raw

    def alert(self, alert_id: str) -> dict[str, Any] | None:
        rows = self.alerts(1000)
        return next((r for r in rows if r["alert_id"] == alert_id), None)

    def save_flow(self, flow: dict[str, Any]) -> None:
        columns = [
            "timestamp", "src_ip", "dst_ip", "protocol", "packets", "bytes",
            "anomaly_score", "asset_id", "src_port", "dst_port", "packet_rate", "service",
        ]
        self._write(
            f"INSERT INTO flows({','.join(columns)}) VALUES({','.join('?' for _ in columns)})",
            tuple(flow.get(k) for k in columns),
        )

    def flows(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM flows ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 1000)),))

    def save_features(self, timestamp: str, asset_id: str | None, values: dict[str, Any]) -> None:
        self._write("INSERT INTO features(timestamp,asset_id,data) VALUES(?,?,?)", (timestamp, asset_id, json.dumps(values)))

    def save_model_score(self, timestamp: str, scores: dict[str, Any], alert_id: str | None = None) -> None:
        self._write("INSERT INTO model_scores(timestamp,alert_id,scores) VALUES(?,?,?)", (timestamp, alert_id, json.dumps(scores)))

    def assets(self) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM assets ORDER BY asset_id")

    def upsert_asset(self, asset: dict[str, Any]) -> None:
        self._write("INSERT OR REPLACE INTO assets(asset_id,hostname,ip,mac,vendor,device_type,firmware,software_version,protocols,criticality,authorized_peers) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(json.dumps(asset.get(k), default=str) if isinstance(asset.get(k), (list, dict)) else asset.get(k)
                          for k in ("asset_id", "hostname", "ip", "mac", "vendor", "device_type", "firmware", "software_version", "protocols", "criticality", "authorized_peers")))

    def feedback(self, item: dict[str, Any]) -> None:
        self._write("INSERT INTO feedback(alert_id,label,comment,timestamp) VALUES(?,?,?,?)",
                    (item["alert_id"], item["label"], item.get("comment", ""), datetime.now(timezone.utc).isoformat()))

    def audit(self, event: str, data: dict[str, Any]) -> None:
        self._write("INSERT INTO audit_log(timestamp,event,data) VALUES(?,?,?)",
                    (datetime.now(timezone.utc).isoformat(), event, json.dumps(data, default=str)))

    def metrics(self) -> dict[str, Any]:
        alert_count = self._rows("SELECT COUNT(*) AS n FROM alerts")[0]["n"]
        flows = self._rows("SELECT COUNT(*) AS n, COALESCE(SUM(packets),0) AS packets, COALESCE(SUM(bytes),0) AS bytes FROM flows")[0]
        levels = self._rows("SELECT risk_level, COUNT(*) AS count FROM alerts GROUP BY risk_level")
        categories = self._rows("SELECT attack_category, COUNT(*) AS count FROM alerts GROUP BY attack_category ORDER BY count DESC LIMIT 10")
        return {
            "total_alerts": alert_count, "packets": flows["packets"], "bytes": flows["bytes"],
            "flows": flows["n"],
            "severity": {str(row["risk_level"] or "UNKNOWN"): row["count"] for row in levels},
            "categories": [{"category": row["attack_category"] or "UNKNOWN", "count": row["count"]}
                           for row in categories],
        }

    def dashboard_summary(
        self, *, start: str | None = None, end: str | None = None,
        severity: str | None = None, category: str | None = None,
        source: str | None = None, destination: str | None = None,
    ) -> dict[str, Any]:
        """Return a bounded, filterable read model for the SOC dashboard."""
        clauses: list[str] = []
        values: list[Any] = []
        if start:
            clauses.append("timestamp >= ?")
            values.append(start)
        if end:
            clauses.append("timestamp <= ?")
            values.append(end)
        for column, value in (("risk_level", severity), ("attack_category", category),
                              ("src_ip", source), ("dst_ip", destination)):
            if value:
                clauses.append(f"{column} = ?")
                values.append(value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        alerts = self._rows(
            f"SELECT timestamp,risk_level,attack_category,src_ip,dst_ip,risk_score "
            f"FROM alerts{where} ORDER BY timestamp DESC LIMIT 1000", tuple(values)
        )
        severity_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        sources: dict[str, int] = {}
        destinations: dict[str, int] = {}
        timeseries: dict[str, int] = {}
        for row in alerts:
            level = str(row.get("risk_level") or "UNKNOWN")
            cat = str(row.get("attack_category") or "UNKNOWN")
            src = str(row.get("src_ip") or "UNKNOWN")
            dst = str(row.get("dst_ip") or "UNKNOWN")
            bucket = str(row.get("timestamp") or "")[:13]
            severity_counts[level] = severity_counts.get(level, 0) + 1
            category_counts[cat] = category_counts.get(cat, 0) + 1
            sources[src] = sources.get(src, 0) + 1
            destinations[dst] = destinations.get(dst, 0) + 1
            timeseries[bucket] = timeseries.get(bucket, 0) + 1
        flows = self._rows(
            "SELECT COUNT(*) AS count, COALESCE(SUM(packets),0) AS packets, "
            "COALESCE(SUM(bytes),0) AS bytes FROM flows"
        )
        protocol_rows = self._rows(
            "SELECT COALESCE(protocol,'UNKNOWN') AS name, COUNT(*) AS count, "
            "COALESCE(SUM(bytes),0) AS bytes FROM flows GROUP BY protocol "
            "ORDER BY count DESC LIMIT 10"
        )
        talkers = self._rows(
            "SELECT src_ip AS name, COUNT(*) AS count FROM flows "
            "WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 10"
        )
        subnets = self._rows(
            "SELECT COUNT(DISTINCT substr(src_ip,1, instr(src_ip,'.') + "
            "instr(substr(src_ip,instr(src_ip,'.') + 1),'.'))) AS count "
            "FROM flows WHERE src_ip IS NOT NULL"
        )
        return {
            "filters": {"start": start, "end": end, "severity": severity, "category": category,
                        "source": source, "destination": destination},
            "kpis": {"alerts": len(alerts), "critical": severity_counts.get("CRITICAL", 0),
                     "high": severity_counts.get("HIGH", 0), "packets": flows[0]["packets"],
                     "bytes": flows[0]["bytes"], "flows": flows[0]["count"]},
            "timeseries": [{"bucket": bucket, "count": count}
                           for bucket, count in sorted(timeseries.items())],
            "severity": [{"name": name, "count": count} for name, count in
                         sorted(severity_counts.items(), key=lambda item: item[1], reverse=True)],
            "categories": [{"name": name, "count": count} for name, count in
                           sorted(category_counts.items(), key=lambda item: item[1], reverse=True)],
            "top_sources": [{"name": name, "count": count} for name, count in
                            sorted(sources.items(), key=lambda item: item[1], reverse=True)[:10]],
            "top_destinations": [{"name": name, "count": count} for name, count in
                                 sorted(destinations.items(), key=lambda item: item[1], reverse=True)[:10]],
            "protocols": protocol_rows,
            "top_talkers": talkers,
            "active_subnets": int(subnets[0]["count"] or 0) if subnets else 0,
            "recent_alerts": self.alerts(20),
        }

    def save_model_version(self, metadata: dict[str, Any]) -> None:
        provenance = metadata.get("provenance") or {}
        self._write(
            "INSERT OR REPLACE INTO model_versions(model_name,model_version,feature_schema_version,"
            "training_dataset,training_timestamp,metrics,hyperparameters) VALUES(?,?,?,?,?,?,?)",
            (metadata.get("model_name"), metadata.get("model_version"),
             metadata.get("feature_schema_version"), json.dumps(provenance),
             provenance.get("training_timestamp"), json.dumps(metadata.get("metrics")),
             json.dumps(metadata.get("hyperparameters"))),
        )

    def model_versions(self) -> list[dict[str, Any]]:
        rows = self._rows("SELECT * FROM model_versions ORDER BY model_name")
        for row in rows:
            for key in ("training_dataset", "metrics", "hyperparameters"):
                if isinstance(row.get(key), str):
                    try:
                        row[key] = json.loads(row[key])
                    except json.JSONDecodeError:
                        pass
        return rows

    def heatmap(self, start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT substr(timestamp, 1, 10) AS day, substr(timestamp, 12, 2) AS hour, attack_category, COUNT(*) AS count FROM alerts"
        values: list[Any] = []
        clauses: list[str] = []
        if start:
            clauses.append("timestamp >= ?")
            values.append(start)
        if end:
            clauses.append("timestamp <= ?")
            values.append(end)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " GROUP BY day, hour, attack_category ORDER BY day, hour"
        return self._rows(query, tuple(values))

    def evidence_chain(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._rows(
            "SELECT chain_sequence, alert_id, timestamp, risk_level, attack_category, "
            "previous_hash, evidence_hash FROM alerts WHERE evidence_hash IS NOT NULL "
            "ORDER BY chain_sequence DESC LIMIT ?", (max(1, min(limit, 1000)),)
        )

    def model_timeseries(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._rows("SELECT timestamp, scores FROM model_scores ORDER BY timestamp DESC LIMIT ?",
                          (max(1, min(limit, 1000)),))
        for row in rows:
            try:
                row["scores"] = json.loads(row["scores"])
            except (TypeError, json.JSONDecodeError):
                row["scores"] = {}
        return rows

    def verify_integrity(self) -> dict[str, Any]:
        from diodeshield.integrity import verify_chain
        rows = self._rows("SELECT * FROM alerts WHERE evidence_hash IS NOT NULL ORDER BY chain_sequence ASC")
        for row in rows:
            for key in ("model_scores", "protocol_evidence", "feature_values", "top_features",
                        "threat_intel", "vulnerability_context", "gateway_context", "diode_health",
                        "explanation", "reasons"):
                if isinstance(row.get(key), str):
                    try:
                        row[key] = json.loads(row[key])
                    except json.JSONDecodeError:
                        pass
        return verify_chain(rows)

    def health(self) -> dict[str, Any]:
        self._conn.execute("SELECT 1").fetchone()
        return {"database": "healthy", "path": str(self.path)}
