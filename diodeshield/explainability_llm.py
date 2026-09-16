"""
DIODESHIELD LLM Explainability Layer
=====================================
Task 2: LLM-generated alert narratives and audio scripts for SOC analysts.

Architecture (air-gapped-safe first):
  1. DeterministicLocalExplainer (DEFAULT) — zero external deps, zero GPU,
     produces precise 3–6 sentence SOC-analyst narratives from alert metadata
     and TreeSHAP top features. Safe for NTRO/unidirectional data-diode
     environments.
  2. ExternalAPIExplainer (OPTIONAL) — connects to Gemini API, OpenAI, or a
     local Ollama endpoint when the appropriate env-var is set. Automatically
     falls back to the local engine on any error or timeout.

All generated explanations are returned as:
  {
    "narrative": str,       # 3–6 sentence plain-English SOC narrative
    "audio_script": str,    # 1-sentence TTS-friendly summary, no jargon
    "generated_at": str,    # ISO-8601 UTC timestamp
    "backend": str          # "local_deterministic" | "gemini" | "openai" | "ollama"
  }

The caller (api/main.py) is responsible for caching results in db.py via
save_alert_explanation() so explanations are not regenerated redundantly.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Service/port resolution helper (mirrors features/protocol.py)
# ---------------------------------------------------------------------------
_PORT_MAP: dict[int, str] = {
    20000: "DNP3",
    44818: "EtherNet/IP",
    4840:  "OPC UA",
    2404:  "IEC-60870-5-104",
    502:   "Modbus/TCP",
    102:   "S7comm/ISO-TSAP",
    19001: "Custom OT Telemetry",
    443:   "HTTPS",
    80:    "HTTP",
    53:    "DNS",
    22:    "SSH",
    123:   "NTP",
    161:   "SNMP",
    162:   "SNMP Trap",
    21:    "FTP",
    23:    "Telnet",
    4444:  "C2/Reverse-Shell (known bad port)",
}


def _resolve_port(port: int | None) -> str:
    if port is None:
        return "unknown port"
    return _PORT_MAP.get(int(port), f"port {port}")


# ---------------------------------------------------------------------------
# Risk-level helpers
# ---------------------------------------------------------------------------
_RISK_PHRASES = {
    "CRITICAL": "critical-severity",
    "HIGH":     "high-severity",
    "MEDIUM":   "medium-severity",
    "LOW":      "low-severity",
    "INFO":     "informational",
}

_CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "UDP_FLOOD":          "a volumetric UDP flood consistent with a denial-of-service attack",
    "IP_SPOOF":           "IP address spoofing targeting the OT control plane",
    "PAYLOAD_ALTERATION": "unauthorised payload modification on the Modbus/TCP channel",
    "C2_BEACON":          "periodic command-and-control beaconing to an external host",
    "OT_RECON":           "active reconnaissance scanning of OT field devices",
    "POLICY_VIOLATION":   "a traffic policy violation on the industrial segment",
    "BASELINE_DEVIATION": "a significant deviation from established traffic baselines",
    "ANOMALY":            "an anomalous traffic pattern with no clear threat category",
}


def _category_desc(category: str | None) -> str:
    if not category:
        return "an anomalous traffic event"
    return _CATEGORY_DESCRIPTIONS.get(str(category).upper(), f"a {category} event")


def _parse_top_features(raw_features: Any) -> list[tuple[str, Any, float]]:
    """Parse top features into a normalized list of (feature_name, value, contribution)."""
    if isinstance(raw_features, str):
        try:
            raw_features = json.loads(raw_features)
        except Exception:
            raw_features = []
    if not isinstance(raw_features, list):
        return []
    parsed = []
    for item in raw_features:
        if isinstance(item, dict):
            name = str(item.get("feature") or item.get("name") or "unknown_feature")
            val = item.get("value")
            contrib = float(item.get("contribution") or 0.0)
            parsed.append((name, val, contrib))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            try:
                contrib = float(item[1])
            except (ValueError, TypeError):
                contrib = 0.0
            parsed.append((str(item[0]), None, contrib))
        elif isinstance(item, str):
            parsed.append((item, None, 0.0))
    return parsed


_FEATURE_LABELS: dict[str, str] = {
    "fan_out": "destination port/IP fan-out",
    "udp_burst_score": "volumetric UDP packet burst",
    "ip_spoofing_score": "spoofed IP identity / forged address headers",
    "packet_alteration_score": "unauthorized payload alteration / CRC mismatch",
    "beacon_score": "C2 command-and-control interval beaconing",
    "baseline_deviation": "statistical deviation from historical OT baseline",
    "protocol_anomaly_score": "Modbus protocol function code / structure anomaly",
    "bytes_per_sec": "abnormal bandwidth / byte transfer surge",
    "iat_cv": "inter-arrival time variation anomaly",
    "periodicity_score": "high cyclic regularity",
    "ttl_anomaly_score": "abnormal Time-To-Live hop count",
    "lateral_movement_score": "unauthorized internal segment traversing attempt",
    "behavior_anomaly_score": "abnormal device behavioral profile",
    "payload_integrity_anomaly": "payload checksum or HMAC verification failure",
}


# ---------------------------------------------------------------------------
# Deterministic Local Explainer (default, air-gapped)
# ---------------------------------------------------------------------------

class DeterministicLocalExplainer:
    """
    Produces precise, deterministic SOC-analyst narratives with zero external
    network calls and zero GPU requirements.  Safe for unidirectional / NTRO
    data-diode environments.
    """

    name: str = "local_deterministic"

    def explain(self, alert: dict[str, Any]) -> dict[str, str]:
        category = str(alert.get("attack_category") or "ANOMALY")
        risk_level = str(alert.get("risk_level") or "MEDIUM")
        risk_score = float(alert.get("risk_score") or 0.0)
        src_ip = alert.get("src_ip") or "unknown"
        dst_ip = alert.get("dst_ip") or "unknown"
        src_port = alert.get("src_port")
        dst_port = alert.get("dst_port")
        protocol = alert.get("protocol") or "unknown"
        confidence = float(alert.get("confidence") or 0.0)

        # Top SHAP features
        raw_top: list[Any] = alert.get("top_features") or []
        parsed_features = _parse_top_features(raw_top)
        feat_names = [f[0] for f in parsed_features[:3]]

        feat_descriptions = [
            f"{_FEATURE_LABELS.get(name, name.replace('_', ' '))}" + (f" (impact: +{contrib:.2f})" if contrib > 0 else "")
            for name, _, contrib in parsed_features[:3]
        ]
        feat_str = ", ".join(feat_descriptions) if feat_descriptions else "volumetric statistics"

        # Model scores summary
        model_scores: dict[str, Any] = alert.get("model_scores") or {}
        if isinstance(model_scores, str):
            try:
                model_scores = json.loads(model_scores)
            except Exception:
                model_scores = {}
        agreeing = sum(1 for v in model_scores.values() if isinstance(v, (int, float)) and float(v) >= 0.5)
        branch_count = len(model_scores) if model_scores else 5

        dst_service = _resolve_port(dst_port)
        src_service_str = f" from {_resolve_port(src_port)}" if src_port else ""

        risk_phrase = _RISK_PHRASES.get(risk_level.upper(), "medium-severity")
        cat_desc = _category_desc(category)
        ts = alert.get("timestamp") or datetime.now(timezone.utc).isoformat()

        narrative = (
            f"At {ts}, DIODESHIELD detected {cat_desc} on the monitored OT network segment. "
            f"Traffic originated from {src_ip}{src_service_str} targeting {dst_ip} ({dst_service}) "
            f"via {protocol}, generating a {risk_phrase} alert with a composite risk score of "
            f"{risk_score:.2f} and ensemble confidence of {confidence:.0%}. "
            f"The top contributing indicators were: {feat_str}. "
            f"{agreeing} out of {branch_count} AI detection branches voted to flag this flow as malicious. "
            f"This event was captured passively on the receive side of the data-diode boundary; "
            f"no retransmission, blocking, or active response was performed by DIODESHIELD."
        )

        # 1-sentence TTS audio script — no jargon, plain English
        primary_driver = (
            _FEATURE_LABELS.get(parsed_features[0][0], parsed_features[0][0].replace('_', ' '))
            if parsed_features else 'traffic anomaly'
        )
        audio_script = (
            f"Security alert: {risk_phrase.replace('-', ' ')} {category.replace('_', ' ').lower()} "
            f"detected from {src_ip} to {dst_ip} on {dst_service}, "
            f"risk score {risk_score:.2f}, driven by {primary_driver}."
        )

        return {
            "narrative":    narrative,
            "audio_script": audio_script,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "backend":      self.name,
        }


# ---------------------------------------------------------------------------
# External API Explainer (optional, with automatic fallback)
# ---------------------------------------------------------------------------

class ExternalAPIExplainer:
    """
    Connects to Gemini API, OpenAI, or a local Ollama server.
    Falls back to DeterministicLocalExplainer on any error / timeout.
    """

    def __init__(self) -> None:
        self._local = DeterministicLocalExplainer()
        self._gemini_key: str | None = os.getenv("DIODESHIELD_LLM_API_KEY") or os.getenv("GEMINI_API_KEY")
        self._openai_key: str | None = os.getenv("OPENAI_API_KEY")
        self._ollama_url: str | None = os.getenv("DIODESHIELD_OLLAMA_URL")
        self._timeout = 8  # seconds

    def _build_prompt(self, alert: dict[str, Any]) -> str:
        parsed_features = _parse_top_features(alert.get("top_features") or [])
        feat_str = ", ".join(
            f"{_FEATURE_LABELS.get(name, name)} (score: {contrib:.2f})"
            for name, _, contrib in parsed_features[:3]
        ) or "none available"
        return (
            "You are a cybersecurity SOC analyst assistant for an OT/ICS environment. "
            "Write ONLY factual information from the data below. Do NOT speculate.\n\n"
            f"Alert category: {alert.get('attack_category')}\n"
            f"Risk level: {alert.get('risk_level')} | Risk score: {alert.get('risk_score')}\n"
            f"Source: {alert.get('src_ip')}:{alert.get('src_port')} "
            f"-> {alert.get('dst_ip')}:{alert.get('dst_port')} ({alert.get('protocol')})\n"
            f"Packet count: {alert.get('packet_count')} | Bytes: {alert.get('byte_count')} "
            f"| Duration: {alert.get('duration_seconds')}s\n"
            f"Top TreeSHAP features: {feat_str}\n"
            f"Timestamp: {alert.get('timestamp')}\n\n"
            "Output JSON only:\n"
            "{\n"
            '  "narrative": "<3-6 sentence plain-English explanation for SOC analyst>",\n'
            '  "audio_script": "<1-sentence TTS-friendly summary, no jargon>"\n'
            "}"
        )

    def _call_gemini(self, prompt: str) -> dict[str, str] | None:
        try:
            import urllib.request
            url = (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                f"gemini-2.0-flash:generateContent?key={self._gemini_key}"
            )
            body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            # Strip markdown code fences if present
            text = text.strip()
            if text.startswith("```"):
                text = "\n".join(text.split("\n")[1:])
            if text.endswith("```"):
                text = "\n".join(text.split("\n")[:-1])
            parsed = json.loads(text.strip())
            parsed["backend"] = "gemini"
            return parsed
        except Exception:
            return None

    def _call_openai(self, prompt: str) -> dict[str, str] | None:
        try:
            import urllib.request
            url = "https://api.openai.com/v1/chat/completions"
            body = json.dumps({
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
                "max_tokens": 400,
            }).encode()
            req = urllib.request.Request(url, data=body, headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._openai_key}",
            })
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
            parsed = json.loads(data["choices"][0]["message"]["content"])
            parsed["backend"] = "openai"
            return parsed
        except Exception:
            return None

    def _call_ollama(self, prompt: str) -> dict[str, str] | None:
        try:
            import urllib.request
            url = f"{self._ollama_url}/api/generate"
            body = json.dumps({"model": "mistral", "prompt": prompt, "stream": False, "format": "json"}).encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
            parsed = json.loads(data.get("response", "{}"))
            parsed["backend"] = "ollama"
            return parsed
        except Exception:
            return None

    def explain(self, alert: dict[str, Any]) -> dict[str, str]:
        prompt = self._build_prompt(alert)
        result: dict[str, str] | None = None
        if self._gemini_key:
            result = self._call_gemini(prompt)
        if result is None and self._openai_key:
            result = self._call_openai(prompt)
        if result is None and self._ollama_url:
            result = self._call_ollama(prompt)
        if result is None:
            result = self._local.explain(alert)
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        return result


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

class LLMExplainer:
    """
    Factory that selects the appropriate backend based on environment variables.

    Usage::

        explainer = LLMExplainer()
        explanation = explainer.explain(alert_dict)
        # -> {"narrative": "...", "audio_script": "...", "generated_at": "...", "backend": "..."}
    """

    def __init__(self) -> None:
        has_external = bool(
            os.getenv("DIODESHIELD_LLM_API_KEY")
            or os.getenv("GEMINI_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("DIODESHIELD_OLLAMA_URL")
        )
        self._backend: DeterministicLocalExplainer | ExternalAPIExplainer = (
            ExternalAPIExplainer() if has_external else DeterministicLocalExplainer()
        )

    def explain(self, alert: dict[str, Any]) -> dict[str, str]:
        """Generate narrative + audio_script for a single alert dict."""
        try:
            return self._backend.explain(alert)
        except Exception as exc:
            # Absolute last-resort fallback — never block alert delivery
            return {
                "narrative":    f"Explanation generation failed: {exc}",
                "audio_script": "Alert detected; explanation unavailable.",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "backend":      "fallback_error",
            }
