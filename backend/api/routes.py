import json
import logging
from collections import deque
from datetime import datetime
from typing import Dict, List

from fastapi import APIRouter, File, HTTPException, UploadFile

from detection.engine import engine
from evidence.ledger import ledger
from graph.analyzer import analyzer
from models.schemas import (
    Alert,
    AnalyzeResponse,
    EvidenceRecord,
    FlowAnalysisRequest,
    FlowRecord,
    GraphData,
    InjectFlowRequest,
    SystemStatus,
    UploadResponse,
)
from services.demo_service import demo_service

logger = logging.getLogger("zyntrix.routes")

router = APIRouter()

# ---------------------------------------------------------------------------
# In-memory storage — bounded to prevent OOM in long-running demos
# ---------------------------------------------------------------------------
MAX_FLOWS = 10_000
MAX_ALERTS = 5_000
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

processed_flows: deque[FlowRecord] = deque(maxlen=MAX_FLOWS)
alerts: deque[Alert] = deque(maxlen=MAX_ALERTS)


# ---------------------------------------------------------------------------
# Cached stats counters — avoid O(n) scans on every poll
# ---------------------------------------------------------------------------
class _StatsCounters:
    """Light counters bumped on insert; avoids list comprehension every 2s."""
    __slots__ = ("suspicious", "malicious")

    def __init__(self) -> None:
        self.suspicious = 0
        self.malicious = 0

    def reset(self) -> None:
        self.suspicious = 0
        self.malicious = 0

_counters = _StatsCounters()


# ---------------------------------------------------------------------------
# Flow processing callback (used by DemoService + inject + upload)
# ---------------------------------------------------------------------------
async def process_new_flow(flow: FlowRecord) -> None:
    result = engine.analyze_flow(flow)
    classification = result["classification"]
    detection_score = result["detection_score"]
    severity = result["severity"]
    reasons = result["reasons"]
    threat_type = result["threat_type"]
    feature_vector = result["feature_vector"]
    sub_scores = result["sub_scores"]

    flow.threat_class = classification
    flow.detection_score = detection_score
    flow.severity = severity
    flow.threat_type = threat_type

    processed_flows.append(flow)

    # Update counters
    if classification == "MALICIOUS":
        _counters.malicious += 1
    elif classification == "OUTLIER":
        _counters.suspicious += 1

    # Update graph
    suspicion_increment = 0.0
    if classification == "MALICIOUS":
        suspicion_increment = 0.5
    elif classification == "OUTLIER":
        suspicion_increment = 0.2

    analyzer.add_flow(flow, suspicion_increment)

    # Generate alert for non-benign flows
    if classification in ("MALICIOUS", "OUTLIER"):
        alert = Alert(
            id=f"alert_{len(alerts):04d}",
            flow_id=flow.id,
            timestamp=flow.timestamp,
            classification=classification,
            detection_score=detection_score,
            severity=severity,
            reasons=reasons,
            evidence_hash="",
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            protocol=flow.protocol,
            threat_type=threat_type,
            feature_vector=feature_vector,
            sub_scores=sub_scores,
            rule_score=result["rule_score"],
            rule_reasons=result["rule_reasons"],
            random_forest_probability=result["random_forest_probability"],
            isolation_prediction=result["isolation_prediction"],
            isolation_decision_score=result["isolation_decision_score"],
            anomaly_signal=result["anomaly_signal"],
            ensemble_score=result["ensemble_score"],
            final_classification=result["final_classification"],
            attack_type=result["attack_type"]
        )

        evidence = ledger.generate_evidence(alert)
        alert.evidence_hash = evidence.current_hash

        alerts.append(alert)


# Register callback
demo_service.on_new_flow = process_new_flow


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@router.get("/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
@router.get("/stats")
def get_stats() -> dict:
    total_flows = len(processed_flows)

    # Build history from recent flows (O(n) but bounded by MAX_FLOWS)
    history: List[dict] = []
    chunk_size = 50
    flow_list = list(processed_flows)  # snapshot for iteration
    for i in range(0, max(1, len(flow_list)), chunk_size):
        chunk = flow_list[i : i + chunk_size]
        if not chunk:
            continue
        benign = sum(1 for f in chunk if f.threat_class == "BENIGN")
        suspicious = sum(1 for f in chunk if f.threat_class == "OUTLIER")
        malicious = sum(1 for f in chunk if f.threat_class == "MALICIOUS")
        try:
            time_str = datetime.fromisoformat(chunk[-1].timestamp).strftime("%H:%M:%S")
        except (ValueError, TypeError):
            time_str = chunk[-1].timestamp
        history.append({
            "time": time_str,
            "benign": benign,
            "suspicious": suspicious,
            "malicious": malicious,
        })

    history = history[-10:] if history else [
        {"time": "00:00", "benign": 0, "suspicious": 0, "malicious": 0}
    ]

    return {
        "flows_processed": total_flows,
        "suspicious_flows": _counters.suspicious,
        "malicious_flows": _counters.malicious,
        "active_alerts": len(alerts),
        "is_running": demo_service.is_running,
        "history": history,
    }


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------
@router.get("/flows", response_model=List[FlowRecord])
def get_flows(limit: int = 50) -> list:
    # Return most recent flows (deque supports slicing via list conversion)
    return list(processed_flows)[-limit:]


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
@router.get("/alerts", response_model=List[Alert])
def get_alerts() -> list:
    return list(alerts)


@router.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str) -> Alert:
    for a in alerts:
        if a.id == alert_id:
            return a
    raise HTTPException(status_code=404, detail="Alert not found")


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------
@router.get("/graph", response_model=GraphData)
def get_graph() -> GraphData:
    return analyzer.get_graph_data()


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
@router.get("/evidence", response_model=List[EvidenceRecord])
def get_evidence() -> list:
    return list(ledger.records)


@router.post("/evidence/verify")
def verify_evidence(alert_id: str) -> dict:
    target_alert = None
    target_record = None

    for a in alerts:
        if a.id == alert_id:
            target_alert = a
            break

    for r in ledger.records:
        if r.alert_id == alert_id:
            target_record = r
            break

    if not target_alert or not target_record:
        raise HTTPException(status_code=404, detail="Alert or evidence not found")

    is_valid = ledger.verify_evidence(target_alert, target_record)
    return {"verified": is_valid, "hash": target_record.current_hash}


# ---------------------------------------------------------------------------
# Demo Control
# ---------------------------------------------------------------------------
@router.post("/demo/start")
async def start_demo() -> dict:
    import networkx as nx

    processed_flows.clear()
    alerts.clear()
    _counters.reset()
    ledger.records = []
    ledger.last_hash = "0" * 64
    analyzer.G = nx.DiGraph()

    demo_service.load_data()
    await demo_service.start()
    logger.info("Demo started")
    return {"status": "Demo started"}


@router.post("/demo/stop")
def stop_demo() -> dict:
    demo_service.stop()
    logger.info("Demo stopped")
    return {"status": "Demo stopped"}


@router.post("/demo/inject")
async def inject_demo_flow(request: InjectFlowRequest) -> dict:
    await demo_service.inject_flow(request.flow)
    return {"status": "Flow injected successfully"}


@router.post("/reset")
def reset_system() -> dict:
    import networkx as nx

    processed_flows.clear()
    alerts.clear()
    _counters.reset()
    ledger.records = []
    ledger.last_hash = "0" * 64
    analyzer.G = nx.DiGraph()
    demo_service.stop()
    logger.info("System reset")
    return {"status": "System reset successfully"}


# ---------------------------------------------------------------------------
# Flow Analysis
# ---------------------------------------------------------------------------
@router.post("/flows/analyze", response_model=AnalyzeResponse)
def analyze_flow(request: FlowAnalysisRequest) -> AnalyzeResponse:
    result = engine.analyze_flow(
        request.flow
    )

    features = {
        "packets": request.flow.packets,
        "bytes": request.flow.bytes,
        "duration": request.flow.duration,
        "mean_iat": request.flow.mean_iat,
        "mean_packet_size": request.flow.mean_packet_size,
        "protocol": request.flow.protocol,
    }

    return AnalyzeResponse(
        classification=result["classification"],
        detection_score=result["detection_score"],
        severity=result["severity"],
        threat_type=result["threat_type"],
        reasons=result["reasons"],
        features=features,
        rule_score=result["rule_score"],
        rule_reasons=result["rule_reasons"],
        random_forest_probability=result["random_forest_probability"],
        isolation_prediction=result["isolation_prediction"],
        isolation_decision_score=result["isolation_decision_score"],
        anomaly_signal=result["anomaly_signal"],
        ensemble_score=result["ensemble_score"],
        final_classification=result["final_classification"],
        attack_type=result["attack_type"]
    )


# ---------------------------------------------------------------------------
# File Upload — with validation
# ---------------------------------------------------------------------------
ALLOWED_CONTENT_TYPES = {
    "application/json",
    "text/plain",                  # sometimes JSON files come as text/plain
    "application/octet-stream",    # fallback for generic binary
}

@router.post("/flows/upload", response_model=UploadResponse)
async def upload_flows(file: UploadFile = File(...)) -> UploadResponse:
    # --- Validate content type ---
    if file.content_type and file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file.content_type}. Upload JSON files only.",
        )

    # --- Validate filename extension ---
    if file.filename:
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in ("json", ""):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file extension: .{ext}. Upload .json files only.",
            )

    # --- Read with size limit ---
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
        )

    parsed_records = 0
    errors = 0

    try:
        data = json.loads(content.decode("utf-8"))
        if not isinstance(data, list):
            data = [data]

        for item in data:
            try:
                flow = FlowRecord(**item)
                await process_new_flow(flow)
                parsed_records += 1
            except Exception:
                errors += 1

        return UploadResponse(
            parsed_records=parsed_records,
            errors=errors,
            message="Upload processed",
        )
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(
            status_code=400,
            detail="Failed to parse upload: file must contain valid UTF-8 JSON.",
        )


# ---------------------------------------------------------------------------
# System Status
# ---------------------------------------------------------------------------
@router.get("/system/status", response_model=SystemStatus)
def get_system_status() -> SystemStatus:
    mode = "DEMO MODE" if demo_service.is_running else "IDLE"
    return SystemStatus(
        flow_ingestion="ONLINE" if demo_service.is_running else "IDLE",
        feature_extraction="ONLINE" if demo_service.is_running else "IDLE",
        detection_engine="ONLINE",
        graph_engine="ONLINE",
        alert_engine="ONLINE",
        evidence_ledger="ONLINE",
        mode=mode,
    )
