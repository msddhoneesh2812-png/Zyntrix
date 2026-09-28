from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class FlowRecord(BaseModel):
    id: str
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packets: int
    bytes: int
    duration: float
    mean_iat: float
    mean_packet_size: float
    status: str
    threat_class: Optional[str] = None
    detection_score: Optional[float] = Field(None, description="Normalized ensemble detection score (0-1), not a calibrated probability")
    severity: Optional[str] = None
    threat_type: Optional[str] = None

class FlowAnalysisRequest(BaseModel):
    flow: FlowRecord

class AnalyzeResponse(BaseModel):
    classification: str
    detection_score: float
    severity: str
    threat_type: Optional[str]
    reasons: List[str]
    features: Dict[str, Any]
    rule_score: float = 0.0
    rule_reasons: List[str] = []
    random_forest_probability: float = 0.0
    isolation_prediction: int = 1
    isolation_decision_score: float = 0.0
    anomaly_signal: float = 0.0
    ensemble_score: float = 0.0
    final_classification: str = ""
    attack_type: Optional[str] = None

class InjectFlowRequest(BaseModel):
    flow: FlowRecord

class UploadResponse(BaseModel):
    parsed_records: int
    errors: int
    message: str

class AlertReason(BaseModel):
    description: str

class Alert(BaseModel):
    id: str
    flow_id: str
    timestamp: str
    classification: str # "BENIGN | MALICIOUS | OUTLIER"
    detection_score: float = Field(..., description="Normalized ensemble detection score (0-1), not a calibrated probability")
    severity: str # "LOW | MEDIUM | HIGH | CRITICAL"
    reasons: List[str]
    evidence_hash: str
    src_ip: str
    dst_ip: str
    protocol: str
    threat_type: Optional[str] = None
    feature_vector: Optional[List[float]] = None
    sub_scores: Optional[Dict[str, float]] = None
    rule_score: float = 0.0
    rule_reasons: List[str] = []
    random_forest_probability: float = 0.0
    isolation_prediction: int = 1
    isolation_decision_score: float = 0.0
    anomaly_signal: float = 0.0
    ensemble_score: float = 0.0
    final_classification: str = ""
    attack_type: Optional[str] = None

class EvidenceRecord(BaseModel):
    id: str
    alert_id: str
    timestamp: str
    previous_hash: str
    current_hash: str
    alert_classification: str
    feature_vector: Optional[List[float]] = None
    sub_scores: Optional[Dict[str, float]] = None
    rule_score: float = 0.0
    rule_reasons: List[str] = []
    random_forest_probability: float = 0.0
    isolation_prediction: int = 1
    isolation_decision_score: float = 0.0
    anomaly_signal: float = 0.0
    ensemble_score: float = 0.0
    final_classification: str = ""
    attack_type: Optional[str] = None

class SystemStatus(BaseModel):
    flow_ingestion: str
    feature_extraction: str
    detection_engine: str
    graph_engine: str
    alert_engine: str
    evidence_ledger: str
    mode: str # "LIVE" | "DEMO MODE" | "IDLE"

class GraphNode(BaseModel):
    id: str
    group: int
    suspicion_score: float

class GraphLink(BaseModel):
    source: str
    target: str
    value: int

class GraphData(BaseModel):
    nodes: List[GraphNode]
    links: List[GraphLink]
