import pytest
from fastapi.testclient import TestClient
from main import app
from models.schemas import FlowRecord, Alert
from detection.engine import engine
from evidence.ledger import ledger

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_system_status():
    response = client.get("/api/system/status")
    assert response.status_code == 200
    data = response.json()
    assert data["detection_engine"] == "ONLINE"
    assert "mode" in data

def test_detection_engine_benign():
    flow = FlowRecord(
        id="test_benign", timestamp="T", src_ip="10.0.0.1", dst_ip="8.8.8.8", 
        src_port=12345, dst_port=443, protocol="TCP", packets=10, bytes=1000, 
        duration=0.5, mean_iat=0.05, mean_packet_size=100.0, status="ESTABLISHED"
    )
    result = engine.analyze_flow(flow)
    assert result["classification"] in ["BENIGN", "OUTLIER"]
    assert "detection_score" in result

def test_detection_engine_malicious():
    flow = FlowRecord(
        id="test_malicious", timestamp="T", src_ip="10.0.0.1", dst_ip="185.15.2.1", 
        src_port=12345, dst_port=4444, protocol="TCP", packets=20, bytes=30000, 
        duration=60.0, mean_iat=3.0, mean_packet_size=1500.0, status="ESTABLISHED"
    )
    result = engine.analyze_flow(flow)
    assert result["classification"] in ["MALICIOUS", "OUTLIER"]
    assert result["rule_score"] > 0

def test_evidence_tamper_verification():
    flow = FlowRecord(
        id="ev_test", timestamp="T", src_ip="10.0.0.1", dst_ip="185.15.2.1", 
        src_port=12345, dst_port=4444, protocol="TCP", packets=20, bytes=30000, 
        duration=60.0, mean_iat=3.0, mean_packet_size=1500.0, status="ESTABLISHED"
    )
    result = engine.analyze_flow(flow)
    
    alert = Alert(
        id="test_alert_001", flow_id=flow.id, timestamp=flow.timestamp,
        classification=result["classification"], detection_score=result["detection_score"],
        severity=result["severity"], reasons=result["reasons"], evidence_hash="",
        src_ip=flow.src_ip, dst_ip=flow.dst_ip, protocol=flow.protocol,
        threat_type=result["threat_type"], feature_vector=result["feature_vector"],
        sub_scores=result["sub_scores"], rule_score=result["rule_score"],
        rule_reasons=result["rule_reasons"], random_forest_probability=result["random_forest_probability"],
        isolation_prediction=result["isolation_prediction"], isolation_decision_score=result["isolation_decision_score"],
        anomaly_signal=result["anomaly_signal"], ensemble_score=result["ensemble_score"],
        final_classification=result["final_classification"], attack_type=result["attack_type"]
    )
    
    record = ledger.generate_evidence(alert)
    alert.evidence_hash = record.current_hash
    
    # Original should pass
    assert ledger.verify_evidence(alert, record) == True
    
    # Tampered should fail
    alert.classification = "BENIGN"
    assert ledger.verify_evidence(alert, record) == False

def test_invalid_upload():
    response = client.post(
        "/api/flows/upload", 
        files={"file": ("test.txt", b"invalid json", "text/plain")}
    )
    assert response.status_code == 400
