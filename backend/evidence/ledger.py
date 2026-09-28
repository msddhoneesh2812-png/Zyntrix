import hashlib
import json
from datetime import datetime
from models.schemas import EvidenceRecord, Alert

from collections import deque

class EvidenceLedger:
    def __init__(self):
        self.records = deque(maxlen=5000)
        self.last_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        
    def _hash_data(self, data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def generate_evidence(self, alert: Alert) -> EvidenceRecord:
        # Create a deterministically serialized string of the alert data
        # We explicitly serialize only the mandatory and specific fields in a fixed order.
        features_str = json.dumps(alert.feature_vector) if alert.feature_vector else ""
        sub_scores_str = json.dumps(alert.sub_scores, sort_keys=True) if alert.sub_scores else ""
        rule_reasons_str = json.dumps(alert.rule_reasons)
        alert_data = f"id:{alert.id}|flow_id:{alert.flow_id}|timestamp:{alert.timestamp}|classification:{alert.classification}|detection_score:{alert.detection_score:.4f}|severity:{alert.severity}|src_ip:{alert.src_ip}|dst_ip:{alert.dst_ip}|protocol:{alert.protocol}|features:{features_str}|scores:{sub_scores_str}|rule_score:{alert.rule_score:.4f}|rule_reasons:{rule_reasons_str}|rf_prob:{alert.random_forest_probability:.4f}|iso_pred:{alert.isolation_prediction}|iso_score:{alert.isolation_decision_score:.4f}|anomaly_sig:{alert.anomaly_signal:.4f}|ensemble_score:{alert.ensemble_score:.4f}|final_class:{alert.final_classification}|attack_type:{alert.attack_type}"
        
        timestamp = datetime.now().isoformat()
        
        # Hash is based on: alert_data + timestamp + previous_hash
        data_to_hash = f"{alert_data}|{timestamp}|{self.last_hash}"
        current_hash = self._hash_data(data_to_hash)
        
        record = EvidenceRecord(
            id=f"ev_{len(self.records):04d}",
            alert_id=alert.id,
            timestamp=timestamp,
            previous_hash=self.last_hash,
            current_hash=current_hash,
            alert_classification=alert.classification,
            feature_vector=alert.feature_vector,
            sub_scores=alert.sub_scores
        )
        
        self.records.append(record)
        self.last_hash = current_hash
        
        return record

    def verify_evidence(self, alert: Alert, record: EvidenceRecord) -> bool:
        features_str = json.dumps(alert.feature_vector) if alert.feature_vector else ""
        sub_scores_str = json.dumps(alert.sub_scores, sort_keys=True) if alert.sub_scores else ""
        rule_reasons_str = json.dumps(alert.rule_reasons)
        alert_data = f"id:{alert.id}|flow_id:{alert.flow_id}|timestamp:{alert.timestamp}|classification:{alert.classification}|detection_score:{alert.detection_score:.4f}|severity:{alert.severity}|src_ip:{alert.src_ip}|dst_ip:{alert.dst_ip}|protocol:{alert.protocol}|features:{features_str}|scores:{sub_scores_str}|rule_score:{alert.rule_score:.4f}|rule_reasons:{rule_reasons_str}|rf_prob:{alert.random_forest_probability:.4f}|iso_pred:{alert.isolation_prediction}|iso_score:{alert.isolation_decision_score:.4f}|anomaly_sig:{alert.anomaly_signal:.4f}|ensemble_score:{alert.ensemble_score:.4f}|final_class:{alert.final_classification}|attack_type:{alert.attack_type}"
        data_to_hash = f"{alert_data}|{record.timestamp}|{record.previous_hash}"
        computed_hash = self._hash_data(data_to_hash)
        return computed_hash == record.current_hash

ledger = EvidenceLedger()
