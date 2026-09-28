import logging
import os
import json
import numpy as np
from typing import Tuple, List, Optional
from models.schemas import FlowRecord
from sklearn.ensemble import RandomForestClassifier, IsolationForest

logger = logging.getLogger("zyntrix.detection")

class RuleDetector:
    def evaluate(self, flow: FlowRecord) -> Tuple[float, List[str]]:
        rule_score = 0.0
        reasons = []
        # C2 / Exfiltration signatures
        if flow.dst_port in [4444, 6667, 3389]:
            rule_score += 0.4
            reasons.append(f"Suspicious destination port {flow.dst_port} (Potential Command and Control)")
        if flow.mean_packet_size > 1000 and flow.packets > 1000:
            rule_score += 0.5
            reasons.append("High volume of large packets (Potential Exfiltration / Volumetric DDoS)")
        
        # Discovery / Scanning signatures
        if flow.mean_packet_size < 100 and flow.packets > 100 and flow.packets <= 500:
            rule_score += 0.3
            reasons.append("High volume of small packets (Potential Network Discovery / Scanning)")
            
        # Volumetric
        if flow.packets > 10000:
            rule_score += 0.6
            reasons.append("Extreme packet rate (Potential Volumetric DDoS)")
            
        return min(rule_score, 1.0), reasons

class MLDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.is_trained = False
        self._train_baseline()

    def _extract_features(self, flow: FlowRecord) -> list:
        proto_map = {"TCP": 1, "UDP": 2}
        proto = proto_map.get(flow.protocol.upper(), 0)
        return [
            flow.duration,
            flow.packets,
            flow.bytes,
            flow.mean_iat,
            flow.mean_packet_size,
            proto
        ]

    def _train_baseline(self):
        data_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "train_labeled.json")
        if not os.path.exists(data_path):
            data_path = os.path.join(os.path.dirname(__file__), "..", "data", "train_labeled.json")
        
        try:
            with open(data_path, "r") as f:
                data = json.load(f)
            
            X = []
            y = []
            for item in data:
                proto_map = {"TCP": 1, "UDP": 2}
                proto = proto_map.get(item.get("protocol", "").upper(), 0)
                duration = item.get("duration", 0)
                packets = item.get("packets", 0)
                features = [
                    duration,
                    packets,
                    item.get("bytes", 0),
                    item.get("mean_iat", 0),
                    item.get("mean_packet_size", 0),
                    proto
                ]
                X.append(features)
                
                label = item.get("threat_class", "BENIGN")
                if label == "MALICIOUS":
                    y.append(2)
                elif label == "OUTLIER":
                    y.append(1)
                else:
                    y.append(0)
                    
            if X:
                self.model.fit(X, y)
                self.is_trained = True
                logger.info("ML Baseline trained successfully on %d samples.", len(X))
        except Exception as e:
            logger.error("Failed to train ML baseline: %s", e)

    def evaluate(self, flow: FlowRecord) -> Tuple[float, float, List[str]]:
        if not self.is_trained:
            return 0.1, 0.0, []
            
        features = self._extract_features(flow)
        probs = self.model.predict_proba([features])[0]
        classes = self.model.classes_
        
        score = 0.0
        malicious_prob = 0.0
        if 2 in classes:
            idx = list(classes).index(2)
            score += probs[idx]
            malicious_prob = probs[idx]
        if 1 in classes:
            idx = list(classes).index(1)
            score += probs[idx] * 0.5

        reasons = []
        if score > 0.5:
            reasons.append(f"Detected malicious pattern (malicious probability: {malicious_prob:.2f})")
            
        return score, malicious_prob, reasons

class AnomalyDetector:
    """Isolation Forest based anomaly detector.
    Trains on benign flows from the demo dataset and flags outliers.
    """
    def __init__(self):
        # Initialize model with reproducible parameters
        # Contamination sets the score threshold so that the expected proportion 
        # of training samples identified as outliers matches the specified value (5%).
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        self.is_trained = False
        self._train_baseline()

    def _extract_features(self, flow: FlowRecord) -> List[float]:
        """Extract the same feature vector used by the Random Forest.
        Order must match the training data.
        """
        proto_map = {"TCP": 1, "UDP": 2}
        proto = proto_map.get(flow.protocol.upper(), 0)
        return [
            flow.duration,
            flow.packets,
            flow.bytes,
            flow.mean_iat,
            flow.mean_packet_size,
            proto,
        ]

    def _train_baseline(self):
        """Train IsolationForest on benign flows.
        The dataset 'train_benign.json' contains exclusively normal flows.
        """
        data_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "train_benign.json"
        )
        if not os.path.exists(data_path):
            data_path = os.path.join(
                os.path.dirname(__file__), "..", "data", "train_benign.json"
            )
        try:
            with open(data_path, "r") as f:
                data = json.load(f)
            X: List[List[float]] = []
            for item in data:
                # Treat missing threat_class as benign for training purposes
                if item.get("threat_class", "BENIGN") != "BENIGN":
                    continue
                proto_map = {"TCP": 1, "UDP": 2}
                proto = proto_map.get(item.get("protocol", "").upper(), 0)
                duration = item.get("duration", 0)
                packets = item.get("packets", 0)
                X.append(
                    [
                        duration,
                        packets,
                        item.get("bytes", 0),
                        item.get("mean_iat", 0),
                        item.get("mean_packet_size", 0),
                        proto,
                    ]
                )
            if X:
                self.model.fit(X)
                self.is_trained = True
                logger.info("IsolationForest trained on %d benign samples.", len(X))
            else:
                logger.warning("No benign samples found for IsolationForest training.")
        except Exception as e:
            logger.error("Failed to train IsolationForest: %s", e)

    def evaluate(self, flow: FlowRecord) -> Tuple[float, int, float, List[str]]:
        """Return anomaly signal and optional reason.
        The IsolationForest predicts -1 for outliers and 1 for inliers.
        We map this to a signal in [0, 1] where higher means more anomalous.
        """
        if not self.is_trained:
            return 0.0, 1, 0.0, []
        features = self._extract_features(flow)
        prediction = self.model.predict([features])[0]
        # decision_function gives a signed distance; < 0 means outlier, > 0 means inlier
        decision = self.model.decision_function([features])[0]
        
        # Transformation mapping:
        # raw Isolation Forest output -> transformation -> normalized heuristic contribution
        # This is a custom normalized heuristic contribution for the ensemble, not a model probability.
        # We invert the negative decision score (so outliers are > 0).
        anomaly_signal = max(0.0, -decision)
        # Normalize by a maximum expected distance (e.g., 0.1) and clamp to [0,1].
        anomaly_signal = min(anomaly_signal / 0.1, 1.0)
        
        reasons: List[str] = []
        if prediction == -1 or anomaly_signal > 0.3:
            pred_str = "ANOMALOUS" if prediction == -1 else "NORMAL"
            reasons.append(f"Prediction: {pred_str}, Decision score: {decision:.2f}")
        return anomaly_signal, prediction, decision, reasons

class EnsembleEngine:
    def __init__(self):
        self.rule_engine = RuleDetector()
        self.ml_engine = MLDetector()
        self.anomaly_engine = AnomalyDetector()
        
    def analyze_flow(self, flow: FlowRecord) -> Dict[str, Any]:
        rule_score, rule_reasons_raw = self.rule_engine.evaluate(flow)
        ml_score, malicious_prob, ml_reasons_raw = self.ml_engine.evaluate(flow)
        anomaly_score, iso_pred, iso_decision, anomaly_reasons_raw = self.anomaly_engine.evaluate(flow)
        
        # Ensemble Mathematics:
        # final_score = RandomForest (0-1) × 0.5 + Rules (0-1) × 0.3 + IsolationForest (0-1) × 0.2
        # All inputs are on a 0-1 scale. 
        # Weights reflect the reliability of the signal: 
        # ML is a supervised model, Rules are explicit signatures, IF is unsupervised noise.
        detection_score = (ml_score * 0.5) + (rule_score * 0.3) + (anomaly_score * 0.2)
        
        reasons = []
        if ml_reasons_raw:
            reasons.append("Random Forest")
            reasons.extend(ml_reasons_raw)
        if anomaly_reasons_raw:
            reasons.append("Isolation Forest")
            reasons.extend(anomaly_reasons_raw)
        if rule_reasons_raw:
            reasons.append("Rules")
            reasons.extend(rule_reasons_raw)
            
        classification = "BENIGN"
        if detection_score > 0.7:
            classification = "MALICIOUS"
        elif detection_score > 0.4:
            classification = "OUTLIER"

        if not reasons:
            reasons = ["Traffic matches expected baseline profiles"]
        else:
            reasons.append("Final")
            reasons.append(classification)
            reasons.append(f"Detection score: {detection_score:.2f}")

        severity = "LOW"
        if detection_score > 0.85:
            severity = "CRITICAL"
        elif detection_score > 0.7:
            severity = "HIGH"
        elif detection_score > 0.4:
            severity = "MEDIUM"

        threat_type = None
        if classification == "MALICIOUS":
            if any("Exfiltration" in r for r in rule_reasons_raw + ml_reasons_raw):
                threat_type = "Data Exfiltration"
            elif any("Scanning" in r for r in rule_reasons_raw + ml_reasons_raw):
                threat_type = "Scanning / Probing"
            elif any("DDoS" in r for r in rule_reasons_raw + ml_reasons_raw):
                threat_type = "Volumetric DDoS"
            elif any("Command and Control" in r for r in rule_reasons_raw + ml_reasons_raw):
                threat_type = "Command and Control"
            else:
                threat_type = "Generic Anomalous Traffic"
                
        feature_vector = self.ml_engine._extract_features(flow)
        sub_scores = {
            "random_forest": ml_score,
            "isolation_forest": anomaly_score,
            "rules": rule_score
        }

        return {
            "classification": classification,
            "detection_score": detection_score,
            "severity": severity,
            "threat_type": threat_type,
            "reasons": reasons,
            "feature_vector": feature_vector,
            "sub_scores": sub_scores,
            "rule_score": rule_score,
            "rule_reasons": rule_reasons_raw,
            "random_forest_probability": malicious_prob,
            "isolation_prediction": int(iso_pred),
            "isolation_decision_score": float(iso_decision),
            "anomaly_signal": anomaly_score,
            "ensemble_score": detection_score,
            "final_classification": classification,
            "attack_type": threat_type
        }

engine = EnsembleEngine()
