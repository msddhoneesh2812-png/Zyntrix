import json
import os
import sys
import platform
import sklearn
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__)))
from detection.engine import engine
from models.schemas import FlowRecord, Alert
from evidence.ledger import ledger

def generate_controlled_cases():
    print("\n" + "="*50)
    print("CONTROLLED TEST CASES")
    print("="*50)
    
    cases = [
        ("BENIGN", FlowRecord(id="c1", timestamp="T", src_ip="192.168.1.10", dst_ip="8.8.8.8", src_port=50000, dst_port=443, protocol="TCP", packets=10, bytes=1000, duration=0.5, mean_iat=0.05, mean_packet_size=100.0, status="ESTABLISHED")),
        ("SCANNING", FlowRecord(id="c2", timestamp="T", src_ip="192.168.1.11", dst_ip="1.1.1.1", src_port=50001, dst_port=80, protocol="TCP", packets=150, bytes=9600, duration=1.0, mean_iat=0.005, mean_packet_size=64.0, status="ESTABLISHED")),
        ("VOLUMETRIC ATTACK", FlowRecord(id="c3", timestamp="T", src_ip="192.168.1.12", dst_ip="104.18.2.1", src_port=50002, dst_port=80, protocol="UDP", packets=20000, bytes=20000000, duration=2.0, mean_iat=0.0001, mean_packet_size=1000.0, status="ESTABLISHED")),
        ("COMMAND & CONTROL", FlowRecord(id="c4", timestamp="T", src_ip="192.168.1.13", dst_ip="185.15.2.1", src_port=50003, dst_port=4444, protocol="TCP", packets=15, bytes=22500, duration=60.0, mean_iat=4.0, mean_packet_size=1500.0, status="ESTABLISHED")),
        ("EXFILTRATION", FlowRecord(id="c5", timestamp="T", src_ip="192.168.1.14", dst_ip="185.15.2.2", src_port=50004, dst_port=443, protocol="TCP", packets=3000, bytes=4500000, duration=120.0, mean_iat=0.04, mean_packet_size=1500.0, status="ESTABLISHED")),
        ("ANOMALOUS", FlowRecord(id="c6", timestamp="T", src_ip="192.168.1.15", dst_ip="142.250.190.46", src_port=50005, dst_port=8080, protocol="UDP", packets=300, bytes=24000, duration=15.0, mean_iat=0.05, mean_packet_size=80.0, status="ESTABLISHED")),
    ]
    
    for name, flow in cases:
        result = engine.analyze_flow(flow)
        print(f"\n--- {name} ---")
        print(f"Input: {flow.protocol} dst_port={flow.dst_port} pkts={flow.packets} bytes={flow.bytes} dur={flow.duration}")
        print(f"Rules: score={result['rule_score']:.2f}, reasons={result['rule_reasons']}")
        print(f"Random Forest: prob={result['random_forest_probability']:.2f}")
        print(f"Isolation Forest: pred={'ANOMALOUS' if result['isolation_prediction'] == -1 else 'NORMAL'}, score={result['isolation_decision_score']:.2f}, signal={result['anomaly_signal']:.2f}")
        print(f"Ensemble: score={result['ensemble_score']:.2f}")
        print(f"Final class: {result['final_classification']}")
        print(f"Reasons: {result['reasons']}")

def evaluate_evidence_verification():
    print("\n" + "="*50)
    print("14. EVIDENCE VERIFICATION TEST")
    print("="*50)
    flow = FlowRecord(id="ev_test", timestamp="T", src_ip="192.168.1.10", dst_ip="185.15.2.1", src_port=50000, dst_port=4444, protocol="TCP", packets=20, bytes=30000, duration=60.0, mean_iat=3.0, mean_packet_size=1500.0, status="ESTABLISHED")
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
    
    pass_original = ledger.verify_evidence(alert, record)
    print(f"Original Alert -> Hash -> Verification = {'PASS' if pass_original else 'FAIL'}")
    
    # Tamper
    alert.classification = "BENIGN"
    pass_tampered = ledger.verify_evidence(alert, record)
    print(f"Modified Alert -> Recalculate -> Verification = {'FAIL' if not pass_tampered else 'PASS'}")

def main():
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "test_stream.json")
    if not os.path.exists(data_path):
        print(f"Test data not found at {data_path}.")
        return

    with open(data_path, "r") as f:
        data = json.load(f)

    y_true = []
    y_pred_ensemble = []
    y_pred_rf = []
    y_pred_if = []
    y_pred_rules = []
    
    from collections import defaultdict
    attack_types = defaultdict(lambda: [0, 0, 0])
    
    fp_cases = []
    fn_cases = []
    
    for item in data:
        flow = FlowRecord(**item)
        
        # Ground truth recovery from generating script logic:
        # test_stream generation has 20% benign, 20% anomalous (labeled BENIGN)
        # 20% outlier, 40% malicious (exfiltration, scanning, ddos)
        true_class = flow.threat_class
        y_true.append(true_class)
        
        # Determine actual attack type from ground truth for per-attack metrics
        actual_attack = None
        if true_class in ["MALICIOUS", "OUTLIER"]:
            actual_attack = item.get("threat_type")
            if not actual_attack:
                actual_attack = "UNKNOWN / NOT MAPPED"
            
        if actual_attack:
            attack_types[actual_attack][0] += 1
            
        result = engine.analyze_flow(flow)
        pred_class = result["classification"]
        y_pred_ensemble.append(pred_class)
        
        # RF Prediction
        rf_prob = result["random_forest_probability"]
        if rf_prob > 0.5: rf_class = "MALICIOUS"
        elif result["sub_scores"]["random_forest"] > 0.4: rf_class = "OUTLIER"
        else: rf_class = "BENIGN"
        y_pred_rf.append(rf_class)
        
        # IF Prediction (Binary: BENIGN vs NON-BENIGN)
        # Prediction: -1 is anomalous (NON-BENIGN), 1 is normal (BENIGN)
        if_class = "NON-BENIGN" if result["isolation_prediction"] == -1 else "BENIGN"
        y_true_binary = "BENIGN" if true_class == "BENIGN" else "NON-BENIGN"
        y_pred_if.append((y_true_binary, if_class))
        
        # Rules Prediction
        rule_score = result["rule_score"]
        rule_class = "MALICIOUS" if rule_score > 0.5 else ("OUTLIER" if rule_score > 0 else "BENIGN")
        y_pred_rules.append(rule_class)
        
        if actual_attack:
            if pred_class in ["MALICIOUS", "OUTLIER"]: # Counted as detected
                attack_types[actual_attack][1] += 1
            else:
                attack_types[actual_attack][2] += 1
                
        if true_class == "BENIGN" and pred_class != "BENIGN":
            fp_cases.append(result)
        elif true_class in ["MALICIOUS", "OUTLIER"] and pred_class == "BENIGN":
            fn_cases.append(result)

    print("# ZYNTRIX PHASE 3 EVALUATION REPORT\n")
    print("## 1. Evaluation Method")
    print("1. Which dataset trained Random Forest? `data/train_labeled.json`")
    print("2. Which dataset trained Isolation Forest? `data/train_benign.json`")
    print("3. Which dataset was evaluated? `data/test_stream.json`")
    print("4. Was the evaluation dataset ever seen during training? No, they are generated separately.")
    print("5. Were labels used as model features? No, features are extracted strictly from flow metadata (duration, packets, bytes, mean_iat, mean_packet_size, protocol).")
    print("6. Are synthetic samples generated using the same distributions as training data? Yes, they use identical underlying statistical bounds, although the test stream presents a sequential narrative.")
    print("7. Is the test set independent enough to be meaningful? It effectively measures performance on this controlled synthetic distribution, but does not prove generalization to unseen real-world distributions.\n")

    print("## 2. Training Dataset")
    print("Synthetic controlled datasets generated via `data/generate_demo.py`.")
    print("Random Forest Training: 400 mixed labeled samples.")
    
    print("\n## 3. Test Dataset")
    print("Test Stream: 500 samples.")
    print(f"Class distribution: BENIGN ({y_true.count('BENIGN')}), OUTLIER ({y_true.count('OUTLIER')}), MALICIOUS ({y_true.count('MALICIOUS')})")
    
    print("\n## 4. Feature Set")
    print("duration, packets, bytes, mean_iat, mean_packet_size, protocol\n")

    labels = ["BENIGN", "OUTLIER", "MALICIOUS"]

    def print_metrics(y_t, y_p, title):
        print(f"## {title}")
        acc = accuracy_score(y_t, y_p)
        print(f"Accuracy: {acc:.4f}")
        p, r, f, _ = precision_recall_fscore_support(y_t, y_p, labels=labels, zero_division=0)
        for i, lab in enumerate(labels):
            print(f"{lab} - Precision: {p[i]:.4f}, Recall: {r[i]:.4f}, F1: {f[i]:.4f}")
        
        p_mac, r_mac, f_mac, _ = precision_recall_fscore_support(y_t, y_p, average='macro', zero_division=0)
        p_wt, r_wt, f_wt, _ = precision_recall_fscore_support(y_t, y_p, average='weighted', zero_division=0)
        print(f"Macro F1: {f_mac:.4f}")
        print(f"Weighted F1: {f_wt:.4f}")

    print_metrics(y_true, y_pred_rf, "5. Random Forest Results")
    
    print("\n## 6. Isolation Forest Results")
    if_true = [x[0] for x in y_pred_if]
    if_pred = [x[1] for x in y_pred_if]
    if_acc = accuracy_score(if_true, if_pred)
    p_if, r_if, f_if, _ = precision_recall_fscore_support(if_true, if_pred, labels=["BENIGN", "NON-BENIGN"], zero_division=0)
    print(f"Binary Classification (BENIGN vs NON-BENIGN)")
    print(f"Accuracy: {if_acc:.4f}")
    print(f"BENIGN - Precision: {p_if[0]:.4f}, Recall: {r_if[0]:.4f}, F1: {f_if[0]:.4f}")
    print(f"NON-BENIGN - Precision: {p_if[1]:.4f}, Recall: {r_if[1]:.4f}, F1: {f_if[1]:.4f}")

    print("\n")
    print_metrics(y_true, y_pred_rules, "7. Rule Engine Results")
    print("\n")
    print_metrics(y_true, y_pred_ensemble, "8. Ensemble Results (Overall)")

    print("\n## 9. Confusion Matrix (Ensemble)")
    cm = confusion_matrix(y_true, y_pred_ensemble, labels=labels)
    print("                  PREDICTED")
    print("              BENIGN OUTLIER MALICIOUS")
    print(f"ACTUAL BENIGN    {cm[0][0]:<6} {cm[0][1]:<7} {cm[0][2]:<9}")
    print(f"ACTUAL OUTLIER   {cm[1][0]:<6} {cm[1][1]:<7} {cm[1][2]:<9}")
    print(f"ACTUAL MALICIOUS {cm[2][0]:<6} {cm[2][1]:<7} {cm[2][2]:<9}")

    print("\n## 10. Precision / Recall / F1")
    print("(See section 8)")

    print("\n## 11. Per-Attack Results")
    for attack, counts in attack_types.items():
        total, detected, missed = counts
        rate = detected/total if total > 0 else 0
        print(f"Attack type: {attack.upper()}")
        print(f"Sample count: {total}")
        print(f"Detected count: {detected}")
        print(f"Missed count: {missed}")
        print(f"Detection rate: {rate:.2%}\n")

    print("## 12. False Positive Analysis")
    print(f"Total False Positives: {len(fp_cases)}")
    if fp_cases:
        print("Example False Positive:")
        fp = fp_cases[0]
        print(f"Expected: BENIGN, Predicted: {fp['final_classification']}")
        print(f"Reason: RF Prob={fp['random_forest_probability']:.2f}, IF Signal={fp['anomaly_signal']:.2f}, Rule Score={fp['rule_score']:.2f}")

    print("\n## 13. False Negative Analysis")
    print(f"Total False Negatives: {len(fn_cases)}")
    if fn_cases:
        print("Example False Negative:")
        fn = fn_cases[0]
        print(f"Expected: MALICIOUS/OUTLIER, Predicted: {fn['final_classification']}")
        print(f"Reason: RF Prob={fn['random_forest_probability']:.2f}, IF Signal={fn['anomaly_signal']:.2f}, Rule Score={fn['rule_score']:.2f}")
    
    evaluate_evidence_verification()

    print("\n## 15. External Dataset Feasibility")
    print("Why it was not integrated: Significant preprocessing and feature mapping would be required to align public PCAP/flow datasets (e.g., CICIDS2017 or UNSW-NB15) with the exact 6-feature schema expected by the currently trained models. Retraining would also be required.")
    print("What mapping would be required: Real-world PCAPs need to be processed via tools like Zeek or CICFlowMeter, and attributes like duration, packets, bytes, mean_iat, mean_packet_size must be extracted and normalized identically.")
    print("What future validation would look like: The engine would ingest the mapped CSV/JSON from the external dataset and report independent test metrics.")

    print("\n## 16. Limitations")
    print("The evaluation measures performance on a controlled synthetic distribution, not generalization to unseen real-world network environments. Both train and test datasets share identical generation logic bounds. The system demonstrates the detection pipeline architecture rather than a production-ready model.")

    print("\n## 17. Reproducibility Instructions")
    print(f"Python version: {platform.python_version()}")
    print(f"Scikit-Learn version: {sklearn.__version__}")
    print("Model parameters: RF(n_estimators=50, random_state=42), IF(n_estimators=100, contamination=0.05, random_state=42)")
    print("Random seed: 42")
    print("Training dataset: data/train_labeled.json, data/train_benign.json")
    print("Evaluation dataset: data/test_stream.json")
    print("Feature vector: [duration, packets, bytes, mean_iat, mean_packet_size, protocol]")
    print(f"Evaluation date: {datetime.now().isoformat()}")

    results_out = {
        "accuracy": accuracy_score(y_true, y_pred_ensemble),
        "macro_f1": precision_recall_fscore_support(y_true, y_pred_ensemble, average='macro', zero_division=0)[2]
    }
    with open("evaluation_results.json", "w") as f:
        json.dump(results_out, f)

if __name__ == "__main__":
    main()
    generate_controlled_cases()
