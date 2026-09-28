import json
import random
import time
from datetime import datetime, timedelta

def generate_dataset(num_flows, mode="mixed"):
    flows = []
    base_time = datetime.now() - timedelta(hours=1)
    
    benign_ports = [80, 443, 53, 123]
    internal_subnet = "192.168.1."
    external_benign = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "104.18.2.161"]
    external_malicious = ["185.15.2.1", "45.33.32.156", "193.3.19.159"]
    
    for i in range(num_flows):
        timestamp = base_time + timedelta(seconds=i*2)
        
        if mode == "benign":
            stage = "benign"
        else:
            # Narrative progression for test stream, random for train_labeled
            if mode == "test_stream":
                if i < num_flows * 0.2: stage = "benign"
                elif i < num_flows * 0.4: stage = "anomalous"
                elif i < num_flows * 0.6: stage = "outlier"
                else: stage = "malicious"
            else:
                stage = random.choices(["benign", "anomalous", "outlier", "malicious"], weights=[0.4, 0.2, 0.2, 0.2])[0]
                
        if stage == "benign":
            src_ip = f"{internal_subnet}{random.randint(10, 50)}"
            dst_ip = random.choice(external_benign)
            dst_port = random.choice(benign_ports)
            protocol = "TCP" if dst_port in [80, 443] else "UDP"
            packets = random.randint(5, 50)
            bytes_count = packets * random.randint(64, 1500)
            duration = random.uniform(0.1, 5.0)
            iat = random.uniform(0.01, 0.5)
            threat_class = "BENIGN"
            
        elif stage == "anomalous":
            src_ip = f"{internal_subnet}{random.randint(51, 100)}"
            dst_ip = random.choice(external_benign)
            dst_port = random.choice([8080, 8443, 53])
            protocol = random.choice(["TCP", "UDP"])
            packets = random.randint(100, 500)
            bytes_count = packets * random.randint(50, 100) 
            duration = random.uniform(5.0, 30.0)
            iat = random.uniform(0.001, 0.05)
            threat_class = "BENIGN"
            
        elif stage == "outlier":
            src_ip = f"{internal_subnet}99"
            dst_ip = random.choice(external_malicious)
            dst_port = 4444 # Typical C2 port
            protocol = "TCP"
            packets = random.randint(10, 20)
            bytes_count = packets * 1500
            duration = random.uniform(30.0, 120.0)
            iat = random.uniform(2.0, 10.0)
            threat_class = "OUTLIER"
            
        elif stage == "malicious":
            src_ip = f"{internal_subnet}99"
            dst_ip = random.choice(external_malicious)
            # Differentiate malicious behaviors
            attack_type = random.choice(["exfiltration", "scanning", "ddos"])
            
            if attack_type == "exfiltration":
                dst_port = random.choice([443, 80])
                protocol = "TCP"
                packets = random.randint(2000, 5000)
                bytes_count = packets * 1500 # Max MTU
                duration = random.uniform(60.0, 300.0)
                iat = random.uniform(0.0001, 0.005)
            elif attack_type == "scanning":
                dst_port = random.randint(1, 1024)
                protocol = "TCP"
                packets = random.randint(100, 200)
                bytes_count = packets * 64 # SYN packets
                duration = random.uniform(0.5, 5.0)
                iat = random.uniform(0.001, 0.01)
            else: # ddos
                dst_port = 80
                protocol = "UDP"
                packets = random.randint(10000, 50000)
                bytes_count = packets * 1000
                duration = random.uniform(1.0, 10.0)
                iat = random.uniform(0.00001, 0.0001)
                
            threat_class = "MALICIOUS"

        flow = {
            "id": f"flow_{mode}_{i:04d}",
            "timestamp": timestamp.isoformat(),
            "src_ip": src_ip,
            "src_port": random.randint(1024, 65535),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "packets": packets,
            "bytes": bytes_count,
            "duration": duration,
            "mean_iat": iat,
            "mean_packet_size": bytes_count / packets if packets > 0 else 0,
            "status": "COMPLETED",
            "threat_class": threat_class,
            "confidence": 0.0, # Removed pre-generated confidence, engine should calculate it
            "severity": "LOW",
            "threat_type": None
        }
        flows.append(flow)
    return flows

def main():
    train_benign = generate_dataset(300, mode="benign")
    with open("data/train_benign.json", "w") as f:
        json.dump(train_benign, f, indent=2)
        
    train_labeled = generate_dataset(400, mode="train_labeled")
    with open("data/train_labeled.json", "w") as f:
        json.dump(train_labeled, f, indent=2)
        
    test_stream = generate_dataset(500, mode="test_stream")
    with open("data/test_stream.json", "w") as f:
        json.dump(test_stream, f, indent=2)
        
    print("Generated train_benign.json, train_labeled.json, test_stream.json")

if __name__ == "__main__":
    main()
