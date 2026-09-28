# Prototype Limitations

As a functional prototype developed for SIH 2026, Zyntrix has the following documented limitations:

## 1. Synthetic Data Distribution
The system is currently evaluated against a controlled, synthetically generated network flow distribution (`test_stream.json`) rather than a live production network or a direct ingest of a public dataset like CICIDS2017. While the underlying statistics mimic network anomalies, performance on real-world traffic is not guaranteed to match the synthetic benchmark.

## 2. Model Calibration
The Random Forest outputs a raw probability score, and the Isolation Forest outputs an anomaly signal based on decision path distance. These are currently combined in the ensemble using static weights. A production system would require rigorous probability calibration (e.g., Platt scaling or Isotonic regression) to ensure the `detection_score` represents a true statistical confidence.

## 3. In-Memory State
To ensure ease of deployment during the demonstration, the backend utilizes bounded in-memory queues (`collections.deque`) to store processed flows, active alerts, and the cryptographic ledger. Restarting the backend service will clear all historical data. Production deployment would necessitate a persistent datastore (e.g., PostgreSQL).

## 4. Security & Authentication
The current dashboard does not implement authentication (e.g., JWT, OAuth2) for SOC analysts, and assumes a trusted operational environment. Role-based access control is not implemented.

## 5. Network Graph Scaling
The interactive network graph visualizes all endpoints and relationships observed during the live demo. In a high-throughput enterprise environment, rendering every endpoint is computationally prohibitive, requiring backend aggregation or sampling strategies before sending data to the UI.
