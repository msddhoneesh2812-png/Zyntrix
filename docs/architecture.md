# SIH 2026 Prototype Architecture

This document outlines the architecture for the "AI-Based Detection of Cyber Threats in Unidirectional IP Traffic" prototype.

## Overview
The system relies exclusively on unidirectional features. The architecture is composed of the following components:

### Frontend
- **React + TypeScript + Vite**: High-performance UI rendering.
- **Tailwind CSS**: Styling utilizing a dark, professional SOC theme.
- **State Management**: React Hooks synchronised with backend via polling/interval data fetching.

### Backend
- **FastAPI**: Serves the REST API and coordinates the demo.
- **EnsembleEngine**: A composite detection engine utilizing trained Random Forest and Isolation Forest models alongside rule-based insights.
- **EvidenceLedger**: Simulates a tamper-evident ledger utilizing sequential SHA-256 hashing.
- **GraphAnalyzer**: Maintains a NetworkX directional graph of endpoint communications based solely on observed traffic.

### Data Flow
1. `DemoService` streams pre-generated records from `test_stream.json`.
2. `EnsembleEngine` extracts features and scores the flow (Benign, Outlier, Malicious).
3. `GraphAnalyzer` updates relationships.
4. If an alert is triggered, the `EvidenceLedger` generates an immutable hash.
5. The Frontend fetches the updated state and visually represents the pipeline.
