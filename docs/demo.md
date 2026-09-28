# SIH 2026 Demo Workflow

To successfully demonstrate this prototype to the judges, follow this workflow:

1. **Start Services**
   - Ensure `uvicorn main:app` is running.
   - Ensure `npm run dev` is running.

2. **Open Dashboard**
   - Show the empty state. Emphasize that the system is ready to receive unidirectional flow telemetry.
   - Click **START LIVE DEMO**.

3. **Narrate the Simulation**
   - **Stage 1 (Benign)**: Traffic streams in normally. The graphs slowly populate.
   - **Stage 2 (Anomalous)**: Traffic characteristics change. Emphasize that the ML ensemble is detecting subtle shifts in flow sizes and IAT.
   - **Stage 3 (Outlier)**: An outlier is flagged. Show the active alerts counter increasing.
   - **Stage 4 (Malicious)**: A critical exfiltration/scanning threat is detected.

4. **Investigate Alert**
   - Go to **Threat Alerts** and click on the generated critical alert.
   - Highlight the **Ensemble Decision** panel to demonstrate explainability (Rule evidence, RF probability, IF signal).
   - Click the **VERIFY EVIDENCE** button to show the cryptographic ledger hashing working in real-time.

5. **Network Graph**
   - Navigate to the **Network Graph**.
   - Show how the malicious source IP has become a "Supernode" through unidirectional observations alone.

6. **Evaluation & Limitations**
   - Conclude the demo by discussing the evaluation benchmark (`evaluate_model.py`) and referencing the `limitations.md` file for an honest prototype assessment.
