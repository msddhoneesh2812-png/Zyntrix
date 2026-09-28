# Models Directory

This directory is intended to store the serialized artifacts of trained Machine Learning models (e.g., `.pkl`, `.h5`, `.joblib`).

For this prototype, models are implemented natively in `backend/detection/engine.py` using genuine `sklearn.ensemble.RandomForestClassifier` and `sklearn.ensemble.IsolationForest` models. They are trained on the normal flow data provided in the `demo_flows.json` dataset to represent real supervised and unsupervised detection capabilities.
