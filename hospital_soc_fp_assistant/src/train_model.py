"""
Model Training and Comparison Module for Hospital SOC Assistant.
Trains and compares Logistic Regression, Decision Tree, and Random Forest.
Selects the model prioritizing Recall and lowest Missed-Incident Rate (FNR).
Saves the selected model and anomaly detection model to the models/ folder.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from anomaly_detection import MedicalDeviceNoveltyDetector

NUMERIC_FEATURES = [
    "severity_score",
    "device_criticality_score",
    "failed_login_count",
    "login_attempts",
    "event_count",
    "destination_port",
    "unusual_time",
    "unusual_destination",
    "historical_alert_count",
    "historical_false_positive_rate",
    "known_scanner",
    "maintenance_window",
    "latency_seconds",
    "high_failure_rate"
]

CATEGORICAL_FEATURES = [
    "protocol",
    "detection_source",
    "device_type",
    "network_segment"
]

def build_preprocessor():
    """Builds a scikit-learn ColumnTransformer for preprocessing features."""
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERIC_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL_FEATURES)
        ]
    )
    return preprocessor

def evaluate_classifier(pipeline, X_test, y_test, model_name):
    """Evaluates a trained classifier with cybersecurity safety metrics."""
    preds = pipeline.predict(X_test)
    probs = pipeline.predict_proba(X_test)[:, 1] if hasattr(pipeline, "predict_proba") else preds
    
    cm = confusion_matrix(y_test, preds)
    # cm layout: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = cm.ravel()
    
    total_incidents = int(fn + tp)
    missed_incidents = int(fn)
    fnr = missed_incidents / total_incidents if total_incidents > 0 else 0.0
    
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    
    return {
        "model_name": model_name,
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_negative_rate": round(float(fnr), 4),
        "missed_incidents": missed_incidents,
        "total_incidents": total_incidents,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn)
    }

def train_and_compare(data_path="data/cleaned_alerts.csv", output_dir="models", results_dir="results"):
    """Trains 3 candidate models, compares them, and saves the best model."""
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Cleaned alerts not found: {data_path}")
        
    df = pd.read_csv(data_path)
    
    # Target: 1 = Confirmed Threat / Incident, 0 = False Positive / Benign
    y = df["confirmed_incident"].values
    X = df[NUMERIC_FEATURES + CATEGORICAL_FEATURES].copy().fillna(0)
    
    # Stratified Train-Test Split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    
    print(f"Training dataset size: {len(X_train)} samples")
    print(f"Testing dataset size:  {len(X_test)} samples (Incidents: {int(y_test.sum())})")
    
    models = {
        "Logistic Regression": LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42),
        "Decision Tree": DecisionTreeClassifier(class_weight="balanced", max_depth=6, random_state=42),
        "Random Forest": RandomForestClassifier(class_weight="balanced", n_estimators=120, max_depth=8, random_state=42)
    }
    
    results = []
    trained_pipelines = {}
    
    for name, clf in models.items():
        preprocessor = build_preprocessor()
        pipeline = Pipeline(steps=[
            ("preprocessor", preprocessor),
            ("classifier", clf)
        ])
        pipeline.fit(X_train, y_train)
        metrics = evaluate_classifier(pipeline, X_test, y_test, name)
        results.append(metrics)
        trained_pipelines[name] = pipeline
        print(f"\n[{name}] Evaluation:")
        print(f"  Recall (Threat Detection): {metrics['recall']:.4f}")
        print(f"  False Negative Rate (FNR): {metrics['false_negative_rate']:.4f} (Missed: {metrics['missed_incidents']})")
        print(f"  Precision:                 {metrics['precision']:.4f}")
        print(f"  F1 Score:                  {metrics['f1_score']:.4f}")
        print(f"  Accuracy:                  {metrics['accuracy']:.4f}")
        
    # Model Selection Strategy:
    # 1. Minimize False Negative Rate (FNR) / Maximize Recall (Clinical Safety First!)
    # 2. Tie-breaker: Highest F1 Score
    best_model_info = sorted(
        results,
        key=lambda m: (-m["recall"], m["false_negative_rate"], -m["f1_score"])
    )[0]
    
    best_name = best_model_info["model_name"]
    best_pipeline = trained_pipelines[best_name]
    
    print(f"\n==========================================")
    print(f"BEST MODEL SELECTED: {best_name}")
    print(f"Primary Selection Rationale: Threat Recall = {best_model_info['recall']:.4f}, Missed Incidents = {best_model_info['missed_incidents']}")
    print(f"==========================================")
    
    # Save the selected model
    model_path = os.path.join(output_dir, "false_positive_model.joblib")
    joblib.dump({
        "pipeline": best_pipeline,
        "model_name": best_name,
        "metrics": best_model_info,
        "features": {
            "numeric": NUMERIC_FEATURES,
            "categorical": CATEGORICAL_FEATURES
        }
    }, model_path)
    print(f"Saved best model -> {model_path}")
    
    # Save comparison report
    comp_path = os.path.join(results_dir, "model_comparison.json")
    with open(comp_path, "w") as f:
        json.dump(results, f, indent=4)
        
    # Fit & Save Anomaly / Novelty Detection Model
    print("\nFitting Isolation Forest Novelty Detector...")
    novelty_detector = MedicalDeviceNoveltyDetector()
    novelty_detector.fit(df)
    anomaly_path = os.path.join(output_dir, "anomaly_model.joblib")
    novelty_detector.save(anomaly_path)
    
    return best_name, results

if __name__ == "__main__":
    train_and_compare()
