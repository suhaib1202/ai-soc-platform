"""
ensemble_detect.py
Ensemble anomaly detection: Isolation Forest + Random Forest.
Two models vote on every event. Both agree = highest confidence threat.
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from datetime import datetime


def extract_features(df):
    """Extract numeric features from log data."""
    features = pd.DataFrame()

    features["bytes_transferred"] = pd.to_numeric(
        df.get("bytes_transferred", 0), errors="coerce").fillna(0)
    features["failed_attempts"]   = pd.to_numeric(
        df.get("failed_attempts", 0), errors="coerce").fillna(0)
    features["process_count"]     = pd.to_numeric(
        df.get("process_count", 0), errors="coerce").fillna(0)
    features["connection_count"]  = pd.to_numeric(
        df.get("connection_count", 0), errors="coerce").fillna(0)
    features["port_number"]       = pd.to_numeric(
        df.get("port", 0), errors="coerce").fillna(0)

    if "generated_at" in df.columns:
        dt = pd.to_datetime(df["generated_at"], errors="coerce")
        features["hour_of_day"] = dt.dt.hour.fillna(12)
        features["day_of_week"] = dt.dt.dayofweek.fillna(0)
        features["after_hours"] = (
            (features["hour_of_day"] >= 22) | (features["hour_of_day"] <= 6)
        ).astype(int)
    else:
        features["hour_of_day"] = 12
        features["day_of_week"] = 0
        features["after_hours"] = 0

    features["has_ioc"] = pd.to_numeric(
        df.get("ioc_flag", 0), errors="coerce").fillna(0).astype(int)

    severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    features["severity_score"] = (
        df.get("severity", "LOW").map(severity_map).fillna(1)
    )
    features["bytes_per_conn"] = (
        features["bytes_transferred"] / (features["connection_count"] + 1)
    ).clip(upper=1000000)

    return features


def train_isolation_forest(X_scaled):
    print("  Training Isolation Forest...")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.10,
        max_features=0.8,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)
    preds  = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)
    labels = (preds == -1).astype(int)
    print(f"  Flagged: {labels.sum():,} anomalies ({labels.mean()*100:.1f}%)")
    return model, labels, scores


def train_random_forest(X_scaled, iso_labels):
    print("\n  Training Random Forest...")
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_scaled, iso_labels,
        test_size=0.2, random_state=42, stratify=iso_labels
    )
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_tr, y_tr)
    preds = model.predict(X_scaled)
    proba = model.predict_proba(X_scaled)[:, 1]
    print(f"  Flagged: {preds.sum():,} anomalies ({preds.mean()*100:.1f}%)")

    # Feature importance
    names = [
        "bytes_transferred", "failed_attempts", "process_count",
        "connection_count", "port_number", "hour_of_day",
        "day_of_week", "after_hours", "has_ioc",
        "severity_score", "bytes_per_conn"
    ]
    imp = pd.Series(
        model.feature_importances_[:len(names)], index=names
    ).sort_values(ascending=False)
    print("\n  Feature Importance (top 5):")
    for feat, val in imp.head(5).items():
        bar = "█" * int(val * 50)
        print(f"    {feat:<22} {bar} {val:.3f}")

    return model, preds, proba


def ensemble_vote(iso_labels, rf_preds, rf_proba, iso_scores):
    final, conf = [], []
    for i in range(len(iso_labels)):
        iso_c = max(0, min(1, (0 - iso_scores[i]) / 0.5))
        if iso_labels[i] == 1 and rf_preds[i] == 1:
            lbl = 1
            c   = iso_c * 0.4 + rf_proba[i] * 0.6
        elif iso_labels[i] == 1 or rf_preds[i] == 1:
            lbl = 1
            c   = max(iso_c, rf_proba[i]) * 0.65
        else:
            lbl = 0
            c   = 0.0
        final.append(lbl)
        conf.append(round(min(c, 1.0), 4))
    final = np.array(final)
    both  = int(((iso_labels == 1) & (rf_preds == 1)).sum())
    print(f"\n  [ENSEMBLE] Flagged    : {final.sum():,} ({final.mean()*100:.1f}%)")
    print(f"  [ENSEMBLE] Both agreed: {both:,}  <- HIGHEST CONFIDENCE")
    return final, conf


def run_ensemble(
    logs_path   = "data/raw_logs.json",
    output_path = "data/ensemble_anomalies.json"
):
    print("\n" + "=" * 60)
    print("  ENSEMBLE ANOMALY DETECTION")
    print("  Isolation Forest  +  Random Forest")
    print("=" * 60)

    df = pd.read_json(logs_path, lines=True)
    print(f"\n[+] Events loaded  : {len(df):,}")

    X        = extract_features(df)
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    print(f"[+] Feature matrix : {X.shape}")

    print("\n[+] Training models...")
    iso_model, iso_labels, iso_scores = train_isolation_forest(X_scaled)
    rf_model,  rf_preds,  rf_proba    = train_random_forest(X_scaled, iso_labels)

    print("\n[+] Ensemble voting...")
    final_labels, confidences = ensemble_vote(
        iso_labels, rf_preds, rf_proba, iso_scores
    )

    df["ensemble_anomaly"]     = final_labels
    df["detection_confidence"] = confidences
    df["iso_forest_flag"]      = iso_labels
    df["random_forest_flag"]   = rf_preds
    df["detected_at"]          = datetime.now().isoformat()

    anomalies = df[df["ensemble_anomaly"] == 1].copy()

    os.makedirs("models", exist_ok=True)
    joblib.dump(iso_model, "models/isolation_forest.pkl")
    joblib.dump(rf_model,  "models/random_forest.pkl")
    joblib.dump(scaler,    "models/scaler.pkl")
    print("\n[+] Models saved   : models/")

    anomalies.to_json(output_path, orient="records", lines=True,
                      default_handler=str)

    print("\n" + "=" * 60)
    print("  ENSEMBLE COMPLETE")
    print("=" * 60)
    print(f"  Events analyzed    : {len(df):,}")
    print(f"  Anomalies detected : {len(anomalies):,}")
    print(f"  Output             : {output_path}")
    print("=" * 60 + "\n")
    return anomalies


if __name__ == "__main__":
    run_ensemble()