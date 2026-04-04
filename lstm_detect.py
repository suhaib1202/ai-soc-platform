"""
lstm_detect.py
LSTM Autoencoder for time-series anomaly detection.
Detects slow, persistent attacks invisible to point-in-time models.
High reconstruction error = sequence the model does not recognize = anomaly.
"""

import os
import numpy as np
import pandas as pd
from datetime import datetime

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (
    LSTM, Dense, RepeatVector, TimeDistributed, Dropout
)
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

SEQUENCE_LENGTH = 10
EPOCHS          = 50
BATCH_SIZE      = 64
THRESHOLD_PCT   = 95


def prepare_sequences(df):
    if "generated_at" in df.columns:
        df["generated_at"] = pd.to_datetime(df["generated_at"], errors="coerce")
        df = df.sort_values("generated_at").reset_index(drop=True)

    preferred = [
        "bytes_transferred", "failed_attempts",
        "connection_count", "process_count", "threat_score"
    ]
    selected = [c for c in preferred if c in df.columns]
    if not selected:
        selected = df.select_dtypes(include=[np.number]).columns.tolist()[:5]
    selected = selected[:5]

    data      = df[selected].fillna(0).values.astype(np.float32)
    col_min   = data.min(axis=0)
    col_max   = data.max(axis=0)
    col_range = np.where((col_max - col_min) == 0, 1, col_max - col_min)
    data_norm = (data - col_min) / col_range

    sequences = np.array([
        data_norm[i: i + SEQUENCE_LENGTH]
        for i in range(len(data_norm) - SEQUENCE_LENGTH + 1)
    ])

    print(f"  Sequences created  : {len(sequences):,}")
    print(f"  Shape              : {sequences.shape}")
    print(f"  Features           : {selected}")
    return sequences, selected


def build_model(seq_len, n_features):
    model = Sequential([
        LSTM(64, input_shape=(seq_len, n_features), return_sequences=True),
        Dropout(0.2),
        LSTM(32, return_sequences=False),
        RepeatVector(seq_len),
        LSTM(32, return_sequences=True),
        Dropout(0.2),
        LSTM(64, return_sequences=True),
        TimeDistributed(Dense(n_features))
    ])
    model.compile(optimizer="adam", loss="mse")
    return model


def run_lstm(
    ensemble_path = "data/ensemble_anomalies.json",
    output_path   = "data/lstm_anomalies.json"
):
    print("\n" + "=" * 60)
    print("  LSTM TIME-SERIES DETECTION")
    print("  Catches slow and persistent attack patterns")
    print("=" * 60)

    df = pd.read_json(ensemble_path, lines=True)
    print(f"\n[+] Events loaded  : {len(df):,}")

    if len(df) < SEQUENCE_LENGTH * 2:
        print("[!] Not enough events. Copying ensemble output as final.")
        df.to_json(output_path, orient="records", lines=True, default_handler=str)
        return df

    print("\n[+] Preparing sequences...")
    sequences, features = prepare_sequences(df)

    seq_len    = sequences.shape[1]
    n_features = sequences.shape[2]

    print(f"\n[+] Building LSTM Autoencoder...")
    model = build_model(seq_len, n_features)
    print(f"  Parameters : {model.count_params():,}")
    print(f"\n  Training on {len(sequences):,} sequences.")
    print("  This takes 3-8 minutes. Do NOT close the terminal.\n")

    os.makedirs("models", exist_ok=True)
    cbs = [
        EarlyStopping(monitor="val_loss", patience=5,
                      restore_best_weights=True),
        ModelCheckpoint("models/lstm_best.keras", save_best_only=True)
    ]

    history = model.fit(
        sequences, sequences,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.1,
        callbacks=cbs,
        verbose=1
    )

    epochs_run = len(history.history["loss"])
    final_loss = history.history["loss"][-1]
    print(f"\n  Stopped at epoch   : {epochs_run}")
    print(f"  Final loss         : {final_loss:.6f}")

    print("\n[+] Calculating reconstruction errors...")
    recon     = model.predict(sequences, verbose=0)
    mse       = np.mean(np.power(sequences - recon, 2), axis=(1, 2))
    threshold = np.percentile(mse, THRESHOLD_PCT)

    print(f"  Threshold (95th)   : {threshold:.6f}")
    print(f"  Min error          : {mse.min():.6f}")
    print(f"  Max error          : {mse.max():.6f}")

    lstm_flags   = (mse > threshold).astype(int)
    event_flags  = np.zeros(len(df), dtype=int)
    event_scores = np.zeros(len(df), dtype=float)

    for i, (flag, score) in enumerate(zip(lstm_flags, mse)):
        idx = min(i + SEQUENCE_LENGTH - 1, len(df) - 1)
        if flag == 1:
            event_flags[idx] = 1
        event_scores[idx] = max(event_scores[idx], float(score))

    df["lstm_anomaly"]              = event_flags
    df["lstm_reconstruction_error"] = event_scores
    df["lstm_threshold"]            = threshold
    df["triple_confirmed"]          = (
        (df.get("ensemble_anomaly",
                pd.Series(0, index=df.index)) == 1) &
        (df["lstm_anomaly"] == 1)
    ).astype(int)

    model.save("models/lstm_autoencoder.keras")
    df.to_json(output_path, orient="records", lines=True, default_handler=str)

    triple = int(df["triple_confirmed"].sum())

    print("\n" + "=" * 60)
    print("  LSTM COMPLETE")
    print("=" * 60)
    print(f"  LSTM anomalies           : {int(event_flags.sum()):,}")
    print(f"  Triple-confirmed threats : {triple:,}  <- HIGHEST PRIORITY")
    print(f"  Model saved              : models/lstm_autoencoder.keras")
    print(f"  Output                   : {output_path}")
    print("=" * 60 + "\n")
    return df


if __name__ == "__main__":
    run_lstm()