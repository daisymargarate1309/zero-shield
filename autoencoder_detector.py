"""
autoencoder_detector.py
------------------------
Deep Learning anomaly detection layer -- YOUR CONTRIBUTION beyond the paper.

An Autoencoder is trained ONLY on benign traffic. It learns to compress and
reconstruct "normal" patterns. When attack traffic (especially ZSL-hard
attacks like Fuzzers) is fed in, reconstruction error spikes -- flagging it
as anomalous, WITHOUT ever having seen that attack type during training.

This directly targets the paper's weak point: attacks with high Wasserstein
Distance (unique feature patterns) that RF/MLP miss.
"""

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "data"))

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.neural_network import MLPRegressor

from generate_dataset import load_data, ATTACK_TYPES, N_FEATURES

FEATURE_COLS = [f"f{i}" for i in range(N_FEATURES)]


class SimpleAutoencoder:
    """
    A lightweight autoencoder built with MLPRegressor (input == output target).
    For a production project, swap this for a Keras/PyTorch autoencoder --
    interface (fit / reconstruction_error) stays identical.
    """
    def __init__(self, bottleneck=6, random_state=42):
        self.model = MLPRegressor(
            hidden_layer_sizes=(16, bottleneck, 16),
            activation="relu", solver="adam",
            max_iter=300, random_state=random_state
        )
        self.threshold_ = None

    def fit(self, X_benign):
        self.model.fit(X_benign, X_benign)          # learn to reconstruct itself
        recon = self.model.predict(X_benign)
        errors = np.mean((X_benign - recon) ** 2, axis=1)
        # threshold = mean + 3*std of benign reconstruction error
        self.threshold_ = errors.mean() + 3 * errors.std()
        return self

    def reconstruction_error(self, X):
        recon = self.model.predict(X)
        return np.mean((X - recon) ** 2, axis=1)

    def predict_anomaly(self, X):
        """Returns 1 = anomaly (attack-like), 0 = normal, plus raw scores."""
        errors = self.reconstruction_error(X)
        flags = (errors > self.threshold_).astype(int)
        return flags, errors


def evaluate_autoencoder_on_fuzzers():
    df = load_data()
    scaler = MinMaxScaler()
    df[FEATURE_COLS] = scaler.fit_transform(df[FEATURE_COLS])

    benign_df = df[df["label"] == "Benign"]
    ae = SimpleAutoencoder().fit(benign_df[FEATURE_COLS].values)

    print(f"{'Attack Type':<16} {'AE Detection Rate (%)':>22}")
    print("-" * 40)
    ae_results = {}
    for attack in ATTACK_TYPES:
        atk_df = df[df["label"] == attack]
        flags, errors = ae.predict_anomaly(atk_df[FEATURE_COLS].values)
        detection_rate = 100.0 * flags.mean()
        ae_results[attack] = round(detection_rate, 2)
        print(f"{attack:<16} {detection_rate:>22.2f}")

    return ae, ae_results


if __name__ == "__main__":
    ae, results = evaluate_autoencoder_on_fuzzers()

    print("\n--- Comparison: ZSL (RF/MLP) vs Autoencoder for Fuzzers ---")
    try:
        zsl = pd.read_csv("/home/claude/zeroshield/models/zsl_results.csv")
        fuzz = zsl[zsl["Zero-Day Attack"] == "Fuzzers"]
        print(fuzz[["Model", "Z-DR (%)"]].to_string(index=False))
    except FileNotFoundError:
        print("(run zsl_train.py first to compare)")
    print(f"Autoencoder Fuzzers Detection Rate: {results['Fuzzers']}%")
