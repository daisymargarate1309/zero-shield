"""
zsl_train.py
------------
Implements the paper's Zero-Shot Learning (ZSL) evaluation methodology.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "data"))

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.base import clone

from generate_dataset import load_data, ATTACK_TYPES

FEATURE_COLS = [f"f{i}" for i in range(20)]


def get_models():
    rf = RandomForestClassifier(
        n_estimators=50, criterion="gini", min_samples_split=2,
        min_samples_leaf=1, random_state=42
    )
    mlp = MLPClassifier(
        hidden_layer_sizes=(100, 100), activation="relu",
        solver="adam", learning_rate_init=0.001, alpha=0.0001,
        max_iter=50, random_state=42
    )
    return {"RF": rf, "MLP": mlp}


def compute_zdr(y_true, y_pred, zero_day_attack):
    mask = (y_true == zero_day_attack)
    tp = np.sum((y_pred == "attack") & mask)
    fn = np.sum((y_pred == "benign") & mask)
    if tp + fn == 0:
        return None
    return 100.0 * tp / (tp + fn)


def run_zsl_experiment(verbose=True):
    df = load_data()
    scaler = MinMaxScaler()
    df[FEATURE_COLS] = scaler.fit_transform(df[FEATURE_COLS])

    results = []
    models = get_models()

    for model_name, model_template in models.items():
        for zero_day_attack in ATTACK_TYPES:
            train_df = df[df["label"] != zero_day_attack].copy()
            X_train, X_val, y_train_bin, y_val_bin = train_test_split(
                train_df[FEATURE_COLS], train_df["is_attack"],
                test_size=0.001 if len(train_df) < 2000 else 0.2,
                random_state=42, stratify=train_df["is_attack"]
            )

            model = clone(model_template)
            model.fit(X_train, y_train_bin)

            test_df = df.sample(frac=0.3, random_state=1)
            X_test = test_df[FEATURE_COLS]
            y_test_label = test_df["label"].values

            y_pred_bin = model.predict(X_test)
            y_pred_str = np.where(y_pred_bin == 1, "attack", "benign")

            zdr = compute_zdr(y_test_label, y_pred_str, zero_day_attack)

            attack_mask = test_df["is_attack"].values == 1
            dr = 100.0 * np.mean(y_pred_bin[attack_mask] == 1) if attack_mask.sum() else 0

            acc = 100.0 * np.mean(y_pred_bin == test_df["is_attack"].values)

            results.append({
                "Model": model_name,
                "Zero-Day Attack": zero_day_attack,
                "Z-DR (%)": round(zdr, 2) if zdr is not None else None,
                "Overall DR (%)": round(dr, 2),
                "Accuracy (%)": round(acc, 2),
            })

    results_df = pd.DataFrame(results)
    if verbose:
        print(results_df.to_string(index=False))
    return results_df


if __name__ == "__main__":
    results = run_zsl_experiment()
    out_path = os.path.join(os.path.dirname(__file__), "zsl_results.csv")
    results.to_csv(out_path, index=False)
    print(f"\nSaved results to {out_path}")
    print("\nAverage Z-DR by model:")
    print(results.groupby("Model")["Z-DR (%)"].mean())
