import argparse
import gc
import os
import time
import joblib

import numpy as np
import pandas as pd


BASE_DIR = (
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if '__file__' in globals()
    else os.path.abspath('.')
)

MODELS_DIR = os.path.join(
    BASE_DIR,
    'models'
)

DEFAULT_DATA_PATH = os.path.join(
    BASE_DIR,
    'dataset',
    'test.csv'
)

DEFAULT_MODEL_NAME = 'Random-Forest'


def load_model(model_name):
    model_file = f"{model_name}.pkl"
    model_path = os.path.join(
        MODELS_DIR,
        model_file
    )

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"[!] Model checkpoint not found: {model_path}\n"
            f"[*] Please run `python src/train.py` first."
        )

    print(
        f"[*] Loading model: {model_file}"
    )
    t = time.time()
    model = joblib.load(model_path)
    print(
        f"[+] Loaded successfully in {time.time() - t:.2f}s"
    )

    return model


def preprocess_data(df):
    packages = (
        df['Package_Name'].values
        if 'Package_Name' in df.columns
        else [f"Sample_{i}" for i in range(len(df))]
    )

    true_labels = (
        df['Level'].values
        if 'Level' in df.columns
        else None
    )

    drop_cols = [
        col for col in ['Package_Name', 'Level']
        if col in df.columns
    ]
    features_df = df.drop(
        columns=drop_cols
    ).copy()

    obj_cols = [
        col for col in features_df.columns
        if features_df[col].dtype == 'object' or pd.api.types.is_string_dtype(features_df[col])
    ]

    for col in obj_cols:
        features_df[col] = pd.factorize(features_df[col])[0]

    X = features_df.astype(np.float32)
    feature_names = list(features_df.columns)

    return X, packages, true_labels, feature_names


def explain_prediction(model, sample_row, feature_names, top_k=3):
    underlying_model = model
    if hasattr(model, 'named_steps'):
        underlying_model = model.named_steps.get('classifier', model)
        if hasattr(underlying_model, 'estimator'):
            underlying_model = underlying_model.estimator

    if hasattr(underlying_model, 'feature_importances_'):
        importances = underlying_model.feature_importances_
        active_indices = np.argsort(importances)[::-1]

        reasons = []
        for idx in active_indices:
            feat = feature_names[idx]
            val = sample_row.iloc[idx]
            if val > 0:
                reasons.append(f"{feat}={val:g}")
            if len(reasons) >= top_k:
                break

        return ", ".join(reasons) if reasons else "Normal profile"

    return "N/A"


def predict(model, X, packages, true_labels, feature_names):
    print("\n" + "=" * 60)
    print("[*] Running DySec Inference Engine...")
    print("=" * 60)

    t_start = time.time()
    preds = model.predict(X)

    try:
        probs = model.predict_proba(X)
    except Exception:
        probs = None

    total_time = time.time() - t_start
    avg_latency_ms = (total_time / len(X)) * 1000

    results = []
    print(
        f"\n{'-' * 88}"
    )
    print(
        f"{'Package Name':<28} | {'Prediction':<11} | {'Confidence':<10} | {'True Label':<10} | {'Top Indicators (RQ2)':<20}"
    )
    print(
        f"{'-' * 88}"
    )

    for i in range(len(X)):
        pred_idx = preds[i]
        label_str = "MALICIOUS" if pred_idx == 1 else "BENIGN"

        if probs is not None:
            conf = probs[i][pred_idx] * 100
            conf_str = f"{conf:>5.1f}%"
        else:
            conf_str = "100.0%"

        if true_labels is not None:
            actual_str = "Malicious" if true_labels[i] == 1 else "Benign"
        else:
            actual_str = "Unknown"

        reasons = explain_prediction(
            model,
            X.iloc[i],
            feature_names,
            top_k=2
        )

        badge = "[!]" if pred_idx == 1 else "[+]"
        pkg_display = packages[i][:26]

        print(
            f"{badge} {pkg_display:<24} | {label_str:<11} | {conf_str:<10} | {actual_str:<10} | {reasons}"
        )

        results.append({
            'Package_Name': packages[i],
            'Prediction': label_str,
            'Confidence': conf_str,
            'True_Label': actual_str,
            'Top_Indicators': reasons
        })

    print(
        f"{'-' * 88}"
    )
    print(
        f"[+] Evaluated: {len(X):,} packages"
    )
    print(
        f"[+] Total inference time: {total_time:.4f}s"
    )
    print(
        f"[+] Average latency per package: {avg_latency_ms:.3f} ms"
    )

    return pd.DataFrame(results)


def main():
    parser = argparse.ArgumentParser(
        description="DySec Inference Engine - PyPI Malicious Package Detection"
    )
    parser.add_argument(
        '--model',
        type=str,
        default=DEFAULT_MODEL_NAME,
        choices=['Random-Forest', 'Decision-Tree', 'Gradient-Boosting', 'SVM'],
        help="Model checkpoint to use (default: Random-Forest)"
    )
    parser.add_argument(
        '--file',
        type=str,
        default=None,
        help="Path to CSV file containing dynamic trace features"
    )
    parser.add_argument(
        '--package',
        type=str,
        default=None,
        help="Inspect a specific package by name from the dataset"
    )
    parser.add_argument(
        '--samples',
        type=int,
        default=10,
        help="Number of demo samples to predict if no specific package is given (default: 10)"
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help="Optional path to save prediction results as CSV"
    )

    args = parser.parse_args()

    data_file = args.file if args.file else DEFAULT_DATA_PATH
    if not os.path.exists(data_file):
        raise FileNotFoundError(
            f"[!] Data file not found: {data_file}"
        )

    model = load_model(args.model)

    print(
        f"[*] Reading data: {os.path.basename(data_file)}"
    )
    df = pd.read_csv(data_file)

    if args.package:
        if 'Package_Name' not in df.columns:
            raise ValueError(
                "[!] Cannot search by package name: 'Package_Name' column not found."
            )
        matched = df[df['Package_Name'] == args.package]
        if len(matched) == 0:
            print(
                f"[-] Package '{args.package}' not found in {data_file}."
            )
            return
        df = matched
    elif not args.file and args.samples > 0:
        if 'Level' in df.columns:
            benign_sample = df[df['Level'] == 0].sample(
                n=min(args.samples // 2, len(df[df['Level'] == 0])),
                random_state=42
            )
            malicious_sample = df[df['Level'] == 1].sample(
                n=min(args.samples // 2, len(df[df['Level'] == 1])),
                random_state=42
            )
            df = pd.concat(
                [benign_sample, malicious_sample]
            ).sample(
                frac=1.0,
                random_state=42
            ).reset_index(drop=True)
        else:
            df = df.sample(
                n=min(args.samples, len(df)),
                random_state=42
            ).reset_index(drop=True)

    X, packages, true_labels, feature_names = preprocess_data(df)

    res_df = predict(
        model,
        X,
        packages,
        true_labels,
        feature_names
    )

    if args.output:
        res_df.to_csv(
            args.output,
            index=False
        )
        print(
            f"\n[+] Saved predictions to: {args.output}"
        )

    del df, X, model
    gc.collect()


if __name__ == '__main__':
    main()
