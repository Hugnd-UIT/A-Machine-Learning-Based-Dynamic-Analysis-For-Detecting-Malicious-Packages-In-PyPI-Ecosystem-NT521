import gc
import os
import time
import joblib

import numpy as np
import pandas as pd

from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


BASE = (
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if '__file__' in globals()
    else os.path.abspath('.')
)

TRAIN_PATH = (
    os.path.join(BASE, 'dataset', 'train.csv')
    if os.path.exists(os.path.join(BASE, 'dataset', 'train.csv'))
    else os.path.join(BASE, 'data', 'train.csv')
)

MODELS_DIR = os.path.join(
    BASE,
    'models'
)
os.makedirs(MODELS_DIR, exist_ok=True)


def load_partition(path, name):
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"[!] Partition not found: {path}"
        )

    print(
        f"[*] Reading {name:<5}: {os.path.basename(path)}"
    )
    df = pd.read_csv(path)

    y = df.pop('Level').values
    if 'Package_Name' in df.columns:
        df.drop(
            columns=['Package_Name'],
            inplace=True
        )

    obj_cols = [
        col for col in df.columns
        if df[col].dtype == 'object' or pd.api.types.is_string_dtype(df[col])
    ]
    for col in obj_cols:
        df[col] = pd.factorize(df[col])[0]

    X = df.astype(np.float32)
    return X, y


def train_models():
    total_start = time.time()

    print("\n" + "=" * 60)
    print("[*] Loading datasets...")
    print("=" * 60)

    t_load = time.time()
    X_train, y_train = load_partition(TRAIN_PATH, 'Train')

    print(
        f"[+] Completed in {time.time() - t_load:.2f}s"
    )
    print(
        f"[+] Features: {X_train.shape[1]} | Train samples: {len(X_train):,}"
    )

    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            random_state=42,
            n_jobs=-1
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=8,
            min_samples_split=10,
            random_state=42
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42
        ),
        'SVM': Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', CalibratedClassifierCV(
                LinearSVC(
                    random_state=42,
                    max_iter=3000,
                    dual=False
                )
            ))
        ])
    }

    print("\n" + "=" * 60)
    print("[*] Training models...")
    print("=" * 60)

    for name, model in models.items():
        print(
            f"\n[*] Training: {name}..."
        )
        t_start = time.time()

        model.fit(X_train, y_train)
        duration = time.time() - t_start

        save_name = name.replace(' ', '-') + '.pkl'
        save_path = os.path.join(
            MODELS_DIR,
            save_name
        )
        joblib.dump(model, save_path)

        print(
            f"[+] Completed in {duration:.2f}s"
        )
        print(
            f"[+] Saved: {save_name}"
        )

    del X_train, y_train, models
    gc.collect()


if __name__ == '__main__':
    train_models()