import gc
import os
import time
import joblib

import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLT_AVAILABLE = True
except ImportError:
    PLT_AVAILABLE = False


BASE_DIR = (
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if '__file__' in globals()
    else os.path.abspath('.')
)

DATA_PATH = os.path.join(
    BASE_DIR,
    'dataset',
    'test.csv'
)

MODELS_DIR = os.path.join(
    BASE_DIR,
    'models'
)

REPORTS_DIR = os.path.join(
    BASE_DIR,
    'models'
)

MODEL_NAMES = [
    'Random-Forest',
    'Decision-Tree',
    'Gradient-Boosting',
    'SVM'
]


def load_test_data(path):
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"[!] Test dataset not found: {path}"
        )

    print(
        f"[*] Reading: {os.path.basename(path)}"
    )

    t = time.time()
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

    print(
        f"\n[+] Loaded: {len(X):,} test samples | {X.shape[1]} features"
    )
    print(
        f"[+] Completed in {time.time() - t:.2f}s"
    )

    return X, y


def evaluate_model(name, model, X, y):
    print("\n" + "=" * 60)
    print(
        f"[*] Evaluating: {name}"
    )
    print("=" * 60)

    t_start = time.time()

    preds = model.predict(X)

    try:
        probs = model.predict_proba(X)[:, 1]
        auc = roc_auc_score(y, probs)
    except Exception:
        probs = None
        auc = 0.0

    duration = time.time() - t_start

    acc = accuracy_score(y, preds)
    prec = precision_score(y, preds, zero_division=0)
    rec = recall_score(y, preds, zero_division=0)
    f1 = f1_score(y, preds, zero_division=0)

    cm = confusion_matrix(y, preds)
    tn, fp, fn, tp = cm.ravel()
    total = len(y)

    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = (fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    print(
        f"[+] Finished in {duration:.2f}s"
    )
    print(
        f"    Accuracy : {acc * 100:.2f}%"
    )
    print(
        f"    Precision: {prec * 100:.2f}%"
    )
    print(
        f"    Recall   : {rec * 100:.2f}%"
    )
    print(
        f"    F1-Score : {f1 * 100:.2f}%"
    )
    print(
        f"    ROC-AUC  : {auc:.4f}"
    )

    print("\n[*] Confusion Matrix:")
    print(
        f"    TN (Benign -> Benign)      : {tn:>6,} ({tn / total * 100:>5.2f}%)"
    )
    print(
        f"    FP (Benign -> Malicious)   : {fp:>6,} ({fp / total * 100:>5.2f}%)"
    )
    print(
        f"    FN (Malicious -> Benign)   : {fn:>6,} ({fn / total * 100:>5.2f}%)"
    )
    print(
        f"    TP (Malicious -> Malicious): {tp:>6,} ({tp / total * 100:>5.2f}%)"
    )

    print("\n[*] Classification Report:")
    print(
        classification_report(
            y,
            preds,
            target_names=['Benign', 'Malicious'],
            digits=4,
            zero_division=0
        )
    )

    return {
        'Model': name,
        'Accuracy': round(acc, 4),
        'Precision': round(prec, 4),
        'Recall': round(rec, 4),
        'F1_Score': round(f1, 4),
        'ROC_AUC': round(auc, 4),
        'TP': int(tp),
        'TN': int(tn),
        'FP': int(fp),
        'FN': int(fn),
        'FPR': round(fpr, 4),
        'FNR': round(fnr, 4),
        'probs': probs,
        'cm': cm
    }


def plot_confusion_matrices(results, save_path):
    if not PLT_AVAILABLE:
        return

    fig, axes = plt.subplots(
        2,
        2,
        figsize=(12, 10)
    )
    axes = axes.flatten()

    for idx, res in enumerate(results):
        cm = res['cm']
        total = np.sum(cm)
        percentages = cm / total * 100

        labels = [
            f"{val:,}\n({pct:.1f}%)"
            for val, pct in zip(cm.flatten(), percentages.flatten())
        ]
        labels = np.asarray(labels).reshape(2, 2)

        sns.heatmap(
            cm,
            annot=labels,
            fmt='',
            cmap='Blues',
            ax=axes[idx],
            cbar=False,
            xticklabels=['Benign', 'Malicious'],
            yticklabels=['Benign', 'Malicious']
        )

        axes[idx].set_title(
            f"{res['Model']} (Acc: {res['Accuracy'] * 100:.2f}%)",
            fontsize=12,
            fontweight='bold'
        )
        axes[idx].set_xlabel('Predicted Label')
        axes[idx].set_ylabel('True Label')

    plt.tight_layout()
    plt.savefig(
        save_path,
        dpi=300
    )
    plt.close()

    print(
        f"[+] Confusion matrices saved to: {save_path}"
    )


def plot_roc_curves(results, y_test, save_path):
    if not PLT_AVAILABLE:
        return

    from sklearn.metrics import roc_curve

    plt.figure(
        figsize=(8, 6)
    )

    for res in results:
        if res['probs'] is not None:
            fpr, tpr, _ = roc_curve(
                y_test,
                res['probs']
            )
            plt.plot(
                fpr,
                tpr,
                label=f"{res['Model']} (AUC = {res['ROC_AUC']:.4f})",
                linewidth=2
            )

    plt.plot(
        [0, 1],
        [0, 1],
        'k--',
        label='Random Guess',
        alpha=0.6
    )

    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate (FPR)', fontsize=11)
    plt.ylabel('True Positive Rate (TPR)', fontsize=11)
    plt.title('ROC Curves - PyPI Malicious Package Detection', fontsize=13, fontweight='bold')
    plt.legend(loc='lower right', fontsize=10)
    plt.grid(True, linestyle='--', alpha=0.5)

    plt.tight_layout()
    plt.savefig(
        save_path,
        dpi=300
    )
    plt.close()

    print(
        f"[+] ROC curves saved to: {save_path}"
    )


def main():
    total_start = time.time()

    X_test, y_test = load_test_data(DATA_PATH)

    results = []

    for name in MODEL_NAMES:
        model_file = f"{name}.pkl"
        model_path = os.path.join(
            MODELS_DIR,
            model_file
        )

        if not os.path.exists(model_path):
            print(
                f"[-] Warning: Model file not found: {model_file} - skipping"
            )
            continue

        model = joblib.load(model_path)
        display_name = name.replace('-', ' ')

        res = evaluate_model(
            display_name,
            model,
            X_test,
            y_test
        )
        results.append(res)

        del model
        gc.collect()

    if not results:
        print("[-] No models were evaluated.")
        return

    print("\n" + "=" * 60)
    print("[*] Summary:")
    print("=" * 60)

    summary_df = pd.DataFrame(results)
    display_cols = [
        'Model',
        'Accuracy',
        'Precision',
        'Recall',
        'F1_Score',
        'ROC_AUC',
        'FPR',
        'FNR'
    ]

    print(
        summary_df[display_cols].to_string(index=False)
    )

    csv_path = os.path.join(
        REPORTS_DIR,
        'evaluation.csv'
    )
    summary_df[display_cols].to_csv(
        csv_path,
        index=False
    )
    print(
        f"\n[+] Saved evaluation summary: {csv_path}"
    )

    cm_path = os.path.join(
        REPORTS_DIR,
        'confusion_matrices.png'
    )
    roc_path = os.path.join(
        REPORTS_DIR,
        'roc_curves.png'
    )

    plot_confusion_matrices(
        results,
        cm_path
    )
    plot_roc_curves(
        results,
        y_test,
        roc_path
    )

    del X_test, y_test, results, summary_df
    gc.collect()


if __name__ == '__main__':
    main()
