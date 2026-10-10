"""
BOLA ML Training Pipeline
==========================
Trains Random Forest (primary) and Logistic Regression (baseline) models
for binary BOLA detection using behavioral session-level features.

Key methodological decisions:
- SESSION-LEVEL splitting only (rolling behavioral features inside a session 
  are temporally correlated — random row splits would cause leakage)
- Excludes: requested_object, object_access_match, authenticated_user, object_owner,
  status_code, response_size (prevents ID memorization and auth-outcome shortcuts)
- Uses: request_frequency, unique_objects_recent, object_switch, etc.
- Output: NORMAL (0) or BOLA (1) with probability score

H3: Unseen-attack generalization is attack-dependent rather than universally successful.
"""

import os
import sys
import json
import datetime
import warnings
import logging
import platform

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, average_precision_score
)
import joblib
import sklearn

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger(__name__)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from feature_definitions import (
    BOLA_BEHAVIORAL_FEATURES, BOLA_LABEL_COL, BOLA_SESSION_COL,
    BOLA_CLASSES, BOLA_EXCLUDED_FEATURES
)

RANDOM_SEED = 42
BOLA_DATASET_PATH = os.environ.get(
    'BOLA_DATASET',
    r'C:\Users\Admin\OneDrive\Desktop\API\vampi_v6_2_50000_ML_READY.csv'
)
MODELS_DIR = os.environ.get(
    'MODEL_DIRECTORY',
    r'C:\Users\Admin\OneDrive\Desktop\API\REST_API_ML_SECURITY_RESEARCH\models\bola'
)
RESULTS_DIR = os.environ.get(
    'RESULTS_DIR',
    r'C:\Users\Admin\OneDrive\Desktop\API\REST_API_ML_SECURITY_RESEARCH\results'
)

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(os.path.join(RESULTS_DIR, 'figures'), exist_ok=True)
os.makedirs(os.path.join(RESULTS_DIR, 'tables'), exist_ok=True)
os.makedirs(os.path.join(RESULTS_DIR, 'metrics'), exist_ok=True)


# ============================================================
# 1. SESSION-LEVEL SPLIT
# ============================================================
def session_level_split(df, session_col, label_col, train_ratio=0.8, val_ratio=0.1, seed=42):
    """
    Splits data at the SESSION level.
    No session is allowed to appear in more than one partition.
    This prevents behavioral correlation leakage.
    """
    sessions = df[session_col].unique()
    np.random.seed(seed)
    np.random.shuffle(sessions)

    n_total = len(sessions)
    n_train = int(n_total * train_ratio)
    n_val   = int(n_total * val_ratio)

    train_sessions = set(sessions[:n_train])
    val_sessions   = set(sessions[n_train:n_train + n_val])
    test_sessions  = set(sessions[n_train + n_val:])

    train_mask = df[session_col].isin(train_sessions)
    val_mask   = df[session_col].isin(val_sessions)
    test_mask  = df[session_col].isin(test_sessions)

    log.info(f"  Sessions: {len(sessions)} total | train={len(train_sessions)} | val={len(val_sessions)} | test={len(test_sessions)}")
    log.info(f"  Rows: train={train_mask.sum()} | val={val_mask.sum()} | test={test_mask.sum()}")

    # Verify no overlap
    assert len(train_sessions & val_sessions) == 0, "Session leakage: train/val overlap"
    assert len(train_sessions & test_sessions) == 0, "Session leakage: train/test overlap"
    assert len(val_sessions & test_sessions) == 0, "Session leakage: val/test overlap"

    return df[train_mask], df[val_mask], df[test_mask]


# ============================================================
# 2. DATASET AUDIT
# ============================================================
def audit_bola_dataset(df: pd.DataFrame) -> dict:
    log.info("=== BOLA Dataset Audit ===")
    audit = {
        "total_records": len(df),
        "total_sessions": int(df[BOLA_SESSION_COL].nunique()),
        "missing_values": int(df.isnull().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "label_distribution": df[BOLA_LABEL_COL].value_counts().to_dict(),
        "normal_count": int((df[BOLA_LABEL_COL] == 0).sum()),
        "bola_count": int((df[BOLA_LABEL_COL] == 1).sum()),
        "features_used": BOLA_BEHAVIORAL_FEATURES,
        "features_excluded": BOLA_EXCLUDED_FEATURES,
    }
    for k, v in audit.items():
        if k not in ('features_used', 'features_excluded'):
            log.info(f"  {k}: {v}")
    return audit


# ============================================================
# 3. TRAIN + EVALUATE
# ============================================================
def train_evaluate_bola(X_train, y_train, X_val, y_val, X_test, y_test,
                         model_type: str) -> tuple:
    log.info(f"  Training BOLA {model_type.upper()}...")

    if model_type == 'rf':
        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            max_features='sqrt',
            random_state=RANDOM_SEED,
            n_jobs=-1
        )
    else:
        clf = LogisticRegression(
            max_iter=1000, class_weight='balanced',
            random_state=RANDOM_SEED, solver='lbfgs', C=1.0
        )

    clf.fit(X_train, y_train)

    # Calibrate threshold on validation set only
    val_proba = clf.predict_proba(X_val)[:, 1]
    best_threshold = 0.5
    best_f1 = 0.0
    for thresh in np.arange(0.3, 0.8, 0.05):
        preds = (val_proba >= thresh).astype(int)
        f1 = f1_score(y_val, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = float(thresh)

    log.info(f"    Calibrated threshold: {best_threshold:.2f} (val F1={best_f1:.4f})")

    # Evaluate on test set
    test_proba = clf.predict_proba(X_test)[:, 1]
    test_pred_thresh = (test_proba >= best_threshold).astype(int)

    metrics = {
        'model_type': model_type,
        'accuracy': float(accuracy_score(y_test, test_pred_thresh)),
        'normal_precision': float(precision_score(y_test, test_pred_thresh, pos_label=0, zero_division=0)),
        'normal_recall': float(recall_score(y_test, test_pred_thresh, pos_label=0, zero_division=0)),
        'normal_f1': float(f1_score(y_test, test_pred_thresh, pos_label=0, zero_division=0)),
        'bola_precision': float(precision_score(y_test, test_pred_thresh, pos_label=1, zero_division=0)),
        'bola_recall': float(recall_score(y_test, test_pred_thresh, pos_label=1, zero_division=0)),
        'bola_f1': float(f1_score(y_test, test_pred_thresh, pos_label=1, zero_division=0)),
        'roc_auc': float(roc_auc_score(y_test, test_proba)),
        'pr_auc': float(average_precision_score(y_test, test_proba)),
        'threshold': best_threshold,
        'confusion_matrix': confusion_matrix(y_test, test_pred_thresh).tolist(),
    }

    log.info(f"    Accuracy={metrics['accuracy']:.4f}, BOLA F1={metrics['bola_f1']:.4f}, ROC-AUC={metrics['roc_auc']:.4f}")

    if model_type == 'rf' and hasattr(clf, 'feature_importances_'):
        metrics['feature_importances'] = dict(zip(X_train.columns.tolist(), clf.feature_importances_.tolist()))

    return clf, metrics, best_threshold


# ============================================================
# 4. MAIN PIPELINE
# ============================================================
def run_bola_pipeline():
    log.info("=" * 60)
    log.info("BOLA ML TRAINING PIPELINE")
    log.info("=" * 60)

    # Load dataset
    if not os.path.exists(BOLA_DATASET_PATH):
        log.error(f"BOLA dataset not found: {BOLA_DATASET_PATH}")
        sys.exit(1)

    log.info(f"Loading: {BOLA_DATASET_PATH}")
    df = pd.read_csv(BOLA_DATASET_PATH)

    # Audit
    audit = audit_bola_dataset(df)
    with open(os.path.join(RESULTS_DIR, 'metrics', 'dataset_audit_bola.json'), 'w') as f:
        json.dump(audit, f, indent=2, default=str)

    # Verify all behavioral features exist
    available_features = [f for f in BOLA_BEHAVIORAL_FEATURES if f in df.columns]
    missing_features = [f for f in BOLA_BEHAVIORAL_FEATURES if f not in df.columns]

    if missing_features:
        log.warning(f"Missing behavioral features: {missing_features}")
    log.info(f"Using {len(available_features)} behavioral features: {available_features}")

    # Verify excluded features are NOT being used
    leaked = [f for f in BOLA_EXCLUDED_FEATURES if f in available_features]
    assert not leaked, f"CRITICAL: Excluded features found in feature set: {leaked}"

    # Prepare data (drop rows with NaN in features)
    df_clean = df.dropna(subset=available_features + [BOLA_LABEL_COL, BOLA_SESSION_COL])
    df_clean = df_clean.copy()
    df_clean[available_features] = df_clean[available_features].fillna(0)

    log.info(f"Clean dataset: {len(df_clean)} rows, {df_clean[BOLA_SESSION_COL].nunique()} sessions")

    # Session-level split
    log.info("\nPerforming session-level split (80/10/10)...")
    df_train, df_val, df_test = session_level_split(
        df_clean, BOLA_SESSION_COL, BOLA_LABEL_COL,
        train_ratio=0.8, val_ratio=0.1, seed=RANDOM_SEED
    )

    X_train = df_train[available_features]
    y_train = df_train[BOLA_LABEL_COL].values
    X_val   = df_val[available_features]
    y_val   = df_val[BOLA_LABEL_COL].values
    X_test  = df_test[available_features]
    y_test  = df_test[BOLA_LABEL_COL].values

    log.info(f"Train label dist: {dict(zip(*np.unique(y_train, return_counts=True)))}")
    log.info(f"Test label dist:  {dict(zip(*np.unique(y_test, return_counts=True)))}")

    # Train RF (primary)
    log.info("\n[BOLA - RandomForest (Primary)]")
    rf_bola, rf_metrics, rf_thresh = train_evaluate_bola(
        X_train, y_train, X_val, y_val, X_test, y_test, 'rf')

    # Train LR (baseline)
    log.info("[BOLA - LogisticRegression (Baseline)]")
    lr_bola, lr_metrics, lr_thresh = train_evaluate_bola(
        X_train, y_train, X_val, y_val, X_test, y_test, 'lr')

    # ============================================================
    # SAVE MODELS
    # ============================================================
    log.info("\n=== Saving BOLA Models ===")

    joblib.dump(rf_bola, os.path.join(MODELS_DIR, 'bola_rf_behavioral.joblib'))
    joblib.dump(lr_bola, os.path.join(MODELS_DIR, 'bola_lr_behavioral.joblib'))

    feature_meta = {
        "features": available_features,
        "count": len(available_features),
        "excluded": BOLA_EXCLUDED_FEATURES
    }
    with open(os.path.join(MODELS_DIR, 'feature_list.json'), 'w') as f:
        json.dump(feature_meta, f, indent=2)

    model_meta = {
        "bola_rf": {
            "model_name": "bola_rf_behavioral",
            "model_version": "1.0.0",
            "algorithm": "RandomForestClassifier",
            "task": "binary",
            "features": available_features,
            "dataset": "VAmPI_BOLA_50K",
            "training_date": datetime.datetime.now().isoformat(),
            "random_seed": RANDOM_SEED,
            "python_version": platform.python_version(),
            "scikit_learn_version": sklearn.__version__,
            "threshold": rf_thresh,
            "training_samples": len(X_train),
            "validation_samples": len(X_val),
            "test_samples": len(X_test),
            "metrics": {k: v for k, v in rf_metrics.items() if k != 'confusion_matrix'}
        },
        "bola_lr": {
            "model_name": "bola_lr_behavioral",
            "algorithm": "LogisticRegression",
            "threshold": lr_thresh,
            "metrics": {k: v for k, v in lr_metrics.items() if k != 'confusion_matrix'}
        }
    }
    with open(os.path.join(MODELS_DIR, 'model_metadata.json'), 'w') as f:
        json.dump(model_meta, f, indent=2)

    # ============================================================
    # PLOTS
    # ============================================================
    # Confusion matrix
    cm = np.array(rf_metrics['confusion_matrix'])
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['NORMAL', 'BOLA'], yticklabels=['NORMAL', 'BOLA'], ax=ax)
    ax.set_title('BOLA RF - Confusion Matrix', fontsize=12)
    ax.set_ylabel('True Label'); ax.set_xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, 'figures', 'bola_confusion_matrix.png'), dpi=120)
    plt.close()

    # Feature importance
    if 'feature_importances' in rf_metrics:
        sorted_feats = sorted(rf_metrics['feature_importances'].items(), key=lambda x: x[1], reverse=True)
        names = [f[0] for f in sorted_feats]
        values = [f[1] for f in sorted_feats]
        fig, ax = plt.subplots(figsize=(8, max(5, len(names) * 0.4)))
        ax.barh(range(len(names)), values, color='#2196F3', alpha=0.85)
        ax.set_yticks(range(len(names))); ax.set_yticklabels(names, fontsize=9)
        ax.invert_yaxis()
        ax.set_xlabel('Feature Importance'); ax.set_title('BOLA RF - Feature Importance')
        plt.tight_layout()
        plt.savefig(os.path.join(RESULTS_DIR, 'figures', 'bola_feature_importance.png'), dpi=120)
        plt.close()

    # Save CSV results
    bola_rows = [
        {**{k: v for k, v in rf_metrics.items() if k not in ('confusion_matrix','feature_importances')}, 'model': 'BOLA_RF'},
        {**{k: v for k, v in lr_metrics.items() if k not in ('confusion_matrix','feature_importances')}, 'model': 'BOLA_LR'},
    ]
    pd.DataFrame(bola_rows).to_csv(
        os.path.join(RESULTS_DIR, 'tables', 'bola_results.csv'), index=False)

    log.info("\n=== BOLA Training Complete ===")
    log.info(f"  RF: Accuracy={rf_metrics['accuracy']:.4f}, BOLA F1={rf_metrics['bola_f1']:.4f}, ROC-AUC={rf_metrics['roc_auc']:.4f}")
    log.info(f"  LR: Accuracy={lr_metrics['accuracy']:.4f}, BOLA F1={lr_metrics['bola_f1']:.4f}")
    log.info(f"  Models saved to: {MODELS_DIR}")

    return {
        "rf_model": rf_bola,
        "lr_model": lr_bola,
        "rf_threshold": rf_thresh,
        "rf_metrics": rf_metrics,
        "features": available_features
    }


if __name__ == "__main__":
    run_bola_pipeline()
