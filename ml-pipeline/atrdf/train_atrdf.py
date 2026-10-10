"""
ATRDF ML Training Pipeline
===========================
Trains Random Forest (primary) and Logistic Regression (baseline) models
for both binary (BENIGN vs MALICIOUS) and multiclass attack classification.

Uses the pre-computed feature sets from the research dataset.
Feature sets: REQUEST_ONLY_13, FULL_25, REDUCED_18

Key methodological decisions:
- Leakage-safe grouped splitting by canonical request hash
- REQUEST_ONLY_13 is the live deployment model (pre-response, gateway-safe)
- FULL_25 and REDUCED_18 are offline ablation comparisons only
- Test set is NEVER used for threshold tuning (validation split only)
"""

import os
import sys
import json
import hashlib
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
    roc_auc_score, confusion_matrix, classification_report,
    average_precision_score
)
from sklearn.preprocessing import LabelEncoder
from sklearn.calibration import CalibratedClassifierCV
import joblib
import sklearn

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger(__name__)

# Adjust path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))
from feature_definitions import (
    REQUEST_ONLY_13, FULL_25, REDUCED_18,
    ATRDF_LABEL_COL, ATRDF_BINARY_COL, ATRDF_CLASSES
)

RANDOM_SEED = 42
DATA_DIR = os.environ.get('ATRDF_DATA_DIR',
    r'C:\Users\Admin\OneDrive\Desktop\API\final_feature_sets-20261005T194332Z-1-001\final_feature_sets')
MODELS_DIR = os.environ.get('MODEL_DIRECTORY',
    r'C:\Users\Admin\OneDrive\Desktop\API\REST_API_ML_SECURITY_RESEARCH\models\atrdf')
RESULTS_DIR = os.environ.get('RESULTS_DIR',
    r'C:\Users\Admin\OneDrive\Desktop\API\REST_API_ML_SECURITY_RESEARCH\results')

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(os.path.join(RESULTS_DIR, 'figures'), exist_ok=True)
os.makedirs(os.path.join(RESULTS_DIR, 'tables'), exist_ok=True)
os.makedirs(os.path.join(RESULTS_DIR, 'metrics'), exist_ok=True)


# ============================================================
# 1. DATASET AUDIT
# ============================================================
def audit_dataset(df: pd.DataFrame, name: str) -> dict:
    log.info(f"=== Dataset Audit: {name} ===")
    audit = {
        "dataset": name,
        "total_records": len(df),
        "missing_values": int(df.isnull().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "columns": list(df.columns),
    }

    if ATRDF_LABEL_COL in df.columns:
        audit["labels"] = df[ATRDF_LABEL_COL].value_counts().to_dict()
        audit["class_count"] = int(df[ATRDF_LABEL_COL].nunique())

    if ATRDF_BINARY_COL in df.columns:
        audit["binary_distribution"] = df[ATRDF_BINARY_COL].value_counts().to_dict()
        benign = int((df[ATRDF_BINARY_COL] == 0).sum())
        malicious = int((df[ATRDF_BINARY_COL] == 1).sum())
        audit["benign_count"] = benign
        audit["malicious_count"] = malicious

    for k, v in audit.items():
        if k not in ('columns',):
            log.info(f"  {k}: {v}")

    return audit


# ============================================================
# 2. PREPROCESSING
# ============================================================
def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    # Drop rows with missing labels
    df = df.dropna(subset=[ATRDF_LABEL_COL])
    # Fill numeric NaN with 0
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)
    return df


# ============================================================
# 3. TRAIN + EVALUATE ONE MODEL
# ============================================================
def train_and_evaluate(
    X_train, y_train, X_val, y_val, X_test, y_test,
    model_type: str,  # 'rf' or 'lr'
    task: str,        # 'binary' or 'multiclass'
    feature_set_name: str,
    label_encoder=None
) -> dict:

    log.info(f"  Training {model_type.upper()} [{task}] on {feature_set_name} features...")

    if model_type == 'rf':
        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            max_features='sqrt',
            random_state=RANDOM_SEED,
            n_jobs=-1
        )
    else:  # Logistic Regression baseline
        clf = LogisticRegression(
            max_iter=1000,
            class_weight='balanced',
            random_state=RANDOM_SEED,
            multi_class='ovr' if task == 'multiclass' else 'auto',
            solver='lbfgs',
            C=1.0
        )

    clf.fit(X_train, y_train)

    # Calibrate threshold using validation set
    val_pred = clf.predict(X_val)
    val_proba = clf.predict_proba(X_val)

    # Compute validation metrics for threshold calibration
    best_threshold = 0.5
    if task == 'binary':
        best_f1 = 0.0
        for thresh in np.arange(0.3, 0.8, 0.05):
            preds = (val_proba[:, 1] >= thresh).astype(int)
            f1 = f1_score(y_val, preds, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = float(thresh)
        log.info(f"    Calibrated threshold: {best_threshold:.2f} (val F1={best_f1:.4f})")

    # Final test evaluation (test set is NOT touched during training)
    test_pred = clf.predict(X_test)
    test_proba = clf.predict_proba(X_test)

    metrics = {}

    if task == 'binary':
        # Use calibrated threshold for binary
        test_pred_thresh = (test_proba[:, 1] >= best_threshold).astype(int)
        metrics['accuracy'] = float(accuracy_score(y_test, test_pred_thresh))
        metrics['precision'] = float(precision_score(y_test, test_pred_thresh, zero_division=0))
        metrics['recall'] = float(recall_score(y_test, test_pred_thresh, zero_division=0))
        metrics['f1'] = float(f1_score(y_test, test_pred_thresh, zero_division=0))
        metrics['roc_auc'] = float(roc_auc_score(y_test, test_proba[:, 1]))
        metrics['pr_auc'] = float(average_precision_score(y_test, test_proba[:, 1]))
        metrics['threshold'] = best_threshold
        cm = confusion_matrix(y_test, test_pred_thresh)
    else:
        metrics['accuracy'] = float(accuracy_score(y_test, test_pred))
        metrics['macro_precision'] = float(precision_score(y_test, test_pred, average='macro', zero_division=0))
        metrics['macro_recall'] = float(recall_score(y_test, test_pred, average='macro', zero_division=0))
        metrics['macro_f1'] = float(f1_score(y_test, test_pred, average='macro', zero_division=0))
        metrics['weighted_precision'] = float(precision_score(y_test, test_pred, average='weighted', zero_division=0))
        metrics['weighted_recall'] = float(recall_score(y_test, test_pred, average='weighted', zero_division=0))
        metrics['weighted_f1'] = float(f1_score(y_test, test_pred, average='weighted', zero_division=0))

        # Per-class metrics
        if label_encoder:
            per_class = {}
            for i, cls_name in enumerate(label_encoder.classes_):
                y_bin = (y_test == i).astype(int)
                y_pred_bin = (test_pred == i).astype(int)
                per_class[str(cls_name)] = {
                    'precision': float(precision_score(y_bin, y_pred_bin, zero_division=0)),
                    'recall': float(recall_score(y_bin, y_pred_bin, zero_division=0)),
                    'f1': float(f1_score(y_bin, y_pred_bin, zero_division=0)),
                    'support': int(y_bin.sum())
                }
            metrics['per_class'] = per_class
        cm = confusion_matrix(y_test, test_pred)

    metrics['confusion_matrix'] = cm.tolist()

    log.info(f"    Test accuracy: {metrics['accuracy']:.4f}")
    if task == 'binary':
        log.info(f"    F1={metrics['f1']:.4f}, ROC-AUC={metrics['roc_auc']:.4f}")
    else:
        log.info(f"    Macro-F1={metrics['macro_f1']:.4f}")

    # Feature importance (RF only)
    if model_type == 'rf' and hasattr(clf, 'feature_importances_'):
        metrics['feature_importances'] = dict(zip(X_train.columns.tolist(), clf.feature_importances_.tolist()))

    return clf, metrics, best_threshold


# ============================================================
# 4. SAVE PLOTS
# ============================================================
def save_confusion_matrix_plot(cm, labels, title, filepath):
    fig, ax = plt.subplots(figsize=(max(6, len(labels)), max(5, len(labels))))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=labels, yticklabels=labels, ax=ax)
    ax.set_title(title, fontsize=13, pad=12)
    ax.set_ylabel('True Label', fontsize=11)
    ax.set_xlabel('Predicted Label', fontsize=11)
    plt.tight_layout()
    plt.savefig(filepath, dpi=120, bbox_inches='tight')
    plt.close()
    log.info(f"  Saved: {filepath}")


def save_feature_importance_plot(importances: dict, title: str, filepath: str, top_n=13):
    sorted_feats = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:top_n]
    names = [f[0] for f in sorted_feats]
    values = [f[1] for f in sorted_feats]

    fig, ax = plt.subplots(figsize=(8, max(5, top_n * 0.4)))
    bars = ax.barh(range(len(names)), values, color='steelblue', alpha=0.85)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel('Feature Importance', fontsize=10)
    ax.set_title(title, fontsize=11)
    plt.tight_layout()
    plt.savefig(filepath, dpi=120, bbox_inches='tight')
    plt.close()
    log.info(f"  Saved: {filepath}")


# ============================================================
# 5. MAIN TRAINING PIPELINE
# ============================================================
def run_atrdf_pipeline():
    log.info("=" * 60)
    log.info("ATRDF ML TRAINING PIPELINE")
    log.info("=" * 60)

    # -- Load datasets --
    log.info("Loading datasets...")
    train_path = os.path.join(DATA_DIR, 'REQUEST_ONLY_train.csv')
    test_path  = os.path.join(DATA_DIR, 'REQUEST_ONLY_test.csv')

    if not os.path.exists(train_path):
        log.error(f"ATRDF training data not found: {train_path}")
        sys.exit(1)

    df_train_raw = pd.read_csv(train_path)
    df_test_raw  = pd.read_csv(test_path)

    # Audit
    audit_train = audit_dataset(df_train_raw, "REQUEST_ONLY_train")
    audit_test  = audit_dataset(df_test_raw, "REQUEST_ONLY_test")

    # Save audit
    combined_audit = {
        "train": audit_train,
        "test": audit_test,
        "total_records": audit_train["total_records"] + audit_test["total_records"]
    }
    with open(os.path.join(RESULTS_DIR, 'metrics', 'dataset_audit_atrdf.json'), 'w') as f:
        json.dump(combined_audit, f, indent=2)

    # Preprocess
    df_train = preprocess(df_train_raw)
    df_test  = preprocess(df_test_raw)

    log.info(f"Train: {len(df_train)} rows | Test: {len(df_test)} rows")
    log.info(f"Actual labels found: {sorted(df_train[ATRDF_LABEL_COL].unique())}")

    # -- Prepare features --
    # The dataset already has train/test split (leakage-safe from prior research work)
    # We use 90% of train as actual train, 10% as validation for threshold calibration
    from sklearn.model_selection import train_test_split

    feature_cols = REQUEST_ONLY_13  # live deployment model

    X_all = df_train[feature_cols].values
    y_binary_all = df_train[ATRDF_BINARY_COL].values
    y_multi_all = df_train[ATRDF_LABEL_COL].values

    # Use GroupShuffleSplit-like approach — since data already pre-split by canonical group,
    # we use a simple holdout here (train came pre-processed leakage-safe)
    idx_train, idx_val = train_test_split(
        np.arange(len(df_train)),
        test_size=0.1,
        random_state=RANDOM_SEED,
        stratify=y_binary_all
    )

    X_train = pd.DataFrame(X_all[idx_train], columns=feature_cols)
    X_val   = pd.DataFrame(X_all[idx_val],   columns=feature_cols)
    X_test  = pd.DataFrame(df_test[feature_cols].values, columns=feature_cols)

    y_bin_train = y_binary_all[idx_train]
    y_bin_val   = y_binary_all[idx_val]
    y_bin_test  = df_test[ATRDF_BINARY_COL].values

    # Multiclass: encode labels
    le = LabelEncoder()
    y_multi_train_enc = le.fit_transform(y_multi_all[idx_train])
    y_multi_val_enc   = le.transform(y_multi_all[idx_val])
    y_multi_test_enc  = le.transform(df_test[ATRDF_LABEL_COL].values)

    log.info(f"Split -> train={len(X_train)}, val={len(X_val)}, test={len(X_test)}")
    log.info(f"Classes: {list(le.classes_)}")

    all_results = {}

    # ---- Binary RF (REQUEST_ONLY_13) — the live gateway model ----
    log.info("\n[ATRDF Binary - REQUEST_ONLY_13 - RandomForest]")
    rf_binary, rf_bin_metrics, rf_bin_thresh = train_and_evaluate(
        X_train, y_bin_train, X_val, y_bin_val, X_test, y_bin_test,
        model_type='rf', task='binary',
        feature_set_name='REQUEST_ONLY_13'
    )
    all_results['binary_rf_request_only'] = rf_bin_metrics

    # ---- Binary LR baseline (REQUEST_ONLY_13) ----
    log.info("[ATRDF Binary - REQUEST_ONLY_13 - LogisticRegression]")
    lr_binary, lr_bin_metrics, lr_bin_thresh = train_and_evaluate(
        X_train, y_bin_train, X_val, y_bin_val, X_test, y_bin_test,
        model_type='lr', task='binary',
        feature_set_name='REQUEST_ONLY_13'
    )
    all_results['binary_lr_request_only'] = lr_bin_metrics

    # ---- Multiclass RF (REQUEST_ONLY_13) ----
    log.info("[ATRDF Multiclass - REQUEST_ONLY_13 - RandomForest]")
    rf_multi, rf_multi_metrics, _ = train_and_evaluate(
        X_train, y_multi_train_enc, X_val, y_multi_val_enc, X_test, y_multi_test_enc,
        model_type='rf', task='multiclass',
        feature_set_name='REQUEST_ONLY_13',
        label_encoder=le
    )
    all_results['multiclass_rf_request_only'] = rf_multi_metrics

    # ---- Multiclass LR baseline ----
    log.info("[ATRDF Multiclass - REQUEST_ONLY_13 - LogisticRegression]")
    lr_multi, lr_multi_metrics, _ = train_and_evaluate(
        X_train, y_multi_train_enc, X_val, y_multi_val_enc, X_test, y_multi_test_enc,
        model_type='lr', task='multiclass',
        feature_set_name='REQUEST_ONLY_13',
        label_encoder=le
    )
    all_results['multiclass_lr_request_only'] = lr_multi_metrics

    # ============================================================
    # ABLATION: FULL_25 and REDUCED_18 (offline only)
    # ============================================================
    for feat_set_name, feat_cols_key in [('FULL_25', 'FULL_25'), ('REDUCED_18', 'REDUCED_18')]:
        feat_path_train = os.path.join(DATA_DIR, f'{feat_set_name}_train.csv')
        feat_path_test  = os.path.join(DATA_DIR, f'{feat_set_name}_test.csv')

        if not os.path.exists(feat_path_train):
            log.warning(f"Skipping ablation {feat_set_name} — file not found")
            continue

        df_abl_train = preprocess(pd.read_csv(feat_path_train))
        df_abl_test  = preprocess(pd.read_csv(feat_path_test))

        from feature_definitions import FULL_25, REDUCED_18
        abl_feats = FULL_25 if feat_cols_key == 'FULL_25' else REDUCED_18

        # Only keep columns that exist in dataset
        abl_feats_present = [c for c in abl_feats if c in df_abl_train.columns]

        if len(abl_feats_present) < 5:
            log.warning(f"Too few features for {feat_set_name}, skipping")
            continue

        Xa_all   = df_abl_train[abl_feats_present].values
        ya_binary_all = df_abl_train[ATRDF_BINARY_COL].values

        idx_a_train, idx_a_val = train_test_split(
            np.arange(len(df_abl_train)), test_size=0.1,
            random_state=RANDOM_SEED, stratify=ya_binary_all
        )

        Xa_train = pd.DataFrame(Xa_all[idx_a_train], columns=abl_feats_present)
        Xa_val   = pd.DataFrame(Xa_all[idx_a_val],   columns=abl_feats_present)
        Xa_test  = pd.DataFrame(df_abl_test[abl_feats_present].values, columns=abl_feats_present)

        ya_bin_train = ya_binary_all[idx_a_train]
        ya_bin_val   = ya_binary_all[idx_a_val]
        ya_bin_test  = df_abl_test[ATRDF_BINARY_COL].values

        log.info(f"[Ablation {feat_set_name} - RF Binary]")
        _, abl_rf_bin_metrics, _ = train_and_evaluate(
            Xa_train, ya_bin_train, Xa_val, ya_bin_val, Xa_test, ya_bin_test,
            model_type='rf', task='binary', feature_set_name=feat_set_name
        )
        all_results[f'binary_rf_{feat_set_name.lower()}'] = abl_rf_bin_metrics

        log.info(f"[Ablation {feat_set_name} - LR Binary]")
        _, abl_lr_bin_metrics, _ = train_and_evaluate(
            Xa_train, ya_bin_train, Xa_val, ya_bin_val, Xa_test, ya_bin_test,
            model_type='lr', task='binary', feature_set_name=feat_set_name
        )
        all_results[f'binary_lr_{feat_set_name.lower()}'] = abl_lr_bin_metrics

    # ============================================================
    # UNSEEN ATTACK GENERALIZATION (Leave-One-Attack-Out)
    # ============================================================
    log.info("\n=== Unseen Attack Generalization (Leave-One-Attack-Out) ===")
    unseen_results = {}
    attack_classes = [c for c in le.classes_ if c != 'Benign']

    for held_out in attack_classes:
        log.info(f"  Hold out: {held_out}")
        # Training on all classes except held_out (binary: benign vs rest-except-held-out)
        train_mask = df_train[ATRDF_LABEL_COL] != held_out
        held_mask  = (df_test[ATRDF_LABEL_COL] == held_out) | (df_test[ATRDF_LABEL_COL] == 'Benign')

        if train_mask.sum() < 100 or held_mask.sum() < 10:
            log.warning(f"    Insufficient samples for {held_out}, skipping")
            continue

        X_loo_train = pd.DataFrame(df_train.loc[train_mask, feature_cols].values, columns=feature_cols)
        y_loo_train = df_train.loc[train_mask, ATRDF_BINARY_COL].values

        X_loo_test  = pd.DataFrame(df_test.loc[held_mask, feature_cols].values, columns=feature_cols)
        y_loo_test  = df_test.loc[held_mask, ATRDF_BINARY_COL].values

        loo_idx_train, loo_idx_val = train_test_split(
            np.arange(len(X_loo_train)), test_size=0.1, random_state=RANDOM_SEED,
            stratify=y_loo_train
        )

        clf_loo = RandomForestClassifier(
            n_estimators=50, max_depth=15, class_weight='balanced',
            random_state=RANDOM_SEED, n_jobs=-1
        )
        clf_loo.fit(X_loo_train.iloc[loo_idx_train], y_loo_train[loo_idx_train])

        y_pred_loo = clf_loo.predict(X_loo_test)
        loo_metrics = {
            'held_out_attack': held_out,
            'accuracy': float(accuracy_score(y_loo_test, y_pred_loo)),
            'precision': float(precision_score(y_loo_test, y_pred_loo, zero_division=0)),
            'recall': float(recall_score(y_loo_test, y_pred_loo, zero_division=0)),
            'f1': float(f1_score(y_loo_test, y_pred_loo, zero_division=0)),
            'test_samples': int(len(y_loo_test)),
            'held_out_samples': int((df_test[ATRDF_LABEL_COL] == held_out).sum())
        }
        unseen_results[held_out] = loo_metrics
        log.info(f"    F1={loo_metrics['f1']:.4f}, Recall={loo_metrics['recall']:.4f}, Samples={loo_metrics['test_samples']}")

    all_results['unseen_attack_generalization'] = unseen_results

    # ============================================================
    # SAVE MODELS
    # ============================================================
    log.info("\n=== Saving Models ===")

    def save_model(clf, name, features, task, threshold=0.5):
        model_path = os.path.join(MODELS_DIR, f'{name}.joblib')
        joblib.dump(clf, model_path)
        meta = {
            "model_name": name,
            "model_version": "1.0.0",
            "algorithm": clf.__class__.__name__,
            "task": task,
            "features": features,
            "feature_count": len(features),
            "dataset": "ATRDF",
            "training_date": datetime.datetime.now().isoformat(),
            "random_seed": RANDOM_SEED,
            "python_version": platform.python_version(),
            "scikit_learn_version": sklearn.__version__,
            "threshold": threshold
        }
        return meta

    meta_rf_binary = save_model(rf_binary, 'atrdf_binary_rf_request_only',
                                 feature_cols, 'binary', rf_bin_thresh)
    meta_rf_multi  = save_model(rf_multi, 'atrdf_multiclass_rf_request_only',
                                 feature_cols, 'multiclass')
    meta_lr_binary = save_model(lr_binary, 'atrdf_binary_lr_request_only',
                                 feature_cols, 'binary', lr_bin_thresh)
    meta_lr_multi  = save_model(lr_multi, 'atrdf_multiclass_lr_request_only',
                                 feature_cols, 'multiclass')

    # Save label encoder
    joblib.dump(le, os.path.join(MODELS_DIR, 'label_encoder_multiclass.joblib'))

    # Save feature list
    with open(os.path.join(MODELS_DIR, 'feature_list_request_only.json'), 'w') as f:
        json.dump({"features": feature_cols, "count": len(feature_cols)}, f, indent=2)

    # Save model metadata
    all_meta = {
        "atrdf_binary_rf": meta_rf_binary,
        "atrdf_multiclass_rf": meta_rf_multi,
        "atrdf_binary_lr": meta_lr_binary,
        "atrdf_multiclass_lr": meta_lr_multi,
        "label_classes": list(le.classes_)
    }
    with open(os.path.join(MODELS_DIR, 'model_metadata.json'), 'w') as f:
        json.dump(all_meta, f, indent=2)

    # ============================================================
    # SAVE RESULTS & FIGURES
    # ============================================================
    # Confusion matrices
    cm_binary = confusion_matrix(y_bin_test,
        (rf_binary.predict_proba(X_test)[:, 1] >= rf_bin_thresh).astype(int))
    save_confusion_matrix_plot(
        cm_binary, ['BENIGN', 'MALICIOUS'],
        'ATRDF Binary RF - Confusion Matrix (REQUEST_ONLY_13)',
        os.path.join(RESULTS_DIR, 'figures', 'atrdf_binary_confusion_matrix.png')
    )

    cm_multi = confusion_matrix(y_multi_test_enc, rf_multi.predict(X_test))
    save_confusion_matrix_plot(
        cm_multi, list(le.classes_),
        'ATRDF Multiclass RF - Confusion Matrix',
        os.path.join(RESULTS_DIR, 'figures', 'atrdf_multiclass_confusion_matrix.png')
    )

    # Feature importance
    if 'feature_importances' in rf_bin_metrics:
        save_feature_importance_plot(
            rf_bin_metrics['feature_importances'],
            'ATRDF Binary RF - Feature Importance (REQUEST_ONLY_13)',
            os.path.join(RESULTS_DIR, 'figures', 'atrdf_binary_feature_importance.png')
        )

    if 'feature_importances' in rf_multi_metrics:
        save_feature_importance_plot(
            rf_multi_metrics['feature_importances'],
            'ATRDF Multiclass RF - Feature Importance',
            os.path.join(RESULTS_DIR, 'figures', 'atrdf_multiclass_feature_importance.png')
        )

    # Ablation comparison bar chart
    ablation_data = {}
    for key in ['binary_rf_request_only', 'binary_rf_reduced_18', 'binary_rf_full_25']:
        if key in all_results and 'f1' in all_results[key]:
            ablation_data[key.replace('binary_rf_', '').replace('_', '\n')] = all_results[key]['f1']

    if len(ablation_data) > 1:
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.bar(list(ablation_data.keys()), list(ablation_data.values()), color=['#2196F3', '#4CAF50', '#FF9800'])
        ax.set_ylim(0, 1)
        ax.set_ylabel('F1 Score', fontsize=11)
        ax.set_title('ATRDF Feature Set Ablation - Binary RF', fontsize=12)
        for i, v in enumerate(ablation_data.values()):
            ax.text(i, v + 0.01, f'{v:.3f}', ha='center', fontsize=10)
        plt.tight_layout()
        plt.savefig(os.path.join(RESULTS_DIR, 'figures', 'atrdf_ablation_comparison.png'), dpi=120)
        plt.close()

    # Unseen attack bar chart
    if unseen_results:
        attacks = list(unseen_results.keys())
        f1_scores = [unseen_results[a]['f1'] for a in attacks]
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(attacks, f1_scores, color='#9C27B0', alpha=0.8)
        ax.set_ylim(0, 1)
        ax.axhline(0.5, color='red', linestyle='--', alpha=0.6, label='0.5 threshold')
        ax.set_ylabel('F1 Score', fontsize=11)
        ax.set_title('ATRDF Leave-One-Attack-Out Generalization', fontsize=12)
        ax.set_xticklabels(attacks, rotation=30, ha='right')
        plt.tight_layout()
        plt.savefig(os.path.join(RESULTS_DIR, 'figures', 'atrdf_unseen_attack_generalization.png'), dpi=120)
        plt.close()

    # Save CSV results tables
    binary_rows = []
    for key in ['binary_rf_request_only', 'binary_lr_request_only',
                'binary_rf_reduced_18', 'binary_lr_reduced_18',
                'binary_rf_full_25', 'binary_lr_full_25']:
        if key in all_results:
            r = all_results[key]
            binary_rows.append({
                'model': key,
                'accuracy': r.get('accuracy'), 'precision': r.get('precision'),
                'recall': r.get('recall'), 'f1': r.get('f1'),
                'roc_auc': r.get('roc_auc'), 'pr_auc': r.get('pr_auc')
            })
    pd.DataFrame(binary_rows).to_csv(
        os.path.join(RESULTS_DIR, 'tables', 'binary_results.csv'), index=False)

    # Multiclass results
    multi_rows = []
    for key in ['multiclass_rf_request_only', 'multiclass_lr_request_only']:
        if key in all_results:
            r = all_results[key]
            multi_rows.append({
                'model': key,
                'accuracy': r.get('accuracy'),
                'macro_precision': r.get('macro_precision'),
                'macro_recall': r.get('macro_recall'),
                'macro_f1': r.get('macro_f1'),
                'weighted_f1': r.get('weighted_f1')
            })
    pd.DataFrame(multi_rows).to_csv(
        os.path.join(RESULTS_DIR, 'tables', 'multiclass_results.csv'), index=False)

    # Unseen attack results
    if unseen_results:
        pd.DataFrame(list(unseen_results.values())).to_csv(
            os.path.join(RESULTS_DIR, 'tables', 'unseen_attack_results.csv'), index=False)

    # Full metrics JSON
    with open(os.path.join(RESULTS_DIR, 'metrics', 'atrdf_all_metrics.json'), 'w') as f:
        # Remove non-serializable confusion matrices from output
        clean_results = {}
        for k, v in all_results.items():
            if isinstance(v, dict):
                clean_results[k] = {kk: vv for kk, vv in v.items()
                                    if kk not in ('confusion_matrix',)}
            else:
                clean_results[k] = v
        json.dump(clean_results, f, indent=2, default=str)

    log.info("\n=== ATRDF Training Complete ===")
    log.info(f"  Binary RF (REQUEST_ONLY_13): F1={rf_bin_metrics.get('f1',0):.4f}, ROC-AUC={rf_bin_metrics.get('roc_auc',0):.4f}")
    log.info(f"  Multiclass RF: Macro-F1={rf_multi_metrics.get('macro_f1',0):.4f}")
    log.info(f"  Models saved to: {MODELS_DIR}")
    log.info(f"  Results saved to: {RESULTS_DIR}")

    return {
        "rf_binary_model": rf_binary,
        "rf_multi_model": rf_multi,
        "label_encoder": le,
        "rf_bin_threshold": rf_bin_thresh,
        "all_results": all_results
    }


if __name__ == "__main__":
    run_atrdf_pipeline()
