# Empirical Research Experiments & Hypotheses Verification

## 1. Research Hypotheses & Experimental Outcomes

### Hypothesis H1: API-aware representations distinguish benign and malicious traffic.
- **Evidence**: The Random Forest binary model on the held-out ATRDF test split ($N=36,554$) achieved **0.9869 Accuracy**, **1.0 Precision**, **0.9391 Recall**, and **0.9686 F1-Score**. Linear baseline achieved **0.8372 F1-Score**.
- **Status**: **CONFIRMED**.

---

### Hypothesis H2: Different attack mechanisms depend on different predictive feature patterns.
- **Evidence**:
  - Gini feature importance shows ATRDF is predominantly driven by **`url_entropy`**, **`url_special_count`**, **`path_length`**, and **`query_length`**.
  - In contrast, BOLA attacks exhibit zero syntactic variance but are strongly predicted by temporal session variables: **`same_owner_ratio_recent`**, **`cross_owner_ratio_recent`**, and **`unique_owners_recent`**.
- **Status**: **CONFIRMED**.

---

### Hypothesis H3: Unseen-attack generalization is attack-dependent rather than universally successful.
- **Evidence (Leave-One-Attack-Out Protocol)**:
  - Injection attacks (XSS: 99.81% recall, SQLi: 99.68% recall, Directory Traversal: 100% recall) generalized exceptionally well due to overlapping token syntax.
  - In contrast, **LOG4J** recall plummeted to **15.13%** ($F_1 = 0.2628$). The model had never observed JNDI delimiter syntax during training.
- **Status**: **CONFIRMED**.

---

### Hypothesis H4: Request-only features support practical pre-response gateway detection.
- **Evidence**:
  - `REQUEST_ONLY_13` achieved **0.9801 Macro F1**, identical to the 25-feature set (`FULL_25`: 0.9801 Macro F1) and reduced set (`REDUCED_18`: 0.9801 Macro F1).
  - Average inference latency was measured at **0.0022 ms per request**, proving inline pre-response evaluation introduces virtually zero gateway overhead.
- **Status**: **CONFIRMED**.
