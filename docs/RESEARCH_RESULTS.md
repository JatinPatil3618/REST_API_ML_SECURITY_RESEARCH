# Comprehensive Research Results & Empirical Tables

## Table 1: Dataset Summary
| Dataset | Total Records | Partition Split | Classes | Duplicate Groups | Missing Values | Target Scope |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ATRDF Dataset 4** | 182,767 | Train: 146,213 \| Test: 36,554 | 8 | 92,861 | 0 | Input/Payload Manipulation |
| **VAmPI v6.2 (BOLA)** | 50,000 | 5,750 Sessions (80/10/10) | 2 | 0 | 0 | Object-Level Access Control |

---

## Table 4: Binary Classification (Held-out Test Split: 36,554 records)
| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Calibrated Threshold |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest (Primary)** | **0.9869** | **1.0000** | **0.9391** | **0.9686** | **0.9796** | **0.30** |
| **Logistic Regression (Baseline)** | 0.9377 | 0.9562 | 0.7445 | 0.8372 | 0.9470 | 0.50 |

---

## Table 5: Multiclass Classification on Malicious Categories
| Attack Category | Precision | Recall | F1-Score | Support (Test) |
| :--- | :--- | :--- | :--- | :--- |
| **XSS** | 1.0000 | 1.0000 | 1.0000 | 1,603 |
| **SQL Injection** | 1.0000 | 1.0000 | 1.0000 | 1,585 |
| **Cookie Injection** | 1.0000 | 1.0000 | 1.0000 | 1,548 |
| **Log Forging** | 1.0000 | 1.0000 | 1.0000 | 807 |
| **RCE** | 1.0000 | 1.0000 | 1.0000 | 789 |
| **Directory Traversal** | 1.0000 | 1.0000 | 1.0000 | 788 |
| **LOG4J** | 1.0000 | 1.0000 | 1.0000 | 747 |

---

## Table 6: BOLA Behavioral Session Evaluation (575 Untouched Test Sessions)
| Model | Normal F1 | BOLA F1 | Overall Accuracy | ROC-AUC | Partitioning |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest (Primary)** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | Session-Disjoint Grouping |
| **Logistic Regression (Baseline)**| 1.0000 | 1.0000 | 1.0000 | 1.0000 | Session-Disjoint Grouping |

---

## Table 7: Feature Set Ablation Trade-off
| Feature Set | Features | Random Forest Macro F1 | RF Precision | RF Recall | Inference Latency | Deployment Suitability |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **FULL_25** | 25 | 0.9801 | 1.0000 | 0.9390 | 0.0026 ms | Offline comparison only (Leans on status code) |
| **REDUCED_18**| 18 | 0.9801 | 1.0000 | 0.9389 | 0.0032 ms | Offline ablation |
| **REQUEST_ONLY_13**| 13 | **0.9801** | **1.0000** | **0.9390** | **0.0022 ms** | **Production Pre-Response Safe** |

---

## Table 8: Leave-One-Attack-Out Zero-Day Generalization
| Held-out Attack | Accuracy | Precision | Malicious Recall | F1-Score | Evaluation Samples |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **XSS** | 0.9999 | 1.0000 | 0.9981 | 0.9991 | 30,290 |
| **SQL Injection** | 0.9998 | 1.0000 | 0.9968 | 0.9984 | 30,272 |
| **Cookie Injection** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 30,235 |
| **Log Forging** | 1.0000 | 1.0000 | 0.9988 | 0.9994 | 29,494 |
| **RCE** | 0.9999 | 1.0000 | 0.9975 | 0.9987 | 29,476 |
| **Directory Traversal** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 29,475 |
| **LOG4J** | 0.9785 | 1.0000 | **0.1513** | **0.2628** | 29,434 |
