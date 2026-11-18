### 5.3 Result Analysis

This section reports three measurements that must not be mixed. Section 5.3.1 is the live six-family review forest scored on the official ATRDF test file after XSS is dropped [3]. Section 5.3.2 is the eight-class forest on the same split with XSS kept. Section 5.3.3 is leave-one-family-out comparison, which is the ranking used when a family is absent from training.

Both Table VI and Table VII use the same Random Forest settings: 100 trees, maximum depth 16, `min_samples_split` 5, `max_features = sqrt`, random seed 42, and decision threshold \(\tau = 0.50\) [15], [16]. Fitting used scikit-learn 1.2.2. Replay: `research/atrdf_payload_experiment/train_six_family_heldout.py`. Production files under `models/atrdf` and `models/bola` were not replaced.

#### 5.3.1 ATRDF six-family official test

The first six-family candidate was a 20-feature forest. It mixed the 13 request statistics with seven structural flags and synthetic flag rows, then scored a 21,041-row development mask that had already been used while the candidate was built. Accuracy, precision, recall, and F1 were all 1.000 (TN 17,271, FP 0, FN 0, TP 3,770). That table is withdrawn. The flags reconstruct family labels. They remain review rules on port 8081. They are not inputs to the reported forest.

A second error was also removed. On this corpus, `header_count`, `url_special_count`, and `cookie_present` separate several families from benign traffic so cleanly that binary precision stays 1.000 at \(\tau = 0.50\). Those three columns are family proxies, not payload evidence. They are omitted here, as in the leave-one-family-out protocol of Section 5.3.3.

The reported detector therefore uses ten request statistics only: `url_entropy`, `path_length`, `url_length`, `path_segment_count`, `query_length`, `url_digit_count`, `user_agent_entropy`, `query_parameter_count`, `request_body_entropy`, and `request_body_digit_count`. XSS rows are dropped from train and test and are not relabeled as benign. No synthetic rows are added. The live review service loads this forest from `models/atrdf_six/` as `candidate_binary_rf_six_heldout`.

Training after the XSS drop uses 139,799 rows. The official test file is opened once after the fit. Table V already listed class support. Attack support on that file is 6,264 rows. Benign support is 28,687 rows. Table VI is the binary result.

**TABLE VI**  
ATRDF SIX-FAMILY OFFICIAL TEST (XSS DROPPED, 10 REQUEST FEATURES, \(\tau = 0.50\))

| Metric | Value |
|---|---:|
| Accuracy | 0.978913 |
| Precision | 0.998197 |
| Recall | 0.883940 |
| F1 | 0.937601 |
| FPR | 0.000349 |
| TN | 28,677 |
| FP | 10 |
| FN | 727 |
| TP | 5,537 |
| Rows | 34,951 |

Accuracy is high because the test file is still majority benign. Precision is high because only ten benign rows are scored malicious. Recall is 0.883940 because 727 of 6,264 attacks are scored benign. That is not a 1.000 diagonal. The false-positive rate is 10 / 28,687 = 0.000349.

Table VI-B splits the same predictions by stored family. A row is a true positive for a family only when the binary forest is malicious and the multiclass forest names that family.

**TABLE VI-B**  
FAMILY-WISE SCORES ON THE SIX-FAMILY OFFICIAL TEST

| Family | Support | Precision | Recall | F1 | Binary misses |
|---|---:|---:|---:|---:|---:|
| Cookie Injection | 1,548 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Directory Traversal | 788 | 1.000000 | 1.000000 | 1.000000 | 0 |
| RCE | 789 | 1.000000 | 1.000000 | 1.000000 | 0 |
| SQL Injection | 1,585 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Log Forging | 807 | 0.987654 | 0.991326 | 0.989487 | 7 |
| LOG4J | 747 | 1.000000 | 0.036145 | 0.069767 | 720 |

Cookie Injection, Directory Traversal, RCE, and SQL Injection remain linearly far from benign on URL and query counts, so the ten-feature forest still separates them [20], [21], [23]. Log Forging misses seven of 807 rows (recall 0.991326) [22]. LOG4J is the failure case. Only 27 of 747 LOG4J rows are detected (recall 0.036145). Of the 727 binary false negatives, 720 are LOG4J and 7 are Log Forging.

That LOG4J gap is expected from the feature set. Stored LOG4J traffic in ATRDF Dataset 4 often carries `${jndi:` in headers [17]. Header text is not one of the ten numeric inputs. Putting `jndi_lookup` into the forest was tried and produced accuracy, precision, recall, and F1 of 1.000 on both Table VI and Table VII. That result was refused and is not deployed. Live blocking of laboratory JNDI markers on port 8081 uses the review rule `ATRDF-JNDI-LOOKUP`. A rule block is not counted as a model detection in Table VI.

Table VI-C reports mean impurity decrease on the binary forest. Length and entropy of the URL dominate. Body digit count is almost unused.

**TABLE VI-C**  
BINARY FEATURE IMPORTANCE (SIX-FAMILY FOREST)

| Feature | Importance |
|---|---:|
| url_entropy | 0.195566 |
| url_length | 0.185340 |
| path_length | 0.152620 |
| path_segment_count | 0.139126 |
| query_length | 0.131872 |
| url_digit_count | 0.104100 |
| query_parameter_count | 0.055786 |
| user_agent_entropy | 0.020348 |
| request_body_entropy | 0.013399 |
| request_body_digit_count | 0.001842 |

About 59.39% of `REQUEST_ONLY_test.csv` rows share the ten-feature vector with train. Table VI-D scores only the 14,840 test rows whose vector was not seen in training. Cookie Injection and RCE have no unseen support on this split, so they do not appear as unseen detections.

**TABLE VI-D**  
UNSEEN-VECTOR SLICE OF THE SAME SIX-FAMILY FOREST

| Metric | Value |
|---|---:|
| Rows | 14,840 |
| Accuracy | 0.974394 |
| Precision | 0.994138 |
| Recall | 0.820910 |
| F1 | 0.899258 |
| FPR | 0.000783 |
| TN | 12,764 |
| FP | 10 |
| FN | 370 |
| TP | 1,696 |

Recall falls from 0.883940 to 0.820910 when repeated vectors are removed. The 370 unseen misses are 363 LOG4J and 7 Log Forging. All 363 unseen LOG4J rows are missed. Table VI is therefore an in-distribution official test, not a claim that a new family will be detected. That claim is tested in Section 5.3.3.

**Figure 5.** Family-wise precision, recall, and F1 on the six-family official test.

#### 5.3.2 Eight-class official test evaluation

Table VII uses the same ten features, the same forest settings, and the same official split. XSS rows are kept. This is not the live six-family review model. It is the eight-class counterpart stored under `models/atrdf_eight/`. Training uses 146,213 rows. The test file has 36,554 rows, which is Table V plus 1,603 XSS rows. Production `models/atrdf` remains the older 13-feature deployment on port 8080 and is not this table.

**TABLE VII**  
EIGHT-CLASS OFFICIAL TEST (XSS KEPT, 10 REQUEST FEATURES, \(\tau = 0.50\))

| Metric | Value |
|---|---:|
| Accuracy | 0.979811 |
| Precision | 0.998462 |
| Recall | 0.907589 |
| F1 | 0.950859 |
| FPR | 0.000383 |
| TN | 28,676 |
| FP | 11 |
| FN | 727 |
| TP | 7,140 |
| Rows | 36,554 |

Recall is higher than Table VI only because XSS is inside the positive class and is detected. The false-negative count is still 727, with the same family mix as Table VI. Eleven benign rows are scored malicious (FPR 0.000383). Precision is 7,140 / (7,140 + 11) = 0.998462.

**TABLE VII-B**  
FAMILY-WISE SCORES ON THE EIGHT-CLASS OFFICIAL TEST

| Family | Support | Precision | Recall | F1 | Binary misses |
|---|---:|---:|---:|---:|---:|
| Cookie Injection | 1,548 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Directory Traversal | 788 | 1.000000 | 1.000000 | 1.000000 | 0 |
| RCE | 789 | 1.000000 | 1.000000 | 1.000000 | 0 |
| SQL Injection | 1,585 | 1.000000 | 1.000000 | 1.000000 | 0 |
| XSS | 1,603 | 1.000000 | 1.000000 | 1.000000 | 0 |
| Log Forging | 807 | 0.986436 | 0.991326 | 0.988875 | 7 |
| LOG4J | 747 | 1.000000 | 0.036145 | 0.069767 | 720 |

XSS recall of 1.000 on this matrix is not used as a six-family result. Many labeled XSS rows in ATRDF Dataset 4 are payload-free `GET /forum` requests. The six-family live detector therefore drops XSS rather than claiming that class [3]. Table VII reports the eight-class forest because the earlier production evaluation included XSS. It does not put XSS back into the review model.

LOG4J recall is again 0.036145. Adding the JNDI marker as an eleventh forest input made this table 1.000 as well and was discarded. The review gateway still blocks laboratory JNDI with `ATRDF-JNDI-LOOKUP`. That rule is outside Table VII.

**TABLE VII-C**  
BINARY FEATURE IMPORTANCE (EIGHT-CLASS FOREST)

| Feature | Importance |
|---|---:|
| url_entropy | 0.205392 |
| url_length | 0.183856 |
| path_length | 0.148381 |
| path_segment_count | 0.118022 |
| query_length | 0.116149 |
| url_digit_count | 0.115955 |
| query_parameter_count | 0.051117 |
| user_agent_entropy | 0.033238 |
| request_body_entropy | 0.019576 |
| request_body_digit_count | 0.008313 |

The importance order matches Table VI-C. URL entropy and URL length remain the two strongest splits. Body features remain weak. The eight-class forest is not a different detector in feature terms. It is the same protocol with XSS kept in the label set.

**Figure 6.** Per-family recall on the eight-class official test, with LOG4J as the missed family.

#### 5.3.3 Offline algorithm comparison

The earlier grouped-development tables that showed accuracy, precision, recall, and F1 of 1.000 for every supervised model are not used here. Those scores were invalid for ranking. About 59.39% of `REQUEST_ONLY_test.csv` rows share a request-only vector with train. On the BOLA corpus, `cross_owner_ratio_recent > 0` has precision 1.000, so owner-ratio features act as generation proxies rather than authorization evidence.

Table VIII is the official-test binary comparison stored in the project. The five models are fit on the six-family train split using the same ten request statistics as Table VI, then scored once on the official test file at \(\tau = 0.50\). Replay: `research/atrdf_payload_experiment/train_table_viii.py`. Artifacts: `research/atrdf_payload_experiment/table_viii/` and `results/tables/TABLE_VIII_atrdf_binary_comparison.csv`. The Random Forest row matches `models/atrdf_six`. Production files under `models/atrdf` were not replaced.

**TABLE VIII**  
ATRDF BINARY COMPARISON (OFFICIAL TEST, 10 REQUEST FEATURES, \(\tau = 0.50\))

| Model | Accuracy | Precision | Recall | F1 | FPR | Latency (ms/row) |
|---|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.978913 | 0.998197 | 0.883940 | 0.937601 | 0.000349 | 0.009693 |
| Gradient boosting | 0.978656 | 0.997296 | 0.883301 | 0.936844 | 0.000523 | 0.009770 |
| Extra Trees | 0.978742 | 0.999277 | 0.882024 | 0.936997 | 0.000139 | 0.008994 |
| Logistic regression | 0.901262 | 0.853481 | 0.542146 | 0.663087 | 0.020323 | 0.000468 |
| Isolation Forest | 0.667248 | 0.250697 | 0.430715 | 0.316927 | 0.281103 | 0.073199 |

Random Forest is the live six-family detector. Extra Trees has the highest precision (0.999277). Logistic regression is the fastest. Isolation Forest is the unsupervised baseline [13], [14]. None of the supervised tree models has a 1.000 diagonal.

Leave-one-family-out is a separate ranking. The model is trained on benign traffic plus all families except one. The threshold is set on held-out benign validation to about 1% FPR. Metrics are the unweighted macro average across seven held-out families. Replay: `research/pattern_reinforcement/run_hard_evaluation.py`. File: `results/tables/TABLE_VIII_leave_one_family_out.csv`.

**TABLE VIII-B**  
ATRDF UNSEEN-FAMILY MACRO AVERAGE (LEAVE-ONE-FAMILY-OUT, 1% FPR)

| Model | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Logistic regression | 0.937269 | 0.460296 | 0.340470 | 0.362436 | 0.009729 | 0.860363 |
| Random Forest | 0.883935 | 0.370356 | 0.313101 | 0.271328 | 0.010168 | 0.877518 |
| Extra Trees | 0.894779 | 0.293778 | 0.085502 | 0.129629 | 0.009741 | 0.715814 |
| Gradient boosting | 0.880186 | 0.246754 | 0.067810 | 0.102191 | 0.010752 | 0.793738 |
| Pattern reinforcement | 0.873753 | 0.172202 | 0.151368 | 0.098006 | 0.010691 | 0.762352 |
| Isolation Forest | 0.871844 | 0.000000 | 0.000000 | 0.000000 | 0.009376 | 0.588175 |

No model keeps precision near 1.000 on unseen families. Logistic regression has the highest macro F1 (0.362436). Random Forest has the highest mean ROC-AUC (0.877518). Isolation Forest does not detect held-out families at this FPR budget.

**TABLE VIII-C**  
PER-FAMILY UNSEEN DETECTION (RANDOM FOREST)

| Held-out family | Support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Cookie Injection | 88 | 0.401826 | 1.000000 | 0.573290 |
| Directory Traversal | 1,004 | 0.832095 | 0.557769 | 0.667859 |
| LOG4J | 2,402 | 0.167742 | 0.010824 | 0.020336 |
| Log Forging | 3,993 | 0.817094 | 0.119709 | 0.208825 |
| RCE | 147 | 0.373737 | 0.503401 | 0.428986 |
| SQL Injection | 5,161 | 0.000000 | 0.000000 | 0.000000 |
| XSS | 134 | 0.000000 | 0.000000 | 0.000000 |

LOG4J, SQL Injection, and XSS do not transfer from other families under these features. Historical patterns on this corpus do not automatically detect every new family.

Table IX uses mixed BOLA sessions plus extra legitimate sessions, and only five timing and switch features: `request_frequency`, `object_switch`, `time_since_previous_request`, `request_burst_rate`, and `hour`. Owner ratios, session length, and request index are excluded. The threshold maximises F1 on validation.

**TABLE IX**  
BOLA MIXED-SESSION COMPARISON (TIMING FEATURES, MAX-F1 THRESHOLD)

| Model | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Pattern reinforcement | 0.791484 | 0.817597 | 0.747861 | 0.781176 | 0.165298 | 0.866447 |
| Random Forest | 0.795875 | 0.843614 | 0.724064 | 0.779281 | 0.132980 | 0.866802 |
| Gradient boosting | 0.797605 | 0.875465 | 0.691711 | 0.772816 | 0.097483 | 0.858257 |
| Extra Trees | 0.709248 | 0.664899 | 0.838235 | 0.741573 | 0.418543 | 0.819411 |
| Isolation Forest | 0.697272 | 0.683538 | 0.729412 | 0.705730 | 0.334570 | 0.766138 |
| Logistic regression | 0.625682 | 0.580483 | 0.893850 | 0.703864 | 0.640000 | 0.686999 |

Pattern reinforcement has the highest BOLA F1 (0.781176). Random Forest is essentially tied (0.779281). False-positive rates sit between 0.097 and 0.640. They are not zero.

**TABLE IX-B**  
BOLA EARLY DETECTION ON MIXED TEST SESSIONS (PATTERN REINFORCEMENT)

| Horizon k | Recall | FPR |
|---|---:|---:|
| 2 | 0.000 | 0.000 |
| 3 | 0.000 | 0.000 |
| 5 | 0.587 | 0.000 |
| 10 | 0.504 | 0.000 |

Detection before the first malicious request is 0. After the attack starts, recall at horizon 5 is 0.587.

**Figure 7.** ATRDF unseen-family macro F1.  
**Figure 8.** BOLA mixed-session F1.
