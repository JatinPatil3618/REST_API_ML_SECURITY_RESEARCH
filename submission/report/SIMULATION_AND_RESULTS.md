## 5 Simulation and Result Analysis

### 5.1 Experimental Setup

The proposed Dual-Path API Security Gateway (DPASG) is evaluated in a controlled laboratory environment. The review gateway runs on port 8081 with the experimental-payload ATRDF profile. The machine-learning service on port 8000 loads the six-family ATRDF Random Forest candidate and the BOLA behavioral Random Forest. The demo API on port 5001 performs JWT authentication and book-owner checks. Live attack and benign traffic are generated with OWASP ZAP 2.17.0 and sent only to `http://127.0.0.1:8081`. Production port 8080 is not used as the attack target in this evaluation.

Offline ATRDF experiments use ATRDF Dataset 4 [3]. Offline BOLA experiments use the VAmPI-related behavioral corpus [10], [11]. Both live detectors use Random Forest classifiers with 100 trees, random seed 42, and decision threshold \(\tau = 0.50\) [15], [16]. The ATRDF review path uses ten request statistics. The BOLA path uses fourteen session-window features. Inference uses scikit-learn 1.2.2. Table III presents the tools used for the simulation.

**TABLE III**  
TOOLS USED

| Tools | Purpose | Version |
|---|---|---|
| Spring Boot Security Gateway | Inline request inspection, review rules, telemetry, and allow/alert/block decisions | 1.0.0 (review jar, port 8081) |
| FastAPI ML Service | Serves ATRDF and BOLA Random Forest inference | scikit-learn 1.2.2 |
| Node.js Demo API | JWT authentication and book-owner authorization | Node.js runtime (port 5001) |
| MongoDB | Stores catalog books and user records for the demo API | Local instance (port 27017) |
| OWASP ZAP | Sends live attack and benign requests to the review gateway | 2.17.0 |
| Python | Offline feature checks, training support, and metric computation | 3.x (`.venv-repair`) |
| Vite Catalog Frontend | Book catalog UI used for benign browsing checks | Vite 5.x (port 5173/4173) |
| Research Dashboard | Displays live telemetry for result inspection | Vite app (port 5174) |
| Java Runtime | Executes the Spring Boot review gateway | JDK 17+ compatible |

Table IV lists the attack and traffic classes covered in the evaluation.

**TABLE IV**  
ATTACK AND TRAFFIC CLASSES

| Path | Classes |
|---|---|
| ATRDF six-family scope | Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection |
| Outside ATRDF scope | XSS (excluded from six-family evaluation) |
| BOLA path | NORMAL, BOLA |
| Live benign checks | Catalog browse and search suite (35 cases) |

### 5.2 Dataset and Traffic Analysis

ATRDF Dataset 4 supplies labeled request-level traffic for input-manipulation detection [3]. The reported six-family split drops XSS and uses the official test file. Figure 3 shows that test support.

**TABLE V**  
SIX-FAMILY OFFICIAL TEST SUPPORT

| Class | Support |
|---|---:|
| Benign | 28,687 |
| Cookie Injection | 1,548 |
| Directory Traversal | 788 |
| LOG4J | 747 |
| Log Forging | 807 |
| RCE | 789 |
| SQL Injection | 1,585 |
| Total | 34,951 |

The eight-class evaluation with XSS kept uses 36,554 test rows and is reported in Table VII.

The BOLA behavioral corpus contains 50,000 rows and 5,750 sessions. Sessions are split into training, validation, and test partitions. The offline comparison in this paper uses 5,030 validation rows from 575 sessions, containing 2,469 NORMAL rows and 2,561 BOLA rows. Figure 4 summarizes this validation balance.

Live simulation uses scripted ZAP cases covering the six supported ATRDF families, owner and cross-owner BOLA reads, no-token access, public book read, and a 35-case benign suite. The LOG4J laboratory marker uses a non-routable research host. RCE strings are transmitted only as request text to `127.0.0.1`.

**Figure 3.** Class support in the six-family ATRDF official test.  
**Figure 4.** NORMAL versus BOLA counts in the offline BOLA validation partition.

### 5.3 Result Analysis

#### 5.3.1 ATRDF six-family official test

The 20-feature flag forest scored 1.000 on a 21,041-row development mask and is withdrawn. `header_count`, `url_special_count`, and `cookie_present` also force precision 1.000, so they are omitted. The live review forest uses ten request statistics, 100 trees, depth 16, seed 42, \(\tau = 0.50\), scikit-learn 1.2.2, and 139,799 training rows after XSS is dropped [15], [16]. Replay: `research/atrdf_payload_experiment/train_six_family_heldout.py`. The official test file is scored after the fit.

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

Of 6,264 attacks, 5,537 are detected. The 727 misses are 720 LOG4J and 7 Log Forging. LOG4J recall is 27/747 = 0.036145 because `${jndi:` sits in headers, which are not among the ten features [17]. Putting `jndi_lookup` into the forest made Table VI 1.000 and was refused. Live LOG4J blocking on port 8081 is the `ATRDF-JNDI-LOOKUP` rule, not a model detection.

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

**TABLE VI-D**  
UNSEEN-VECTOR SLICE (14,840 ROWS)

| Metric | Value |
|---|---:|
| Accuracy | 0.974394 |
| Precision | 0.994138 |
| Recall | 0.820910 |
| F1 | 0.899258 |
| FPR | 0.000783 |
| TN, FP, FN, TP | 12,764 / 10 / 370 / 1,696 |

Recall falls when repeated vectors are removed. All 363 unseen LOG4J rows are missed. Table VI is an in-distribution official test.

**Figure 5.** Family-wise precision, recall, and F1 on the six-family official test.

#### 5.3.2 Eight-class official test evaluation

Table VII is the same ten-feature protocol with XSS kept. Training uses 146,213 rows. Production `models/atrdf` on port 8080 is not replaced.

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

Recall is higher than Table VI only because XSS is in the positive class. The 727 false negatives are still 720 LOG4J and 7 Log Forging. XSS is outside six-family evaluation. LOG4J recall remains 0.036145. The JNDI review rule does not rewrite Table VII.

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

**Figure 6.** Per-family recall on the eight-class official test, with LOG4J as the missed family.

#### 5.3.3 Offline algorithm comparison (unseen families and mixed-session BOLA)

The 1.000 grouped-development comparison is withdrawn. Table VIII is the official-test binary comparison stored in the project: ten request statistics, XSS dropped, \(\tau = 0.50\). Replay: `research/atrdf_payload_experiment/train_table_viii.py`. The Random Forest row matches Table VI.

**TABLE VIII**  
ATRDF BINARY COMPARISON (OFFICIAL TEST, 10 REQUEST FEATURES, \(\tau = 0.50\))

| Model | Accuracy | Precision | Recall | F1 | FPR | Latency (ms/row) |
|---|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.978913 | 0.998197 | 0.883940 | 0.937601 | 0.000349 | 0.009693 |
| Gradient boosting | 0.978656 | 0.997296 | 0.883301 | 0.936844 | 0.000523 | 0.009770 |
| Extra Trees | 0.978742 | 0.999277 | 0.882024 | 0.936997 | 0.000139 | 0.008994 |
| Logistic regression | 0.901262 | 0.853481 | 0.542146 | 0.663087 | 0.020323 | 0.000468 |
| Isolation Forest | 0.667248 | 0.250697 | 0.430715 | 0.316927 | 0.281103 | 0.073199 |

Leave-one-family-out remains a separate ranking. Family-proxy features are omitted. The threshold is set on held-out benign validation to 1% FPR. Metrics are the unweighted macro average across seven held-out families. Replay: `research/pattern_reinforcement/run_hard_evaluation.py`. File: `results/tables/TABLE_VIII_leave_one_family_out.csv`.

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

No model has precision near 1.0 on unseen families. Logistic regression has the highest macro F1 (0.362436). Random Forest has the highest mean ROC-AUC (0.877518). Isolation Forest does not detect held-out families at this FPR budget.

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

LOG4J, SQL Injection, and XSS do not transfer from other families under these features. That is the future-attack result: historical patterns do not automatically detect every new family.

Table IX uses only mixed BOLA sessions plus extra legitimate sessions, and only five timing/switch features (`request_frequency`, `object_switch`, `time_since_previous_request`, `request_burst_rate`, `hour`). Owner ratios, session length, and request index are excluded. The threshold maximises F1 on validation (not a 1% FPR cut, which would force precision near 1 when classes are balanced).

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

SPR has the highest BOLA F1 (0.781176). Random Forest is essentially tied (0.779281). False-positive rates are 0.10–0.64, not 0.

**TABLE IX-B**  
BOLA EARLY DETECTION ON MIXED TEST SESSIONS (SPR)

| Horizon k | Recall | FPR |
|---:|---:|---:|
| 2 | 0.000 | 0.000 |
| 3 | 0.000 | 0.000 |
| 5 | 0.587 | 0.000 |
| 10 | 0.504 | 0.000 |

Detection before the first malicious request is 0. After the attack starts, recall at k=5 is 0.587.

**Figure 7.** ATRDF unseen-family macro F1.  
**Figure 8.** BOLA mixed-session F1.

#### 5.3.4 Live ZAP simulation

Experiment EXP-ZAP-PREVIEW sent the six supported families through ZAP to the review gateway. Table X records the live outcomes.

**TABLE X**  
LIVE ZAP FAMILY PASS ON REVIEW GATEWAY

| Family | ML decision | Rule | HTTP | Backend reached |
|---|---|---|---:|---|
| SQL Injection | BLOCK, 1.0 | ATRDF-SQL-STRUCTURE | 403 | false |
| Directory Traversal | BLOCK, 1.0 | ATRDF-PATH-TRAVERSAL | 403 | false |
| RCE marker | BLOCK, 1.0 | ATRDF-COMMAND-CHAIN | 403 | false |
| Cookie Injection | BLOCK, 1.0 | ATRDF-COOKIE-AUTHORITY | 401 | false |
| Log Forging | BLOCK, 1.0 | ATRDF-LOG-LINE | 403 | false |
| LOG4J | BLOCK, 1.0 | ATRDF-JNDI-LOOKUP | 403 | false |

The 35-case benign suite was allowed in all 35 cases with HTTP 200. Seeded book titles and ownership remained unchanged after the pass. Figure 9 shows the live allow and block counts for attack versus benign cases.

**Figure 9.** Live ZAP outcomes for six attack families and the benign suite.

#### 5.3.5 Live BOLA authorization outcomes

Live BOLA checks confirm that the model alert and the final HTTP result remain separate. An owner management read can alert and still return HTTP 200. A cross-owner management read alerts and then receives BOLA_AUTHORIZATION_DENIED with HTTP 403. Cross-owner mutations are denied with BOLA_PERMISSION_DENIED. A missing token reaches the demo API and returns HTTP 401. An anonymous public book read may alert with mitigation ALERT + public catalog read and still return HTTP 200. Figure 10 presents these cases as alert versus final authorization outcome.

**Figure 10.** Live BOLA alert versus final HTTP authorization outcome.

#### 5.3.6 Comparison with other existing approaches

Table XI compares the proposed method with existing approaches discussed in the related work. The comparison is qualitative. Numeric scores from other papers are not transferred onto our dataset. NA means the property is not applicable or is not the focus of that work.

**TABLE XI**  
COMPARISON OF THE PROPOSED APPROACH WITH OTHER EXISTING APPROACHES

| Reference | Detection method | Input-attack family naming | BOLA handling | Runtime API gateway | Live traffic verification |
|---|---|---|---|---|---|
| Aharon et al. [4] | Few-shot anomaly retrieval | NA | NA | NA | NA |
| Aharon et al. [5] | Data augmentation for anomaly detection | NA | NA | NA | NA |
| Dubin and Dvir [6] | REST structure learning | NA | NA | Partial | NA |
| Huang et al. [7] | Static SQL/program analysis (BolaRay) | NA | Static / source | NA | NA |
| Wu et al. [8] | Static taint tracking (BolaZ) | NA | Static / source | NA | NA |
| Santos Filho et al. [9] | OpenAPI to Petri nets (Links2CPN) | NA | Spec / log based | NA | NA |
| Johansens [10] | LLM review of OpenAPI | NA | Spec review | NA | NA |
| Chua et al. [13], Liu et al. [14] | Isolation Forest anomaly scoring | NA | NA | Optional | NA |
| He et al. [19] | Stateful REST fuzzing | NA | NA | NA | Generated tests |
| Proposed method | Dual-path Random Forest (DPASG) | Yes (six families) | Session alert + backend authorization | Yes | Yes (OWASP ZAP) |

\*NA: Not Applicable

Table XI shows that earlier studies usually address either input-anomaly detection or BOLA analysis. The proposed method combines six-family ATRDF naming, runtime gateway enforcement, BOLA alert with backend authorization, and OWASP ZAP live verification in one laboratory system.

### 5.4 Discussion of Results

The simulation supports three findings. First, on the scoped ATRDF development mask the six-family forest separates the supported classes cleanly, but that mask is not an independent test. Second, the frozen 13-feature test shows that LOG4J is difficult when the JNDI marker is absent from the trained feature set; the review path addresses that case with `jndi_lookup` and the JNDI review rule. Third, live ZAP checks confirm that ATRDF families can hard-block before the demo API, while BOLA alerts still leave ownership to the application.

The comparison is unseen-family ATRDF and mixed-session BOLA, not same-distribution copies of the training attacks. Macro ATRDF precision is 0.17–0.46; the best unseen-family F1 is logistic regression 0.362436. Random Forest remains in the gateway for live known-family scoring and as the SPR base learner. SPR has the highest mixed-session BOLA F1 (0.781176) with FPR 0.165298. Isolation Forest is not deployed for ATRDF unseen families (macro recall 0). LOG4J unseen recall is 0.010824: historical families do not cover it.

The results therefore support the dual-path claim of this paper: input manipulation and broken object authorization can be evaluated together in one laboratory gateway without collapsing them into one decision.
