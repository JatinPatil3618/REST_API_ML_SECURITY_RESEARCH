# Machine-Learning-Based Detection of REST API Security Attacks Across Input Manipulation and Broken Object-Level Authorization

**Draft for editing.** All metrics below are taken from the locked project evaluation and verification logs. They are not estimates. A limited local scan does not show that every attack is blocked or that vulnerabilities are absent.

---

## Abstract

REST APIs face two failure modes that are often collapsed into a single “malicious” label: input manipulation in the request, and broken object-level authorization (BOLA) across object identifiers. This paper presents a dual-path security gateway that separates those roles. Input manipulation is scored by a request-only Random Forest before the application executes the request. BOLA is scored by a session-window Random Forest, while the HTTP outcome for book management remains the application’s JWT and owner check. The input pathway uses ATRDF Dataset 4 with six supported families after XSS is removed from evaluation scope. The authorization pathway uses a VAmPI-derived behavioral corpus. On the official test after XSS is dropped (34,951 rows), the six-family forest has accuracy 0.978913, precision 0.998197, recall 0.883940, and F1 0.937601 (TN 28,677, FP 10, FN 727, TP 5,537). LOG4J recall is 0.036145; live LOG4J blocking uses the JNDI review rule. The eight-class test with XSS kept (36,554 rows) reports accuracy 0.979811, precision 0.998462, recall 0.907589, F1 0.950859, and false-positive rate 0.000383. Live checks with OWASP ZAP 2.17.0 against the review gateway show the six scripted families blocked before the demo API, and a 35-case benign suite allowed. The contribution is not a claim of complete coverage; it is a measured separation of detection, deterministic rules, and backend authorization on one catalog application.

**Keywords:** REST API security, Random Forest, ATRDF, SQL injection, directory traversal, RCE, cookie injection, log forging, Log4j/JNDI, BOLA, OWASP ZAP.

---

## I. Introduction

Application Programming Interfaces (APIs) are a primary interface between clients and backend services. The OWASP API Security Top 10 ranks broken object-level authorization first and lists injection among the critical API risks [1]. Surveys of RESTful API vulnerability detection likewise treat injection and insecure object references as distinct classes of failure [2].

A gateway that observes HTTP traffic can refuse a malicious payload before the application interprets it. The same statistical score cannot safely decide object ownership. Treating both problems as one binary “attack” class hides that difference. Blocking an anonymous public catalog read because a BOLA model alerts also hides a legitimate product behavior.

This paper studies both problems on one book-catalog laboratory. Catalog browsing is a normal website. Attack traffic is sent with OWASP ZAP [14] to a review security gateway. The design goals are:

1. Detect supported input-manipulation families from request-only features and block before the demo API.
2. Name the attack family when the binary detector scores the request malicious.
3. Score BOLA from a session window that does not use the raw user identifier as a shortcut feature.
4. Leave the owner decision to the demo API after a BOLA alert.
5. Record machine-learning decisions and deterministic rule matches as separate telemetry fields.

The remainder of the paper is organized as follows. Section II reviews related work. Section III states the research gap and contributions. Section IV describes the system. Section V presents methodology and datasets. Section VI reports experiments and results. Section VII discusses threats to validity. Section VIII concludes.

---

## II. Related Work

### A. Input Manipulation and ATRDF

The API Traffic Research Dataset Framework (ATRDF) provides progressive HTTP API corpora for malicious versus benign request classification, including SQL injection, XSS, RCE, Log4j, directory traversal, cookie injection, and log forging [3]. Aharon et al. evaluate few-shot anomaly detection with FastText embeddings and approximate nearest-neighbor retrieval on CSIC 2010 and ATRDF 2023, reporting strong unsupervised scores on ATRDF [4]. Those works primarily frame detection as anomaly or binary malice. They do not deploy a live gateway that (i) names six families with a supervised forest, (ii) separates rule blocks from model blocks, and (iii) keeps object authorization out of the payload classifier.

The LOG4J family in this study refers to JNDI lookup abuse associated with CVE-2021-44228 [13].

### B. Broken Object-Level Authorization

BolaRay detects BOLA by combining SQL and static analysis over database-backed applications [5]. BolaZ uses zero-trust static taint tracking of resource identifiers and authorization intervals [6]. Santos Filho et al. transform OpenAPI specifications into colored Petri nets and check server traces for BOLA with Links2CPN [7]. These approaches find or verify authorization flaws in source, specification, or logs. They are complementary to, not the same as, a runtime session-window classifier that only alerts while the application still enforces ownership.

Johansens evaluates large language models for BOLA discovery from OpenAPI documents and includes VAmPI among REST APIs suitable for BOLA study [8]. VAmPI is a deliberately vulnerable OpenAPI-based API used for security testing [9]. This project uses VAmPI-derived traffic for the behavioral BOLA corpus and does not reimplement the LLM detector in [8].

### C. Anomaly Detection and Classifiers

Isolation Forest is a canonical unsupervised anomaly detector [10]. Random Forests remain a strong supervised baseline for tabular security features [11]. Models in this work are trained and loaded with scikit-learn [12]. Isolation Forest is retained only as a comparison baseline in offline algorithm comparison; the live detectors are Random Forests.

### D. Live Exercise

OWASP ZAP is used as the local proxy and request tool for scripted attack and benign checks against the review gateway [14].

---

## III. Research Gap and Contributions

**Gap.** Offline API detectors often either (a) treat every unusual request as one malicious class, or (b) make the detector also the access-control decision. Static BOLA tools [5]–[7] do not score live session windows in a gateway. Unsupervised ATRDF detectors [4] do not report per-family gateway telemetry with separate rule and backend fields.

**Contributions.**

1. A dual-path review gateway: ATRDF family detection can hard-block; BOLA scoring alerts and defers ownership to the demo API.
2. A six-family request-only Random Forest (13 statistics, XSS dropped) with structural flags kept as review rules rather than as forest inputs.
3. Telemetry that stores `mlDecision`, `ruleId`, gateway `decision`, HTTP status, and `backendReached` separately.
4. A measured ZAP exercise on the review path (port 8081) for six families, BOLA cases, and a 35-case benign suite, without treating production port 8080 as the attack target.

---

## IV. System Architecture

The laboratory stack is:

- **Catalog frontend** — book browse/search UI.
- **Review security gateway** — port 8081, experimental payload ATRDF profile.
- **ML inference service** — port 8000, loads ATRDF and BOLA Random Forests.
- **Demo API** — port 5001, JWT login and book owner checks.
- **OWASP ZAP** — local tool on `127.0.0.1:8091` for scripted requests [14].
- **Research dashboard** — reads gateway telemetry; it is not an attack surface in this evaluation.

Production gateway port 8080 and production model files remain unchanged for the review experiments.

**Decision separation.**

- An ATRDF model BLOCK returns before the demo API (`backendReached = false`). Cookie Injection uses HTTP 401; other supported ATRDF classes use HTTP 403.
- If the model allows and a review rule matches, the HTTP block is attributed to the rule; telemetry still records `mlDecision` ALLOW when applicable.
- A BOLA model BLOCK on the review profile is stored and converted to gateway ALERT for book management and for public book read. The demo API then applies JWT and owner checks. A public catalog read that alerts and still returns HTTP 200 is treated as policy, not as a confirmed BOLA vulnerability.

Identity is taken only from a verified login JWT. Missing or invalid identity is `unknown`. The header `X-Authenticated-User` is not trusted.

---

## V. Methodology

### A. Datasets

**ATRDF Dataset 4** [3], as stored in project metadata, contains 182,767 records (146,213 train / 36,554 test), eight labels, no missing values. Production multiclass labels include Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, and XSS.

For the six-family review candidate, XSS-labeled rows are dropped from the official train and test CSVs. They are not relabeled as benign. The reported forest is scored on 34,951 official-test rows.

**BOLA / VAmPI.** Following prior BOLA testbed selection that includes VAmPI [8], [9], the behavioral corpus used in metadata is named VAmPI v6.2: 50,000 records and 5,750 sessions, split by session into train / validation / test partitions. Classes are NORMAL and BOLA. Predictors exclude raw user and object identifiers as shortcut labels.

### B. Features

**ATRDF (production, 13 features):** Shannon entropies and counts over URL, path, query, headers, cookie presence, and body.

**ATRDF (review forest):** 10 request statistics after family-proxy columns are removed. Seven structural flags are review rules, not forest inputs. Header values are still scanned for `${jndi:` so the JNDI rule can block LOG4J [17].

**BOLA (14 behavioral features):** request frequency, distinct objects/owners, switches, cross-owner count and ratio, same-owner and same-object ratios, inter-arrival time, burst rate, hour, session length, and request index over a recent window.

### C. Models

Both live pathways use Random Forest classifiers [15], [16]: 100 trees, `random_state = 42`. ATRDF max depth is 16; BOLA max depth is 12. Decision threshold is 0.50 and was not lowered. Review model names report `candidate_binary_rf_six_heldout`. Logistic regression remains a stored linear baseline; Isolation Forest [13], [14] is used only in offline comparison.

XSS is outside six-family evaluation. A large share of labeled XSS rows are payload-free `GET /forum` requests; using path memorization would inflate recall and was not added.

---

## VI. Experiments and Results

### A. Six-Family Official Test

The development mask that scored 1.0 on every binary metric is withdrawn. The reported six-family forest uses 10 request statistics after family-proxy columns are removed. XSS rows are dropped. Official test, 34,951 rows, \(\tau = 0.50\):

| Metric | Value |
|---|---:|
| Accuracy | 0.978913 |
| Precision | 0.998197 |
| Recall | 0.883940 |
| F1 | 0.937601 |
| False-positive rate | 0.000349 |
| TN, FP, FN, TP | 28,677 / 10 / 727 / 5,537 |

LOG4J recall is 0.036145. The 727 misses are 720 LOG4J and 7 Log Forging. Live LOG4J blocking is the review rule, not this forest.

### B. Eight-Class Official Test Evaluation

The same 10-feature protocol with XSS kept, 36,554 test rows at threshold 0.50:

| Metric | Value |
|---|---:|
| Accuracy | 0.979811 |
| Precision | 0.998462 |
| Recall | 0.907589 |
| F1 | 0.950859 |
| FPR | 0.000383 |
| TN, FP, FN, TP | 28,676 / 11 / 727 / 7,140 |

Of the 727 false negatives, 720 are LOG4J and 7 are Log Forging. End-to-end LOG4J recall on that matrix is 0.036145 (support 747). Live review LOG4J blocking uses the JNDI review rule; it does not rewrite Table VII.

### C. Offline Algorithm Comparison (Unseen Families and Mixed-Session BOLA)

Same-distribution precision near 1.0 is discarded as a ranking. Table VIII is leave-one-family-out with family-proxy features removed (`header_count`, `url_special_count`, `cookie_present`). Macro-average over seven held-out families at 1% benign FPR: logistic regression precision 0.460296, recall 0.340470, F1 0.362436, ROC-AUC 0.860363; Random Forest precision 0.370356, recall 0.313101, F1 0.271328, ROC-AUC 0.877518. LOG4J unseen recall is 0.010824. Isolation Forest macro recall is 0.

BOLA uses mixed sessions and five timing/switch features only. The threshold maximises validation F1. Pattern reinforcement: precision 0.817597, recall 0.747861, F1 0.781176, FPR 0.165298, ROC-AUC 0.866447. Random Forest F1 0.779281. Extra Trees FPR is 0.418543. Early mixed-session recall is 0 at request index ≤ 3 and 0.587 at horizon 5. Production `models/` files were not replaced.

### D. Live ZAP Family Pass

Experiment `EXP-ZAP-PREVIEW` sent scripted families to `http://127.0.0.1:8081` only [14]:

| Family | ML | Rule | HTTP | Backend |
|---|---|---|---:|---|
| SQL Injection | BLOCK, 1.0 | ATRDF-SQL-STRUCTURE | 403 | false |
| Directory Traversal | BLOCK, 1.0 | ATRDF-PATH-TRAVERSAL | 403 | false |
| RCE marker | BLOCK, 1.0 | ATRDF-COMMAND-CHAIN | 403 | false |
| Cookie Injection | BLOCK, 1.0 | ATRDF-COOKIE-AUTHORITY | 401 | false |
| Log Forging | BLOCK, 1.0 | ATRDF-LOG-LINE | 403 | false |
| LOG4J | BLOCK, 1.0 | ATRDF-JNDI-LOOKUP | 403 | false |

The 35-case benign suite was 35/35 ALLOW with HTTP 200. Seeded book titles and ownership were unchanged after the pass. XSS was not sent in this six-family live count.

### E. Live BOLA Authorization

On review BOLA cases, the model may alert while the demo API decides:

- Owner management read: ALERT, backend reached, HTTP 200.
- Cross-owner management read: ALERT, then `BOLA_AUTHORIZATION_DENIED`, HTTP 403.
- Cross-owner mutation: `BOLA_PERMISSION_DENIED`, resource unchanged.
- No token: HTTP 401 from the demo API.
- Anonymous public book read: ALERT + public catalog read, HTTP 200 (not counted as a vulnerability).

---

## VII. Threats to Validity

1. Same-family official-test recall can still be high for payload families whose request statistics differ sharply from benign traffic.
2. Six-family LOG4J recall is 0.358768 without the lookup marker as a trained feature. Live LOG4J blocking is the review rule.
3. Frozen eight-class LOG4J recall on 36,554 rows is the same 0.358768 figure; leave-one-attack-out LOG4J recall in earlier tables is a different experiment.
4. BOLA CSV offline scores and live session-window scores are different measurements.
5. ZAP scripted cases and a bounded local scan do not cover every payload, method, or route. Rule-only blocks are reported as rules, not as model detections.
6. Results are for a laboratory catalog and review gateway, not an Internet-facing production deployment.

---

## VIII. Conclusion

This paper presented a dual-path REST API security gateway that detects six input-manipulation families with a request-only Random Forest and scores BOLA with a session-window Random Forest while leaving object ownership to the application. ATRDF Dataset 4 [3] and a VAmPI-derived corpus [8], [9] supply the offline labels. Live ZAP checks [14] show hard blocks for the six scripted families before the demo API, allowed benign catalog traffic in a 35-case suite, and BOLA alerts whose HTTP outcomes follow JWT and owner checks. The work separates machine-learning predictions, deterministic rules, and backend authorization in telemetry. It does not claim complete attack coverage or independent-test perfection for the six-family candidate.

**Future work.** A pre-declared scoring pass of the six-family candidate on a file unused during flag design; broader payload coverage; and optional stronger baselines for unsupervised comparison without deploying Isolation Forest as the live enforcer.

---

## References

[1] OWASP Foundation, “OWASP API Security Top 10,” 2023. [Online]. Available: https://owasp.org/API-Security/editions/2023/en/0x11-t10/

[2] F. Tanveer, F. Iradat, W. Iqbal, and A. Ahmad, “Towards secure APIs: A survey on RESTful API vulnerability detection,” Comput. Mater. Continua, vol. 84, no. 3, pp. 4223–4257, 2025, doi: 10.32604/cmc.2025.067536.

[3] S. Lavian and Ariel University, Ariel Cyber Innovation Center (ACIC), “The API Traffic Research Dataset Framework (ATRDF),” 2023. [Online]. Available: https://github.com/ArielCyber/Cisco_Ariel_Uni_API_security_challenge

[4] U. Aharon, R. Dubin, A. Dvir, and C. Hajaj, “A classification-by-retrieval framework for few-shot anomaly detection to detect API injection,” Comput. Secur., vol. 150, Art. no. 104249, 2025, doi: 10.1016/j.cose.2024.104249.

[5] Y. Huang, C. Shi, J. Lu, H. Li, H. Meng, and L. Li, “Detecting broken object-level authorization vulnerabilities in database-backed applications,” in Proc. ACM SIGSAC Conf. Comput. Commun. Secur. (CCS), Salt Lake City, UT, USA, 2024, doi: 10.1145/3658644.3690227.

[6] A. Wu, Z. Feng, R. Feng, Z. Xing, and Y. Liu, “Rethinking broken object level authorization attacks under zero trust principle,” arXiv:2507.02309, 2025. [Online]. Available: https://arxiv.org/abs/2507.02309

[7] A. Santos Filho, R. J. Rodríguez, and E. L. Feitosa, “Automated broken object-level authorization attack detection in REST APIs through OpenAPI to colored Petri nets transformation,” Int. J. Inf. Secur., vol. 24, Art. no. 83, 2025, doi: 10.1007/s10207-024-00970-5.

[8] E. Johansens, “Detecting BOLA vulnerabilities with large language models,” B.A. thesis, Univ. of Twente, Enschede, The Netherlands, 2025. [Online]. Available: https://essay.utwente.nl/essays/107423

[9] erev0s, “VAmPI: Vulnerable API (based on OpenAPI 3),” GitHub repository. [Online]. Available: https://github.com/erev0s/VAmPI

[10] F. T. Liu, K. M. Ting, and Z.-H. Zhou, “Isolation Forest,” in Proc. 8th IEEE Int. Conf. Data Mining (ICDM), Pisa, Italy, 2008, pp. 413–422, doi: 10.1109/ICDM.2008.17.

[11] L. Breiman, “Random forests,” Mach. Learn., vol. 45, no. 1, pp. 5–32, 2001.

[12] F. Pedregosa et al., “Scikit-learn: Machine learning in Python,” J. Mach. Learn. Res., vol. 12, pp. 2825–2830, 2011.

[13] NIST National Vulnerability Database, “CVE-2021-44228,” 2021. [Online]. Available: https://nvd.nist.gov/vuln/detail/CVE-2021-44228

[14] OWASP ZAP Project, “OWASP Zed Attack Proxy (ZAP),” ver. 2.17.0. [Online]. Available: https://www.zaproxy.org/
