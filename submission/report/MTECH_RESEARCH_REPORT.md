# Machine-Learning-Based Detection and Generalization of REST API Security Attacks Across Access-Control and Input-Manipulation Threats

M.Tech Cybersecurity final-year research report. The measurements below are taken from the project metadata, the locked evaluation report, the six-family scope note, and the verification logs. They are not estimates. A limited local scan does not show that the system blocks every attack, and it does not show that vulnerabilities are absent.

## Abstract

This project separates two REST API failure modes. Input manipulation is scored by a request-only Random Forest before the application runs the request. Broken object-level authorization is scored by a session-window Random Forest, and the HTTP result for book management is still the demo API's JWT and owner check. The review six-family forest uses the 10 request statistics that are not family proxies. Structural flags are review rules, not model inputs. On the official test file after XSS is dropped (34,951 rows), accuracy is 0.978913, precision is 0.998197, recall is 0.883940, and F1 is 0.937601, with confusion TN 28,677, FP 10, FN 727, TP 5,537. The 727 misses are 720 LOG4J and 7 Log Forging. The eight-class scoring with XSS kept (36,554 rows) is reported separately. Live checks through OWASP ZAP 2.17.0 sent the six supported families to `http://127.0.0.1:8081`. A matching review rule can still block when the forest stays benign, including LOG4J through `ATRDF-JNDI-LOOKUP`. A 35-case benign suite was 35/35 allowed. XSS is outside the six-family evaluation.

**Keywords:** REST API security, Random Forest, SQL injection, directory traversal, command markers, cookie injection, log forging, JNDI, BOLA, OWASP ZAP.

## 1. Introduction

A gateway that sees the HTTP request can refuse a payload before the application interprets it. The same gateway cannot decide object ownership from a statistical score alone. This project studies both problems on one book-catalog application. The catalog is a normal website. Attack requests are sent by OWASP ZAP to the review gateway, not by buttons on the page.

The production gateway listens on port 8080 and still loads the original model files under `models/atrdf` and `models/bola`. The review gateway listens on port 8081 with `--gateway.atrdf.profile=experimental-payload`. The built catalog at `http://127.0.0.1:4173/` calls `http://127.0.0.1:8081`.

## 2. Problem statement

Input-manipulation families and broken object authorization fail for different reasons. A single classifier that treats both as one malicious class hides that difference. A classifier that blocks a public book read because the caller is anonymous also hides a legitimate catalog operation. The problem is to detect the supported input families from the request, keep object authorization in the application, and show which component produced the HTTP result.

## 3. Objectives

1. Score request-only features for input manipulation before the demo API runs.
2. Name the attack family when the binary model calls the request malicious.
3. Score BOLA from a session window that does not contain the raw user id as a shortcut.
4. Leave the owner decision to the demo API when the BOLA model alerts.
5. Record the machine-learning decision and any deterministic rule as separate fields.
6. Exercise the review path with OWASP ZAP without sending those tests to port 8080.

## 4. Research contributions

- A six-family request-only Random Forest scored on the official test after XSS is dropped, with structural flags kept as review rules rather than as model features.
- Gateway telemetry that stores `mlDecision`, `ruleId`, `decision`, HTTP status, and `backendReached` separately.
- A review policy that forwards a BOLA model block on book management and on a public book read, while an ATRDF model block still stops the request.
- A ZAP record that joins the ZAP message id to the gateway request id for the six families, the benign suite, and the BOLA cases.

## 5. Related work

The OWASP API Security Top 10, 2023 edition, lists broken object-level authorization as API1 and places injection among the API risks [1]. OWASP ZAP 2.17.0 is the proxy and scanner used for the live checks [2]. Random Forests are the classifier family used for both pathways [3]. The saved forests were loaded with scikit-learn [4]. The LOG4J family refers to the JNDI lookup class of CVE-2021-44228 [5]. The BOLA corpus is named in this repository as VAmPI v6.2. The input corpus is named ATRDF Dataset 4 in `models/atrdf/model_metadata.json`. This repository does not store an external citation for ATRDF Dataset 4, so none is added here.

## 6. Research gap

Published API testbeds and attack corpora are often evaluated offline, or the detector is also the access-control decision. This project keeps those roles apart. Offline metrics on a validation mask are not treated as proof about unseen traffic. The live gateway can also block with a deterministic rule when the forest stays benign, and that outcome is reported as a rule block.

## 7. Methodology

### 7.1 Datasets and labels

ATRDF Dataset 4, as stored in the project metadata, has 182,767 records: 146,213 training rows and 36,554 test rows, eight labels, no missing values. The production multiclass order is Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, and XSS.

The six-family trainer drops XSS-labeled rows from the official train and test CSVs. They are not rewritten as benign. The reported forest is trained on 139,799 rows and scored on 34,951 official-test rows. The seven laboratory requests were not added to training. Production files under `models/` were not written.

VAmPI v6.2, as stored in `models/bola/model_metadata.json`, has 50,000 records and 5,750 sessions, split by session into 4,600 training sessions (40,010 rows), 5,030 validation rows, and 4,960 test rows across 575 test sessions. The classes are NORMAL and BOLA. The feature list excludes raw user and object identifiers.

### 7.2 Preprocessing and features

The reported six-family forest uses 10 request statistics: Shannon entropies and counts of the URL, path, query, and body. `header_count`, `url_special_count`, and `cookie_present` are omitted because they reconstruct family identity. Their formulas are in `docs/FEATURES.md`. Seven structural flags (`sql_structure`, `markup_script`, `path_traversal`, `command_chain`, `cookie_signal`, `log_control`, and `jndi_lookup`) are computed for review rules. They are not inputs to `candidate_binary_rf_six_heldout`. `jndi_lookup` is true when the text contains `${jndi:` with optional internal whitespace. Header values are scanned for that marker because stored LOG4J rows keep it in headers.

The BOLA vector has 14 features over a window of 10 requests: frequency, distinct objects and owners, switches, cross-owner count and ratio, repeat ratio, inter-arrival time, burst rate, hour, session length, and request index.

### 7.3 Models

Both pathways use a Random Forest of 100 trees and seed 42. The ATRDF depth is 16. The BOLA depth is 12. Logistic regression is the stored linear baseline. The review binary and multiclass files are `research/atrdf_payload_experiment/heldout_six/candidate_binary_rf_six_heldout.joblib` and `candidate_multiclass_rf_six_heldout.joblib`. Live inference reports `candidate_binary_rf_six_heldout`. The threshold is 0.50. It was not lowered. `max_features` is `sqrt`. Class indices 0 through 5 are Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, and SQL Injection.

A markup-only laboratory request can still match review rule `ATRDF-MARKUP-SCRIPT`. That event is outside six-family model scoring.

The production artifacts under `models/atrdf` and `models/bola` were not replaced. `docs/MODELS.md` mentions a validation F1 peak at threshold 0.30. The saved ATRDF metadata and the locked test evaluation both use 0.50. The deployed threshold in this submission is 0.50.

### 7.4 Gateway decisions

An ATRDF block is written by the gateway and the method returns before `forwardToDemoApi`. Cookie Injection uses HTTP 401 and the body `Invalid session state. Reauthentication required.` The other ATRDF classes use HTTP 403. `backendReached` stays false on that path.

If the model allows the request and a review rule matches, the HTTP block is the rule. Telemetry still shows `mlDecision` ALLOW and class BENIGN. The rule identifiers are `ATRDF-SQL-STRUCTURE`, `ATRDF-PATH-TRAVERSAL`, `ATRDF-COMMAND-CHAIN`, `ATRDF-COOKIE-AUTHORITY`, `ATRDF-LOG-LINE`, `ATRDF-JNDI-LOOKUP`, and `ATRDF-MARKUP-SCRIPT`.

A BOLA model block on the review profile is stored as `mlDecision` BLOCK and gateway `decision` ALERT when no review rule matched. Management views and mutations use mitigation `ALERT + backend authorization`. A plain book GET or HEAD uses `ALERT + public catalog read`. The demo API then applies its own JWT and owner checks. A public read that the model scores as BOLA is not treated as a vulnerability.

Identity is taken from a verified login JWT. A missing, invalid, or spoofed identity is `unknown`. The header `X-Authenticated-User` is not trusted.

## 8. Architecture

The diagrams in `submission/diagrams/` match the review deployment:

1. `01_system_architecture.svg` — catalog, ZAP, review gateway, ML service, demo API, telemetry, and the untouched production gateway.
2. `02_request_flow.svg` — identity, features, model, rules, decision, telemetry.
3. `03_atrdf_detection.svg` — model block, rule-only block, and forward.
4. `04_bola_authorization.svg` — model alert, then the demo API or the public-read forward.
5. `05_zap_workflow.svg` — passive scan of the built site, active tests only against port 8081.

The ML service listens on port 8000. The demo API listens on port 5001. ZAP 2.17.0 listens on `127.0.0.1:8091`. The research dashboard on port 5174 reads telemetry and is not an attack surface in this evaluation.

## 9. Experimental setup

Offline ATRDF scoring used scikit-learn 1.2.2 for the locked test pass and for the six-family candidate. The production metadata file records scikit-learn 1.2.0 at training time on 8 October 2026. The six-family validation mask is the same seed-42 mask used for the earlier payload candidates. It is not a fresh holdout.

The live stack for the final ZAP pass was review PID 22888 on port 8081, production PID 32176 on port 8080, and the built catalog on port 4173. Experiment id `EXP-ZAP-PREVIEW`. XSS was not sent. The LOG4J marker host was `test-research-domain.invalid`. The RCE string was query text sent only to `127.0.0.1`.

## 10. Results

### 10.1 Six-family official test

These figures are from `research/atrdf_payload_experiment/HELDOUT_SIX_REPORT.md`. XSS rows are dropped. Structural flags and family-proxy statistics are not model inputs.

| Metric | Value |
|---|---:|
| Accuracy | 0.978913 |
| Precision | 0.998197 |
| Recall | 0.883940 |
| F1 | 0.937601 |
| False-positive rate | 0.000349 |
| TN, FP, FN, TP | 28,677, 10, 727, 5,537 |
| Rows | 34,951 |

| Family | Test support | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| SQL Injection | 1,585 | 1.0 | 1.0 | 1.0 |
| Directory Traversal | 788 | 1.0 | 1.0 | 1.0 |
| RCE | 789 | 1.0 | 1.0 | 1.0 |
| Cookie Injection | 1,548 | 1.0 | 1.0 | 1.0 |
| Log Forging | 807 | 0.987654 | 0.991326 | 0.989487 |
| LOG4J | 747 | 1.0 | 0.036145 | 0.069767 |

The 727 binary misses are 720 LOG4J and 7 Log Forging. The withdrawn 1.000 development-mask table is not used.

### 10.2 Eight-class official test evaluation

`models/atrdf_eight/metrics.json` records the same 10-feature protocol with XSS kept. Production files under `models/atrdf` were not replaced.

On 36,554 rows at threshold 0.50, binary accuracy is 0.979811, precision is 0.998462, recall is 0.907589, F1 is 0.950859, and the false-positive rate is 0.000383. Confusion is TN 28,676, FP 11, FN 727, TP 7,140. The 727 misses are 720 LOG4J and 7 Log Forging.

End-to-end family metrics from that same matrix:

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Cookie Injection | 1.0 | 1.0 | 1.0 | 1,548 |
| Directory Traversal | 1.0 | 1.0 | 1.0 | 788 |
| LOG4J | 1.0 | 0.036145 | 0.069767 | 747 |
| Log Forging | 0.986436 | 0.991326 | 0.988875 | 807 |
| RCE | 1.0 | 1.0 | 1.0 | 789 |
| SQL Injection | 1.0 | 1.0 | 1.0 | 1,585 |
| XSS | 1.0 | 1.0 | 1.0 | 1,603 |

`docs/RESEARCH_RESULTS.md` Table 5 lists recall 1.0 for every family, including LOG4J. That table does not match this confusion matrix. The matrix is the measurement used in this report.

`docs/RESEARCH_RESULTS.md` Table 8 reports a leave-one-attack-out LOG4J malicious recall of 0.1513. That is a different experiment, on attacks held out of training. It is not a score of the six-family candidate.

### 10.3 XSS exclusion

Validation XSS on the header-aware candidate is 931 rows. 469 contain markup. 462 do not. Two unflagged rows pick up another structural flag. The other 460 set no flag. XSS recall on that candidate is 471/931 = 0.5059. Precision on that family is 1.0. Every XSS row in the training partition uses the path `/forum`, and no benign row uses that path. A path feature would raise recall by memorizing the endpoint. It was not added.

The raw partition has 3,211 plain `GET /forum` rows and 3,203 rows whose `message` query contains a script tag. The plain rows have an empty query and body. Their response body is the 24-character content type `text/html; charset=utf-8`, which is not a payload and is not a feature. The six-family model therefore does not claim an XSS class. The deterministic rule `ATRDF-MARKUP-SCRIPT` can still block a laboratory script payload. When that payload is scored, the model label is RCE because of `markup_script`. That event is excluded from the six-family detection count.

### 10.4 BOLA metrics and live authorization

`models/bola/model_metadata.json` stores test metrics for the production forest: accuracy 1.0, NORMAL F1 1.0, BOLA F1 1.0, ROC-AUC 1.0, on 4,960 test rows and 575 test sessions. A later replay of 5,030 validation rows (2,469 NORMAL, 2,561 BOLA), scored from the precomputed CSV columns at threshold 0.50, gave TN 2,469, FP 0, FN 0, TP 2,561. That replay did not score live gateway features, and it did not open the ATRDF test file.

Live ZAP evidence is the authorization result. On experiment `EXP-ZAP-BOLA`, user01's management read of book 101 was model BOLA 1.0, gateway ALERT, backend reached, HTTP 200. User02's management read was the same model block and ALERT, then backend `BOLA_AUTHORIZATION_DENIED`, HTTP 403. User02's edit and delete of disposable book 111 were denied with `BOLA_PERMISSION_DENIED`. A management read with no token reached the backend and returned HTTP 401 `Authentication required. Please log in.` An anonymous public read of book 101 was model BOLA 1.0, gateway `ALERT + public catalog read`, HTTP 200. That public-read alert is not a BOLA vulnerability.

On the final review process, experiment `EXP-ZAP-PREVIEW`, the owner management read REQ-1048 was BOLA 0.73 / NORMAL 0.27, ALERT, HTTP 200, backend true. User02's read REQ-1049 was BOLA 1.0, ALERT, HTTP 403 `BOLA_AUTHORIZATION_DENIED`, backend true. The probability differs across processes because the session window changes. The HTTP outcome is the demo API's check.

### 10.5 ZAP attack tests and benign regression

The final explicit family pass, `EXP-ZAP-PREVIEW`, used ZAP `sendRequest` against `http://127.0.0.1:8081` only.

| Family | ZAP message | Request | ML | Rule | HTTP | Backend |
|---|---:|---|---|---|---:|---|
| SQL Injection | 124 | REQ-1002 | BLOCK, SQL Injection, 1.0 | `ATRDF-SQL-STRUCTURE` | 403 | false |
| Directory Traversal | 125 | REQ-1003 | BLOCK, Directory Traversal, 1.0 | `ATRDF-PATH-TRAVERSAL` | 403 | false |
| RCE marker | 126 | REQ-1004 | BLOCK, RCE, 1.0 | `ATRDF-COMMAND-CHAIN` | 403 | false |
| Cookie Injection | 127 | REQ-1005 | BLOCK, Cookie Injection, 1.0 | `ATRDF-COOKIE-AUTHORITY` | 401 | false |
| Log Forging | 128 | REQ-1006 | BLOCK, Log Forging, 1.0 | `ATRDF-LOG-LINE` | 403 | false |
| LOG4J | 129 | REQ-1007 | BLOCK, LOG4J, 1.0 | `ATRDF-JNDI-LOOKUP` | 403 | false |

The Cookie Injection 401 is the gateway status for that class. The body is `Invalid session state. Reauthentication required.` It is not the demo API sentence `Authentication required. Please log in.`

`category=Technology`, `search=sleep`, and `ref=a+b;c` were REQ-1008 through REQ-1010, all ALLOW, malicious probability 0.0, rule NONE, backend true. The 35-case suite was REQ-1011 through REQ-1045, 35/35 HTTP 200 ALLOW, with the same model decision. Book 101 remained `Foundations of Network Protocol Security`, owner user01, with 1 comment. Book 201 remained `Applied Machine Learning in Anomaly Detection`, owner user02.

An earlier bounded active scan of port 8081, policy `bounded-safe`, raised 0 injection alerts from the enabled scanners. The joined history also showed rule-only blocks: 17 SQL, 13 path, and 13 command rows where the model stayed BENIGN at malicious probability 0.0. Those rows are rule mitigations. They are not model detections. Three markup rows classified as RCE are excluded from both the XSS count and the RCE success count.

### 10.6 Software tests already recorded

Python `test_payload_features.py` passed 22 cases. The gateway run that included the public-read and CSP cases passed 15 tests with 0 failures at 2026-10-11T15:37:37+05:30. `VerifiedIdentityTest` passed 5 tests with 0 failures at 2026-10-11T16:06:15+05:30. An earlier package run recorded 32 passing gateway tests at 2026-10-11T14:11:28+05:30, before the later public-read change. This submission did not rerun those suites and did not rerun the test class that rewrites `controlled_suite_features.json`.

### 10.7 Built-frontend headers

ZAP passive spider scan 1 of `http://127.0.0.1:4173/`, before preview headers, reported missing `X-Content-Type-Options`, missing anti-clickjacking protection, and a missing Content Security Policy, plus an informational comment match in the bundle. After `vite preview` was given headers, spider scan 2 no longer reported plugins 10021, 10020, or 10038.

The preview policy is `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' http://127.0.0.1:8081 https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`, together with `nosniff` and `X-Frame-Options: DENY`.

Plugin 10055 remains because `style-src` includes `'unsafe-inline'`. The catalog components set style attributes. Removing the keyword would block those styles. Rewriting the catalog layout to avoid it would be an interface redesign, which this freeze does not do. Plugin 90003 remains because the Google Fonts stylesheet has no integrity attribute. That stylesheet is not a fixed file, so a stored hash would not stay valid. Integrity attributes were not added, and the alerts were not deleted. Plugin 10027 is an informational match on the word `select` inside the React bundle's SVG namespace string. Plugin 10109 is an informational modern-application note.

The Vite development server on port 5173 does not send this policy. Its missing-header findings belong to that development server. The built preview is the measured frontend.

The built page rendered the seeded catalog. The Technology filter returned four books. Search for `Anomaly` returned one book. View Details showed owner user02 and zero comments. The computed font was Inter, so the font hosts in the policy loaded.

## 11. Threats to validity

The withdrawn flag-forest development mask scored 1.000 because the flags reconstructed labels. The reported six-family forest does not use those flags or the three family-proxy statistics. LOG4J recall on the official test is 0.036145 without the lookup marker as a trained feature. The live LOG4J block on the review gateway is the `ATRDF-JNDI-LOOKUP` rule. It does not rewrite Table VI or Table VII.

The BOLA CSV scores and the live session scores are different measurements. A public book read can receive a BOLA alert because the caller is `unknown` and the owner is another user. Forwarding that read is a policy choice on the review profile. The running production jar was not updated with that policy.

ZAP's bounded active scan and the six scripted requests do not cover every payload, method, or route. Time-based and file-target strings have been observed where the forest stays benign and only the review rule blocks. Header findings on a local preview server are not a statement about an internet-facing deployment.

`REQUEST_ONLY_test.csv` was opened once to score `candidate_binary_rf_six_heldout` after that forest was fit. Production files under `models/` were not replaced.

## 12. Conclusion

The review gateway can block the six scripted families with the held-out forest, a review rule, or both, and does not call the demo API on those blocks. Benign catalog reads in the 35-case suite are allowed. Object authorization for book management remains the demo API's decision after a BOLA alert. XSS is outside the model scope. LOG4J model recall on the official test is 0.358768; live LOG4J blocking uses the JNDI review rule. The production models and port 8080 were not changed. None of these results is a claim of complete coverage.

## 13. Future work

Further work can add the JNDI marker as a single trained feature without bringing the other family flags back into the forest, and can replace inline style attributes so the preview policy can drop `'unsafe-inline'`. Neither change is required for the measured catalog behavior.

## 14. Reproducibility

Start only the review path. Do not point ZAP or the catalog at port 8080. The demo checklist in `submission/demo/DEMO_CHECKLIST.md` lists the processes, the six family requests, the BOLA cases, and the benign suite. Feature formulas are in `docs/FEATURES.md` and `research/atrdf_payload_experiment/FEATURE_DEFINITIONS.md`. The verification narratives are `docs/END_TO_END_VERIFICATION.md`, `docs/ZAP_ATRDF_VERIFICATION.md`, and `docs/BOLA_MITIGATION_VERIFICATION.md`.

Python feature checks, when repeated, must use `.venv-repair\Scripts\python.exe`. Gateway packaging that must not rewrite the controlled-suite feature file uses Maven with tests skipped. The review profile flag is `--gateway.atrdf.profile=experimental-payload`.

## References

[1] OWASP Foundation. *OWASP API Security Top 10*, 2023 edition. https://owasp.org/API-Security/editions/2023/en/0x11-t10/

[2] OWASP ZAP. Version 2.17.0, as reported by the local daemon `GET /JSON/core/view/version/`. Project site: https://www.zaproxy.org/

[3] Breiman, L. Random Forests. *Machine Learning* 45, 5–32 (2001).

[4] Pedregosa, F., et al. Scikit-learn: Machine Learning in Python. *Journal of Machine Learning Research* 12, 2825–2830 (2011). The live candidate was loaded with scikit-learn 1.2.2. The production metadata records 1.2.0.

[5] NIST National Vulnerability Database. CVE-2021-44228. https://nvd.nist.gov/vuln/detail/CVE-2021-44228

Dataset names ATRDF Dataset 4 and VAmPI v6.2 are the names stored in this repository's model metadata. No additional bibliographic record for ATRDF Dataset 4 is present in the repository.
