## 3 Proposed Model: Dual-Path API Security Gateway (DPASG)

The proposed model evaluates each incoming REST API request before the book-catalog application fully trusts it. The Dual-Path API Security Gateway (DPASG) continuously monitors the request route, the verified identity, the feature vector of the active detector, the probability returned by the Random Forest, and any matching review rule. DPASG improves the allocation of security decisions for incoming requests. An input-manipulation finding can block before the demo API runs. A BOLA finding alerts and still leaves ownership to the application. Every request is handled by one primary detector path, selected by route. The module uses a fixed threshold so that enforcement remains stable. The threshold helps understand when a block or an alert should be raised. DPASG is composed of parameters such as the request \(r\), ATRDF features \(x^{\mathrm{A}}\), BOLA features \(x^{\mathrm{B}}\), malicious probability \(P_{\mathrm{mal}}\), BOLA probability \(P_{\mathrm{BOLA}}\), and threshold \(\tau\).

If the request is not an object-access route, DPASG builds \(x^{\mathrm{A}}\) and queries the ATRDF forests. If \(P_{\mathrm{mal}} \ge \tau\), the request is blocked and is not forwarded. If the model allows the request, review rules are checked. If a rule matches, the request is blocked by the rule. Otherwise the request is forwarded.

If the request targets `/api/books/{id}`, DPASG builds \(x^{\mathrm{B}}\) from the session window and queries the BOLA forest. The binary decisions use the same threshold rule:

\begin{equation}
\hat{d} =
\begin{cases}
1, & P \ge \tau \\
0, & P < \tau
\end{cases}
,\qquad
\tau = 0.50
\end{equation}

where \(P\) denotes \(P_{\mathrm{mal}}\) on the ATRDF path and \(P_{\mathrm{BOLA}}\) on the BOLA path. Each Random Forest with \(T=100\) trees estimates class probability by averaging tree votes:

\begin{equation}
P(x)
=
\frac{1}{T}
\sum_{t=1}^{T}
p_t(c \mid x)
\end{equation}

where \(p_t(c \mid x)\) is the class-\(c\) fraction in the leaf reached by tree \(t\). The ATRDF forest uses maximum depth 16. The BOLA forest uses maximum depth 12. Both use seed 42 and are served with scikit-learn [15], [16]. For policy stability, \(\tau\) is kept at \(0.50\) and is not lowered.

(i) **Incoming Request (\(r\)):** \(r\) represents the HTTP call arriving at the review gateway. Requests may arrive as benign catalog traffic or as attack traffic sent through OWASP ZAP [18]. Object-access routes and other routes use different detectors.

(ii) **Decision Threshold (\(\tau\)):** \(\tau\) defines the capacity of a detector to raise a positive decision. At inference time DPASG compares \(P_{\mathrm{mal}}\) or \(P_{\mathrm{BOLA}}\) with \(\tau\). The value used in this work is \(0.50\).

(iii) **Feature Vectors (\(x^{\mathrm{A}}\), \(x^{\mathrm{B}}\)):** \(x^{\mathrm{A}}\) holds thirteen request statistics and seven structural flags for ATRDF scoring [3]. \(x^{\mathrm{B}}\) holds fourteen behavioral session features for BOLA scoring [10], [11]. Raw user and object identifiers are not used as shortcut predictors in \(x^{\mathrm{B}}\).

**TABLE I**  
PARAMETERS AND DEFINITIONS

| Parameter | Definition |
|---|---|
| \(r\) | Incoming HTTP request |
| \(u\) | Verified JWT identity, or `unknown` |
| \(x^{\mathrm{A}}\) | ATRDF feature vector |
| \(x^{\mathrm{B}}\) | BOLA feature vector |
| \(P_{\mathrm{mal}}\) | Malicious probability from ATRDF binary forest |
| \(P_{\mathrm{BOLA}}\) | BOLA probability from behavioral forest |
| \(\tau\) | Decision threshold, \(0.50\) |
| \(\hat{y}\) | Predicted ATRDF family label |
| \(\delta\) | Gateway decision: ALLOW, ALERT, or BLOCK |
| \(\rho\) | Matched review-rule id, or none |

### 3.1 Process Flow for the Dual-Path Gateway

The proposed system loads the ATRDF and BOLA Random Forest models and starts the review gateway. At the same time, the BOLA session tracker and the review-rule set are made ready.

As the gateway remains operational, the system continuously handles incoming requests. For each request, identity \(u\) is taken from a verified JWT. If the path matches `/api/books/{id}`, the system builds \(x^{\mathrm{B}}\) and scores \(P_{\mathrm{BOLA}}\). Otherwise it builds \(x^{\mathrm{A}}\) and scores \(P_{\mathrm{mal}}\).

On the ATRDF path, if \(P_{\mathrm{mal}} \ge \tau\), the request is blocked before the demo API. Cookie Injection returns HTTP 401. The other supported families return HTTP 403. If \(P_{\mathrm{mal}} < \tau\), review rules are checked. A matched rule blocks the request and is recorded as a rule block. If no rule matches, the request is allowed and forwarded.

On the BOLA path, if \(P_{\mathrm{BOLA}} \ge \tau\), the gateway sets ALERT and forwards the request so the demo API can apply JWT and owner checks. If \(P_{\mathrm{BOLA}} < \tau\), the request is allowed and forwarded. Public book reads may alert and still return HTTP 200 under the review public-catalog policy.

After each decision, telemetry stores the machine-learning decision, any rule id, the gateway decision, HTTP status, and whether the backend was reached. This loop continues while the gateway is active and keeps family blocking separate from authorization alerting.

**Figure 2.** Dual-path request handling flow of the proposed model.

### 3.2 Path Differentiation

The gateway includes path differentiation to meet application-specific needs. Differentiation is provided by categorizing routes and decisions.

ATRDF analysis is used for request-level attack behaviour and early blocking with family labels on supported input attacks [3], [4]. The six supported families are Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, and SQL Injection [17], [20]–[23]. XSS is outside this evaluation scope. When \(P_{\mathrm{mal}} \ge \tau\), the multiclass forest assigns the family label \(\hat{y}\).

BOLA classification using the session score follows (1). Depending on the score and route type, the outcome is ALERT with backend authorization for management or mutation views, ALERT with public catalog read for anonymous public book reads, or ALLOW when the session looks normal [7]–[11].

### 3.3 Handling Algorithm

The Dual-Path Request Handling algorithm starts by resolving identity and selecting the detector from the route. While the gateway is active, features are computed for each request. Object-access requests use the BOLA path: if \(P_{\mathrm{BOLA}} \ge \tau\), the gateway alerts and forwards; otherwise it allows and forwards. Other requests use the ATRDF path: if \(P_{\mathrm{mal}} \ge \tau\), the request is blocked with the predicted family; otherwise review rules are checked. If a rule matches, the request is blocked by the rule; otherwise it is allowed and forwarded. Telemetry is updated after each outcome. This process repeats while the gateway remains active.

### 3.4 Dual-Path Handling Algorithms

Algorithm 1 manages security decisions for API requests using ATRDF family analysis and BOLA session analysis.

#### 3.4.1 DPASG algorithm

The DPASG algorithm depicts gateway decision allocation for incoming requests. The models are loaded according to the system configuration. Initially, DPASG sets \(\tau = 0.50\).

The primary purpose is to manage detection in a dual-path API gateway. The shared services are the ML inference service and the demo API. Identity is verified from the JWT. The objective is to stop dangerous payloads early and to keep object-access suspicion from replacing ownership checks.

**Case 1: Object-access route**

If the path matches `/api/books/{id}`, the algorithm builds the session vector and scores \(P_{\mathrm{BOLA}}\). If \(P_{\mathrm{BOLA}} \ge \tau\), the gateway alerts and forwards. If \(P_{\mathrm{BOLA}} < \tau\), the request is allowed and forwarded.

**Case 2: Non-object route**

If the path is outside the book-object routes, the algorithm builds the ATRDF vector and scores \(P_{\mathrm{mal}}\). If \(P_{\mathrm{mal}} \ge \tau\), the request is blocked with the multiclass family. If \(P_{\mathrm{mal}} < \tau\) and a review rule matches, the request is blocked by the rule. Otherwise the request is allowed and forwarded.

Essentially, this algorithm acts as a dynamic security decision manager, balancing family blocking and authorization alerting in real time.

**Algorithm 1** Dual-Path Request Handling

**Input:**  
Request \(r\)  
ATRDF binary and multiclass forests  
BOLA behavioral forest  
Review rule set  
Threshold \(\tau = 0.50\)

**Output:**  
Gateway decision \(\delta\)  
HTTP response  
Telemetry record

**Algorithm:**  
1: Resolve identity \(u\) from verified JWT, else \(u \leftarrow\) `unknown`  
2: **while** gateway active **do**  
3:     Accept request \(r\)  
4:     **if** \(r\) matches `/api/books/{id}` **then**  
5:         Build \(x^{\mathrm{B}}\)  
6:         Compute \(P_{\mathrm{BOLA}}\) using (2)  
7:         **if** \(P_{\mathrm{BOLA}} \ge \tau\) **then**  
8:             \(\delta \leftarrow\) ALERT; forward \(r\) to demo API  
9:         **else**  
10:            \(\delta \leftarrow\) ALLOW; forward \(r\) to demo API  
11:        **end if**  
12:    **else**  
13:        Build \(x^{\mathrm{A}}\)  
14:        Compute \(P_{\mathrm{mal}}\) using (2)  
15:        **if** \(P_{\mathrm{mal}} \ge \tau\) **then**  
16:            \(\hat{y} \leftarrow\) multiclass family; \(\delta \leftarrow\) BLOCK; return family response  
17:        **else if** review rule \(\rho\) matches \(r\) **then**  
18:            \(\delta \leftarrow\) BLOCK; return rule response  
19:        **else**  
20:            \(\delta \leftarrow\) ALLOW; forward \(r\)  
21:        **end if**  
22:    **end if**  
23:    Write telemetry  
24: **end while**

**Algorithm 2** ATRDF Family Scoring

**Input:**  
\(x^{\mathrm{A}}\) = ATRDF feature vector  
Binary forest, multiclass forest  
\(\tau\) = threshold

**Output:**  
Decision and family label

**Algorithm:**  
1: Compute \(P_{\mathrm{mal}}\) using (2)  
2: **if** \(P_{\mathrm{mal}} < \tau\) **then**  
3:     **return** ALLOW, BENIGN  
4: **end if**  
5: \(\hat{y} \leftarrow\) multiclass prediction on \(x^{\mathrm{A}}\)  
6: **return** BLOCK, \(\hat{y}\)
