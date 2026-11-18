# Algorithm 1 Dual-Path Request Handling (with mitigation)

The steps below follow the review gateway filter, the family mitigation catalog, and the mitigation engine. Detection still chooses ALLOW, ALERT, or BLOCK. Mitigation is the action that follows that choice: a hard block that never reaches the demo API, a cookie wipe on cookie injection, a source cooldown after repeated blocks, or a BOLA alert that is forwarded so the demo API can apply JWT and owner checks.

**Algorithm 1** Dual-Path Request Handling

**Input:**  
Request \(r\)  
ATRDF binary and multiclass forests  
BOLA behavioral forest  
Review rule set  
Family mitigation catalog  
Threshold \(\tau = 0.50\)

**Output:**  
Gateway decision \(\delta\)  
Mitigation \(\mu\)  
HTTP response  
Telemetry record

**Algorithm:**  
1: **while** gateway active **do**  
2:     Accept request \(r\)  
3:     Resolve identity \(u\) from verified JWT, else \(u \leftarrow\) `unknown`  
4:     **if** \(r\) matches `/api/books/{id}` **then**  
5:         Build \(x^{\mathrm{B}}\)  
6:         Compute \(P_{\mathrm{BOLA}}\) using (2)  
7:         **if** \(P_{\mathrm{BOLA}} \ge \tau\) **then**  
8:             \(\delta \leftarrow\) ALERT  
9:             **if** \(r\) is a management or mutation call **then**  
10:               \(\mu \leftarrow\) `ALERT + backend authorization`  
11:           **else**  
12:               \(\mu \leftarrow\) `ALERT + public catalog read`  
13:           **end if**  
14:           Forward \(r\) to the demo API  
15:           HTTP response \(\leftarrow\) demo API JWT and owner check  
16:           `backendReached` \(\leftarrow\) true  
17:        **else**  
18:           \(\delta \leftarrow\) ALLOW; \(\mu \leftarrow\) ALLOW  
19:           Forward \(r\) to the demo API  
20:        **end if**  
21:    **else**  
22:        Build \(x^{\mathrm{A}}\)  
23:        Compute \(P_{\mathrm{mal}}\) using (2)  
24:        **if** \(P_{\mathrm{mal}} \ge \tau\) **then**  
25:           \(\hat{y} \leftarrow\) multiclass family  
26:           \(\delta \leftarrow\) BLOCK  
27:           Look up \(\mu\) and techniques \(T\) for \(\hat{y}\) in the family catalog  
28:           **if** source cooldown is exceeded **then**  
29:               \(\mu \leftarrow\) `MITIGATION-RATE-LIMIT`; return HTTP 429  
30:           **else**  
31:               Apply hard block: do not forward \(r\) (`backendReached` \(\leftarrow\) false)  
32:               Apply family controls in \(T\) (no SQL run, no command run, reject path escape, drop JNDI, redact control characters)  
33:               **if** \(\hat{y}\) is Cookie Injection **then**  
34:                   Clear session cookies; return HTTP 401  
35:               **else**  
36:                   Return HTTP 403 with the family block body  
37:               **end if**  
38:           **end if**  
39:        **else if** review rule \(\rho\) matches \(r\) **then**  
40:           \(\delta \leftarrow\) BLOCK; \(\mu \leftarrow \rho\)  
41:           Apply hard block: do not forward \(r\)  
42:           Return the rule response  
43:        **else**  
44:           \(\delta \leftarrow\) ALLOW; \(\mu \leftarrow\) ALLOW  
45:           Forward \(r\) to the demo API  
46:        **end if**  
47:    **end if**  
48:    Write telemetry (\(\delta\), \(\mu\), \(T\), HTTP status, `backendReached`)  
49: **end while**

Family catalog strings used by the gateway:

| Predicted class | Mitigation \(\mu\) | Techniques actually run |
|---|---|---|
| SQL Injection | BLOCK + parameterized query path | hard_block, reject_untrusted_query, no_sql_execution |
| Cookie Injection | BLOCK + session validation | hard_block, invalidate_session_cookie, require_reauthentication |
| Log Forging | BLOCK / ALERT + structured logging | hard_block, redact_control_characters |
| RCE | BLOCK (Execution: NOT PERFORMED) | hard_block, never_execute_command |
| Directory Traversal | BLOCK + path validation | hard_block, reject_path_escape |
| LOG4J | BLOCK / ALERT + safe logging | hard_block, drop_jndi_lookup, redact_control_characters |
| BOLA | ALERT + backend authorization, or ALERT + public catalog read | alert_and_authorize, backend_owner_check, defer_to_backend |
| BENIGN | ALLOW | forward |

# Algorithm 2 ATRDF Family Scoring (with mitigation)

This is the scoring path in the ML service. If the binary forest stays below \(\tau\), the request is BENIGN and mitigation is ALLOW. If it is at or above \(\tau\), the multiclass forest names the family and the catalog attaches \(\mu\) and \(T\). The gateway in Algorithm 1 then applies the hard block.

**Algorithm 2** ATRDF Family Scoring

**Input:**  
\(x^{\mathrm{A}}\) = ATRDF feature vector  
Binary forest, multiclass forest  
Family mitigation catalog  
\(\tau = 0.50\)

**Output:**  
Decision \(\delta\)  
Family label  
Mitigation \(\mu\)  
Techniques \(T\)

**Algorithm:**  
1: Compute \(P_{\mathrm{mal}}\) using (2)  
2: **if** \(P_{\mathrm{mal}} < \tau\) **then**  
3:     \(\delta \leftarrow\) ALLOW; \(\hat{y} \leftarrow\) BENIGN  
4:     \(\mu \leftarrow\) ALLOW; \(T \leftarrow\) \{forward\}  
5:     **return** \(\delta\), \(\hat{y}\), \(\mu\), \(T\)  
6: **end if**  
7: \(\hat{y} \leftarrow\) multiclass prediction on \(x^{\mathrm{A}}\)  
8: \(\delta \leftarrow\) BLOCK  
9: Look up \(\mu\) and \(T\) for \(\hat{y}\) in the family catalog  
10: **return** \(\delta\), \(\hat{y}\), \(\mu\), \(T\)
