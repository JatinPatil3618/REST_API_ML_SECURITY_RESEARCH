# End-to-end verification

Current six-family detector: `research/atrdf_payload_experiment/HELDOUT_SIX_REPORT.md`. The 1.000 development-mask scores in later sections of this log are historical and are not Table VI.

Live checks were run on 11 October 2026 against the frontend on port 5173, the production gateway on port 8080, the ML service on port 8000, and the demo API on port 5001. OWASP ZAP was not run. Models were not retrained, thresholds were not changed, and `REQUEST_ONLY_test.csv` was not opened.

The production profile stayed `gateway.atrdf.profile=production`. Catalog and login decisions used `atrdf_binary_rf_request_only`. Book-id decisions used `bola_rf_behavioral`. The experimental gateway on port 8081 was left running and was not part of these results.

## Gateway process

The gateway that was already listening on port 8080 (PID 612) accepted `GET /api/books/101` and then never answered. Curl reported a timeout with 0 bytes. During the hang the socket stayed `ESTABLISHED` on PID 612, every `http-nio-8080-exec-*` thread was idle in the worker queue, and the poller was blocked in `select`. Those requests produced no telemetry. The same path on a new JVM of the current production-profile jar returned in under a second.

`gateway/target/security-gateway-1.0.0.jar` cannot be launched: `java -jar` reports `no main manifest attribute`. PID 612 was stopped and replaced with the current boot jar, started as:

`java -jar <current production-profile jar> --server.port=8080`

No `--gateway.atrdf.profile` override was passed. The replacement listener is PID 32176. Frontend, ML service, and demo API processes were reused.

## Frontend

`http://localhost:5173/` returned HTTP 200 with title `SecureBook API Lab - Academic REST Research Platform`. The served module sets `GATEWAY_URL` to `http://localhost:8080`. Loading the catalog issued two fetches to `http://localhost:8080/api/books` and showed `Dangerous lookup pattern blocked.`

| Request | Client | Gateway decision | Backend reached |
|---|---|---|---|
| REQ-1014 `GET /api/books` | Block message in the page | BLOCK, LOG4J 0.67, model `atrdf_binary_rf_request_only` | No |
| REQ-1015 `GET /api/books` | Block message in the page | BLOCK, LOG4J 0.67, same model | No |

Both events are `EXP-LIVE` / `CASE-WEB` at 22:30:43Z from `0:0:0:0:0:0:0:1`. They are separate from the scripted catalog request below.

## Scripted gateway matrix

Tokens came from `POST /api/auth/login` on port 8080 for seeded users `user01` and `user02`. Correlation id `EXP-E2E-8080`. A disposable book `111`, titled `E2E disposable probe` and owned by `user01`, was created through the gateway and later deleted by `user01`. Seeded book `101` stayed `Foundations of Network Protocol Security` / `user01`. Seeded book `201` stayed `Applied Machine Learning in Anomaly Detection` / `user02`. After cleanup the demo API reported 10 books and `GET /api/books/111` returned 404.

Telemetry `statusCode` and `backendReached` are stored when the gateway chooses ALLOW or BLOCK, before the demo API response is copied back. The client status below is the HTTP status the caller received. Those two numbers differ when the backend returns its own 201, 403, or 404 after an ALLOW.

| Case | Request | Client result | Gateway telemetry | Backend and data |
|---|---|---|---|---|
| Login user01 | REQ-1001 `POST /api/auth/login` | 200, token subject `user01` | ALLOW, BENIGN 0.92, `atrdf_binary_rf_request_only`, backendReached true, telemetry status 200 | Login succeeded |
| Login user02 | REQ-1002 `POST /api/auth/login` | 200, token subject `user02` | ALLOW, BENIGN 0.92, same model, backendReached true, telemetry status 200 | Login succeeded |
| Catalog | REQ-1003 `GET /api/books` | 200, `total` 10 | ALLOW, BENIGN 0.9177, same model, backendReached true, telemetry status 200 | Read only |
| Health | REQ-1004 `GET /api/health` | 200, service `demo_api` | ALLOW, BENIGN 0.7825, same model, backendReached true, telemetry status 200 | Read only |
| Create disposable book | REQ-1005 `POST /api/books` | 201, id `111`, owner `user01`, title `E2E disposable probe` | ALLOW, BENIGN 0.9377, same model, backendReached true, telemetry status 200 | Book `111` was added |
| Owner management read | REQ-1006 `GET /api/books/111?view=manage` with user01 | 403, body code `BOLA`, message `Access denied. This book belongs to another user.` | BLOCK, BOLA 0.73, `bola_rf_behavioral`, backendReached false, telemetry status 403 | Backend was not called. Book unchanged |
| Other user management read | REQ-1007 `GET /api/books/111?view=manage` with user02 | 403, code `BOLA_AUTHORIZATION_DENIED`, body keys `bookId`, `code`, `error` only | ALLOW, NORMAL 0.55, `bola_rf_behavioral`, backendReached true, telemetry status 200. Telemetry user label `user01` | Backend denied the JWT subject. No title, author, description, rating, date, or owner in the body. Book unchanged |
| Other user update | REQ-1008 `PUT /api/books/111` with user02, title `changed-by-user02` | 403, code `BOLA_PERMISSION_DENIED` | ALLOW, NORMAL 0.56, `bola_rf_behavioral`, backendReached true, telemetry status 200. Telemetry user label `user01` | Backend denied the update. Direct read afterward still showed title `E2E disposable probe` and owner `user01` |
| Other user delete | REQ-1009 `DELETE /api/books/111` with user02 | 403, code `BOLA_PERMISSION_DENIED` | ALLOW, NORMAL 0.59, `bola_rf_behavioral`, backendReached true, telemetry status 200. Telemetry user label `user01` | Backend denied the delete. Book `111` still existed |
| Update without a token | REQ-1010 `PUT /api/books/111` | 403, body code `BOLA`, gateway error body | BLOCK, BOLA 0.73, `bola_rf_behavioral`, backendReached false, telemetry status 403, user `anonymous` | Backend was not called, so its 401 was not returned on this request. Book unchanged |
| Public read after the denied writes | REQ-1011 `GET /api/books/111` | 200, title `E2E disposable probe`, owner `user01` | ALLOW, NORMAL 0.55, `bola_rf_behavioral`, backendReached true, telemetry status 200 | Confirms the denied writes did not change the row |
| Owner delete | REQ-1012 `DELETE /api/books/111` with user01 | 200, `Book deleted successfully.` | ALLOW, NORMAL 0.60, `bola_rf_behavioral`, backendReached true, telemetry status 200 | Disposable row removed |
| Read after delete | REQ-1013 `GET /api/books/111` | 404, `Book not found.` | ALLOW, NORMAL 0.56, `bola_rf_behavioral`, backendReached true, telemetry status 200 | Direct demo API read was also 404 |

REQ-1007, REQ-1008, and REQ-1009 are the authorization evidence. The gateway ALLOW did not bypass the demo API. The backend applied the JWT subject and the owner check, and the disposable row stayed unchanged until the owner delete.

## Fixes

No application source, model, threshold, or `application.properties` change was made. The only change was replacing PID 612 after the book-id hang was shown on a thread dump and by missing telemetry. The replacement uses the production profile on port 8080.

The disposable book was deleted. Seeded books were not edited.

`demo_api/test/book-management-access.test.js` was not rerun. `server.js` was not modified in this pass. The earlier run of that file, 7 passing, remains the regression result for the backend JWT and management-view checks.

## What is implemented

- Login issues a JWT. Protected create, update, and delete routes on the demo API require that JWT.
- `PUT` and `DELETE /api/books/:id` deny a different owner in the demo API. This was observed live on REQ-1008 and REQ-1009 after the gateway had allowed the request.
- `GET /api/books/:id?view=manage` denies a different owner in the demo API and omits the private book fields. This was observed live on REQ-1007 after the gateway had allowed the request.
- Ordinary `GET /api/books` is public. REQ-1003 returned the catalog.
- The demo API has HTML escaping for comment text and strips line breaks in security log messages. Those paths were not called in this matrix.
- The gateway runs ATRDF and BOLA models and can block before the backend. That is detection. It is not the ownership check.

## What remains unverified or blocked

- The owner's permitted management read did not reach the backend. REQ-1006 was blocked by `bola_rf_behavioral` at 0.73. The model decision is not an ownership decision, and the threshold was not changed.
- The tokenless update did not reach the backend. REQ-1010 was blocked by the same model at 0.73. The demo API's 401 for a missing token was not produced on this gateway request.
- The browser catalog does not load. REQ-1014 and REQ-1015 were blocked as LOG4J at 0.67. A scripted catalog GET with a different header set was allowed on REQ-1003.
- Gateway telemetry labels any Bearer token as `user01`. The demo API does not use that label; it uses the JWT subject. The label is still wrong for user02 on REQ-1007, REQ-1008, and REQ-1009.
- Telemetry `statusCode` 200 with `backendReached` true does not mean the client received 200. REQ-1007, REQ-1008, REQ-1009, and REQ-1013 show that.
- `gateway/target/security-gateway-1.0.0.jar` has no main manifest, so the usual launch path cannot start the gateway that is now serving port 8080.
- Experimental JNDI scoring was not repeated. The recorded miss for that profile stays outside this production run.
- ZAP was not run. Payload classes other than the BOLA model scores above were not exercised.

## Continuation

Listeners were checked again without stopping any process. Ports 8000 and 5001 were not rechecked.

| Port | PID | Health |
|---|---|---|
| 5173 frontend | 31608, Vite | `GET /` HTTP 200 |
| 5174 dashboard | 26488, Vite | `GET /` HTTP 200 |
| 8080 production gateway | 32176, `java -jar` the current production-profile jar `--server.port=8080` | `GET /health` HTTP 200, `status` PASS, `port` 8080 |
| 8081 experimental gateway | 24316, same jar with `--gateway.atrdf.profile=experimental-jndi` | `GET /health` HTTP 200, `status` PASS. The JSON `port` field still says 8080 |

The catalog check used the open frontend at `http://localhost:5173/`. Reset runs `fetchBooks` in `frontend/src/App.jsx`, which sends `GET http://localhost:8080/api/books` with the header `X-Authenticated-User: user01` and `Authorization: Bearer dummy-token-user01`. That bearer value is not a JWT from `POST /api/auth/login`, so the telemetry user label is not authentication proof.

The new event is REQ-1016 at 22:41:28Z, source `0:0:0:0:0:0:0:1`, experiment `EXP-LIVE`, test case `CASE-WEB`. It is distinct from REQ-1014 and REQ-1015. The page showed `Dangerous lookup pattern blocked.` The resource URL was `http://localhost:8080/api/books`.

| Field | REQ-1016 |
|---|---|
| HTTP result | 403, backend not reached |
| Model | `atrdf_binary_rf_request_only` |
| Prediction | LOG4J, multiclass confidence 0.67. Probabilities: LOG4J 0.67, Cookie Injection 0.28, XSS 0.05, other classes 0.0 |
| Policy | BLOCK |
| Top features | `path_length`, `url_special_count`, `path_segment_count`, `url_entropy` |

No source, threshold, model, or gateway configuration change was made. The block is the production model's score for this browser request. The BOLA regression cases were not sent through the gateway.

## Same browser catalog request on both profiles

The comparison was sent from the open page at `http://localhost:5173/`, so the browser supplied its own headers. Each call also sent the frontend's `X-Authenticated-User: user01` and `Authorization: Bearer dummy-token-user01`. That bearer value is not a login JWT. Correlation headers `X-Experiment-Id: EXP-BROWSER-COMPARE` and a distinct `X-Test-Case-Id` were added. The gateway excludes those correlation headers from the feature vector. The URLs were `http://127.0.0.1:8080/api/books` and `http://127.0.0.1:8081/api/books`.

| | Production REQ-1017 | Experimental REQ-1010 |
|---|---|---|
| Time | 22:44:58.226Z | 22:44:58.643Z |
| Profile evidence | model `atrdf_binary_rf_request_only` | model `candidate_binary_rf_jndi_augmented` |
| HTTP status | 403 | 200 |
| Decision | BLOCK | ALLOW |
| Probabilities stored on the event | Multiclass: LOG4J 1.0, all other classes 0.0. The binary pair is not in this event. | Binary: BENIGN 0.82, MALICIOUS 0.18 |
| Backend reached | No | Yes |
| Body | `Dangerous lookup pattern blocked.`, code `LOG4J` | 10 books, first title `Foundations of Network Protocol Security` |

The production gateway copies multiclass probabilities into telemetry after the binary stage classifies a request as malicious, so REQ-1017 does not retain the binary probabilities. The experimental event is the binary score. Thresholds and models were not changed.

## Local review frontend

The experimental gateway allowed the browser catalog request and the response contained the live catalog. `frontend/src/App.jsx` and `frontend/src/services/api.js` now use `import.meta.env.VITE_GATEWAY_URL`, and the code default remains `http://localhost:8080`. `frontend/.env.local` sets `VITE_GATEWAY_URL=http://127.0.0.1:8081` for this review only. `.env.local` is listed in `.gitignore`. Gateway configuration was not changed. The Vite process was restarted so it would read the new variable; the gateways on 8080 (PID 32176) and 8081 (PID 24316) were left running. The frontend listener is now PID 26300.

Reloading `http://localhost:5173/` issued two browser requests to `http://127.0.0.1:8081/api/books`. The page history shows both, and they match the experimental gateway:

| Request | Page result | Telemetry |
|---|---|---|
| REQ-1017, 22:47:36.661Z | HTTP 200, ALLOW, `Loaded catalog` | ALLOW, BENIGN 0.82 / MALICIOUS 0.18, `candidate_binary_rf_jndi_augmented`, backend reached, telemetry status 200, `EXP-LIVE` / `CASE-WEB` |
| REQ-1018, 22:47:36.719Z | HTTP 200, ALLOW, `Loaded catalog` | Same model and probabilities, backend reached |

The rendered catalog includes `Foundations of Network Protocol Security` by Dr. Evelyn Carter and `Applied Machine Learning in Anomaly Detection` by Dr. Rajiv Menon. Those titles came from the demo API response, not from a local sample list. The page subtitle still says port 8080; the network requests went to port 8081.

## Review connection recheck

`frontend/.env.local` is the single line `VITE_GATEWAY_URL=http://127.0.0.1:8081` followed by a newline. `git check-ignore` matches it through `.gitignore` rule `.env.local`. `frontend/src/App.jsx` sets `GATEWAY_URL` from `import.meta.env.VITE_GATEWAY_URL` and falls back to `http://localhost:8080`. `frontend/src/services/api.js` uses the same expression for `baseURL`. The running catalog is `frontend/src/main.jsx`, which renders `App.jsx` and does not import the dashboard. The dashboard was not edited.

Only the Vite process on port 5173 was restarted. It now listens as PID 23736. Production gateway PID 32176 remains on port 8080, and experimental gateway PID 24316 remains on port 8081. The served `App.jsx` module contains `"VITE_GATEWAY_URL": "http://127.0.0.1:8081"`.

Reloading `http://localhost:5173/` made the browser request `http://127.0.0.1:8081/api/books` twice. The page history and the experimental gateway agree:

| Request | Browser | Experimental telemetry |
|---|---|---|
| REQ-1024, 22:52:56.905Z | HTTP 200, ALLOW, `Loaded catalog` | ALLOW, BENIGN 0.82 / MALICIOUS 0.18, `candidate_binary_rf_jndi_augmented`, `backendReached` true, status 200 |
| REQ-1025, 22:52:57.001Z | HTTP 200, ALLOW, `Loaded catalog` | Same model, probabilities, and `backendReached` true |

The page rendered `Foundations of Network Protocol Security` by Dr. Evelyn Carter. This experimental allow is a local review path. It does not make the experimental model the production deployment.

## BOLA checks through the review gateway

Tokens came from `POST /api/auth/login` on port 8081. The login responses named subjects `user01` (REQ-1026) and `user02` (REQ-1027). Both were HTTP 200, ALLOW, BENIGN 0.94, model `candidate_binary_rf_jndi_augmented`, `backendReached` true. `X-Authenticated-User` was not sent. A disposable book `111`, title `BOLA review probe`, owner `user01`, was created through the same gateway (REQ-1028, client HTTP 201). Seeded books were not edited. Book `111` was deleted by `user01` after the checks (REQ-1034, client HTTP 200). A direct demo API read then returned 404. Books `101` and `201` still had their original titles and owners.

The management route is `GET /api/books/:id?view=manage`. Updates are `PUT /api/books/:id`. Deletes are `DELETE /api/books/:id`. Experiment id `EXP-BOLA-8081`. Telemetry `statusCode` 200 on an ALLOW is stored before the demo API response is copied back, so the client status is listed separately. Gateway telemetry still labels any Bearer token as `user01`; the backend JWT subject is the identity that matters.

| Case | Client | Gateway telemetry | What this shows |
|---|---|---|---|
| REQ-1029 owner `view=manage` | 403, code `BOLA`, decision BLOCK | BLOCK, BOLA 0.73 / NORMAL 0.27, `bola_rf_behavioral`, `backendReached` false | Gateway block. The backend owner allow was not exercised. |
| REQ-1030 user02 `view=manage` | 403, code `BOLA_AUTHORIZATION_DENIED`, body keys `error`, `code`, `bookId` | ALLOW, NORMAL 0.55 / BOLA 0.45, `backendReached` true, telemetry status 200 | Backend denial after a gateway allow. No title, description, or owner in the body. |
| REQ-1031 `view=manage` with no token | 403, code `BOLA`, decision BLOCK | BLOCK, BOLA 1.0 / NORMAL 0.0, user `anonymous`, `backendReached` false | Gateway block. The backend 401 was not returned. |
| REQ-1032 user02 `PUT` title `changed-by-user02` | 403, code `BOLA_PERMISSION_DENIED`, `requesting_user` `user02`, `expected_owner` `user01` | ALLOW, NORMAL 0.56 / BOLA 0.44, `backendReached` true, telemetry status 200 | Backend denial after a gateway allow. Direct read afterward still showed title `BOLA review probe` and owner `user01`. |
| REQ-1033 user02 `DELETE` | 403, code `BOLA_PERMISSION_DENIED`, `requesting_user` `user02` | ALLOW, NORMAL 0.59 / BOLA 0.41, `backendReached` true, telemetry status 200 | Backend denial after a gateway allow. Book `111` still existed until the owner delete. |

Passed: user02 could not read the management view, update the book, or delete it. Those three denials came from the demo API after the gateway had allowed the request, and the disposable row did not change. Failed: the owner's own management read and the tokenless management read were blocked by `bola_rf_behavioral` before the backend, so those two backend outcomes were not shown. No unauthorized write succeeded, and no backend code was changed. The BOLA model and its threshold were not changed.

## BOLA alert forwarding on the review gateway

The review gateway was rebuilt from the current gateway source. `mvn package` completed and its tests passed. The new jar was started only on port 8081 as PID 22176:

`java -jar <review jar> --server.port=8081 --gateway.atrdf.profile=experimental-jndi`

Production port 8080 is still PID 32176, started earlier with `--server.port=8080` and no profile override. Its process was not restarted. Thresholds, models, and `application.properties` were not changed.

For a book management view (`view=manage` or `access=edit`) and for a book mutation, a `bola_rf_behavioral` BLOCK no longer ends the request. The gateway keeps the prediction, records the decision as `ALERT` with mitigation `ALERT + backend authorization`, and forwards the original request to the demo API. The client receives the demo API status and body. An ATRDF block is still a gateway block. `X-Authenticated-User` is still not treated as identity by the demo API.

Tokens came from `POST /api/auth/login` on port 8081. REQ-1012 named subject `user01` and REQ-1013 named subject `user02`. Both were HTTP 200, ALLOW, BENIGN 0.94, model `candidate_binary_rf_jndi_augmented`, `backendReached` true. Experiment id `EXP-BOLA-DEFER-8081`. Disposable book `111`, title `BOLA policy probe`, owner `user01`, was created by REQ-1014 (client HTTP 201) and deleted by `user01` in REQ-1021 (client HTTP 200). A direct demo API read then returned 404, and the direct catalog total was 10. Books `101` and `201` still had their original titles and owners. Gateway telemetry still labels any Bearer token as `user01`; `requesting_user` on the backend denial is the JWT subject. The telemetry `endpoint` field stores the path without the query string. The management requests below were sent with `?view=manage`.

| Case | Client | Gateway telemetry | Result |
|---|---|---|---|
| REQ-1015 owner `GET /api/books/111?view=manage` | 200, id `111`, title `BOLA policy probe`, owner `user01`. Header `X-Security-Decision: ALERT` | ALERT, BOLA 0.73 / NORMAL 0.27, `bola_rf_behavioral`, mitigation `ALERT + backend authorization`, `backendReached` true, status 200 | Pass. The owner read reached the backend. |
| REQ-1016 user02 same management read | 403, code `BOLA_AUTHORIZATION_DENIED`, keys `error`, `code`, `bookId` | ALLOW, NORMAL 0.55 / BOLA 0.45, `backendReached` true, status 403 | Pass. Backend denial. No title, author, description, owner, rating, or date. |
| REQ-1017 same management read, no token | 401, body `Authentication required. Please log in.` Header `X-Security-Decision: ALERT` | ALERT, BOLA 0.73 / NORMAL 0.27, same model, mitigation `ALERT + backend authorization`, `backendReached` true, status 401 | Pass. Backend authentication denial. No book fields. |
| REQ-1018 user02 `PUT` title `changed-by-user02` | 403, code `BOLA_PERMISSION_DENIED`, `requesting_user` `user02`, `expected_owner` `user01` | ALLOW, NORMAL 0.56 / BOLA 0.44, `backendReached` true, status 403 | Pass. Direct read afterward still showed title `BOLA policy probe` and owner `user01`. |
| REQ-1019 user02 `DELETE` | 403, code `BOLA_PERMISSION_DENIED`, `requesting_user` `user02`, `expected_owner` `user01` | ALLOW, NORMAL 0.59 / BOLA 0.41, `backendReached` true, status 403 | Pass. The book still existed until the owner delete. |

REQ-1020 `GET /api/books` returned HTTP 200 with `total` 11 while book `111` still existed. Telemetry: ALLOW, BENIGN 0.99 / MALICIOUS 0.01, `candidate_binary_rf_jndi_augmented`, `backendReached` true, status 200. Pass.

The representative input-manipulation request was the existing lab case `SQLI_001`, sent to this same review process before the disposable book existed. REQ-1010 `GET /api/books` with that search, experiment `EXP-BOLA-POLICY-8081`, returned HTTP 200 and `total` 0. Telemetry at 23:08:09.097Z: ALLOW, BENIGN 0.556 / MALICIOUS 0.444, `candidate_binary_rf_jndi_augmented`, mitigation `ALLOW`, `backendReached` true, status 200. The score stayed below the unchanged 0.50 malicious threshold, so the request was forwarded. It was not converted into a BOLA authorization alert. This run did not produce an ATRDF BLOCK, so the live hard-block response was not observed. The decision engine still treats an ATRDF BLOCK as a gateway block, and that behavior was covered by the gateway tests in this build.

Two other existing lab requests on this process also stayed under that threshold. REQ-1023, the cookie-header catalog request, was ALLOW, BENIGN 0.71 / MALICIOUS 0.29, HTTP 200, `backendReached` true. REQ-1022, the RCE search, was ALLOW, BENIGN 0.536 / MALICIOUS 0.464, and the client then received HTTP 502 from the gateway forwarder because the query string contains a character that `URI.create` rejects. That 502 is not a demo API response and not an ATRDF block. The traversal lab URL returned HTTP 400 from Tomcat with no request id, so it never reached the model.

Passed: owner management read, cross-owner management read, missing-token management read, cross-owner update, cross-owner delete, and the benign catalog. The SQLI lab request followed the existing allow-below-threshold rule. No remaining blocker in these checks. This review-gateway alert forward does not make the experimental model the production deployment.

## Query forwarding for REQ-1022

REQ-1022 did not reach the demo API. The review gateway caught `URI.create` rejecting the raw `|` in the query and wrote the HTTP 502 itself: `Demo API backend unavailable: Illegal character in query at index 63`. That exception is thrown before `restTemplate.exchange`, so no HTTP call was made. `GET /api/books` on the demo API is not written to the security log, and there is no backend record of this request. `backendReached` was true only because the ML decision was ALLOW. The model score stayed BENIGN 0.536 / MALICIOUS 0.464. That was not a detection.

The catalog search contract is a literal substring over title, author, description, and category. It does not run the search text. The review gateway now rebuilds the query from the parsed parameters and percent-encodes it before forwarding. A query that still cannot be encoded returns HTTP 400 `INVALID_QUERY` instead of a 502. `backendReached` is set true only after the demo API returns an HTTP status. Thresholds and models were not changed. Production port 8080 is still PID 32176. The rebuilt review gateway is PID 32032 on port 8081 with `--gateway.atrdf.profile=experimental-jndi`.

Both checks used experiment `EXP-QUERY-8081` on that new process. These request IDs start again at REQ-1001 and are not the earlier production events.

| Request | Client | Telemetry | Result |
|---|---|---|---|
| REQ-1001 `GET /api/books`, 23:18:27.661Z | HTTP 200, `total` 10, first book `101` `Foundations of Network Protocol Security` / `user01` | ALLOW, BENIGN 0.99 / MALICIOUS 0.01, `candidate_binary_rf_jndi_augmented`, `backendReached` true, status 200 | Pass. Live catalog body from the demo API. |
| REQ-1002 same search string as REQ-1022, 23:18:27.792Z | HTTP 200, catalog keys `authenticated_user`, `books`, `total`, `total` 0 | ALLOW, BENIGN 0.536 / MALICIOUS 0.464, same model, mitigation `ALLOW`, `backendReached` true, status 200 | Pass. The literal search was forwarded and matched no book. The model still classified it as benign. No command was run. |

The gateway package tests passed, including the check that this search value is forwarded with `%7C` and without a raw `|`.

## Query-encoding verification

`mvn -Dtest=MlUnavailableGatewayTest,DecisionEngineTest test` finished with exit code 0.

```
Tests run: 5, Failures: 0, Errors: 0, Skipped: 0 -- DecisionEngineTest
Tests run: 4, Failures: 0, Errors: 0, Skipped: 0 -- MlUnavailableGatewayTest
Tests run: 9, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

`MlUnavailableGatewayTest` includes `searchQueryEncodesReservedCharactersBeforeForwarding`. The packaged jar was copied to a separate temporary directory and started only on port 8081 as PID 29916 with `--gateway.atrdf.profile=experimental-jndi`. Production port 8080 is still PID 32176, using the same jar and `--server.port=8080` with no profile override.

Experiment `EXP-QUERY-VERIFY-8081` is on this new process, so REQ-1001 and REQ-1002 here are not the earlier events with those IDs. The search was `GET /api/books?search=protocol&ref=a+b;c`. The reserved characters are `&`, `+`, and `;`. The value was not executed.

| Request | Client | Telemetry | Backend |
|---|---|---|---|
| REQ-1001 `GET /api/books`, 23:24:29.107Z | HTTP 200, `total` 10, keys `authenticated_user`, `books`, `total` | ALLOW, BENIGN 0.99 / MALICIOUS 0.01, `candidate_binary_rf_jndi_augmented`, `backendReached` true, status 200 | Pass. The body is the live catalog, including `Foundations of Network Protocol Security`. |
| REQ-1002 reserved-character search, 23:24:29.237Z | HTTP 200, `total` 1, title `Foundations of Network Protocol Security` | ALLOW, BENIGN 0.97 / MALICIOUS 0.03, same model, mitigation `ALLOW`, `backendReached` true, status 200 | Pass. The demo API applied the literal `protocol` filter and ignored `ref`. |

Both `backendReached` values match a demo API catalog response. No threshold or model change was made.

## BOLA authorization after the alert forward

The earlier owner management read, REQ-1029 on the previous review process, was HTTP 403 code `BOLA` with `backendReached` false. `bola_rf_behavioral` scored BOLA 0.73, and `DecisionEngine` turns that family into action `BLOCK`. The filter returned that block immediately, so the demo API never applied the owner check. The same score blocked the tokenless management read before the backend 401.

A BOLA `BLOCK` on a book management view (`view=manage` or `access=edit`) or a book mutation is now recorded as `ALERT` with mitigation `ALERT + backend authorization`, and the request is forwarded. The HTTP status and body come from the demo API. An ATRDF `BLOCK` is still returned by the gateway. The demo API still verifies the JWT and compares `user.username` with `book.owner`. It does not accept `X-Authenticated-User`. Thresholds were not changed.

The current source was packaged and started only on port 8081 as PID 3336 with `--gateway.atrdf.profile=experimental-jndi`. Production port 8080 is still PID 32176, with `--server.port=8080` and no profile override. Experiment `EXP-BOLA-FINAL-8081` is on this new process, so these request IDs are not the earlier ones. Login responses named `user01` (REQ-1001) and `user02` (REQ-1002). Disposable book `111`, title `BOLA final probe`, owner `user01`, was created by REQ-1003 and deleted by `user01` in REQ-1010. A direct demo API read then returned 404. Books `101` and `201` kept their original titles and owners. Gateway telemetry still labels any Bearer token as `user01`; `requesting_user` is the JWT subject.

| Case | Client | Telemetry | What decided the result |
|---|---|---|---|
| REQ-1004 owner `GET /api/books/111?view=manage`, 23:29:20.066Z | HTTP 200, id `111`, title `BOLA final probe`, owner `user01`. Header `X-Security-Decision: ALERT` | ALERT, BOLA 0.73 / NORMAL 0.27, `bola_rf_behavioral`, mitigation `ALERT + backend authorization`, `backendReached` true, status 200 | Pass. The 0.73 score is an alert. The HTTP 200 is the backend owner allow. |
| REQ-1005 user02 same management read, 23:29:20.156Z | HTTP 403, code `BOLA_AUTHORIZATION_DENIED`, keys `error`, `code`, `bookId` | ALLOW, NORMAL 0.55 / BOLA 0.45, `backendReached` true, status 403 | Pass. The model allowed it. The backend denied the other owner. No title, author, description, rating, date, or owner. |
| REQ-1006 same management read, no token, 23:29:20.247Z | HTTP 401, `Authentication required. Please log in.` Header `X-Security-Decision: ALERT` | ALERT, BOLA 0.73 / NORMAL 0.27, mitigation `ALERT + backend authorization`, `backendReached` true, status 401 | Pass. The score is an alert. The HTTP 401 is the backend authentication denial. No book fields. |
| REQ-1007 user02 `PUT` title `changed-by-user02`, 23:29:20.348Z | HTTP 403, code `BOLA_PERMISSION_DENIED`, `requesting_user` `user02`, `expected_owner` `user01` | ALLOW, NORMAL 0.56 / BOLA 0.44, `backendReached` true, status 403 | Pass. Backend denial. Direct read afterward still showed title `BOLA final probe` and owner `user01`. |
| REQ-1008 user02 `DELETE`, 23:29:20.425Z | HTTP 403, code `BOLA_PERMISSION_DENIED`, `requesting_user` `user02`, `expected_owner` `user01` | ALLOW, NORMAL 0.59 / BOLA 0.41, `backendReached` true, status 403 | Pass. Backend denial. The book remained until the owner delete. |
| REQ-1009 `GET /api/books`, 23:29:20.482Z | HTTP 200, `total` 11 while book `111` still existed | ALLOW, BENIGN 0.99 / MALICIOUS 0.01, `candidate_binary_rf_jndi_augmented`, `backendReached` true, status 200 | Pass. Normal catalog reached the backend. |

Passed: owner management read, other-user management read, missing-token management read, cross-owner update, cross-owner delete, and the normal catalog. None failed. No remaining blocker in these checks. The experimental profile remains a review path.

## Verified telemetry identity

The review gateway no longer labels every Bearer token as `user01`. It asks the demo API to verify the token and records `unknown` when that verification does not return a username. Production port 8080 was not restarted. The new review process is PID 24388 on port 8081. Experiment `EXP-BOLA-IDENTITY-8081`. These IDs are not the earlier events with the same numbers.

| Request | HTTP and identity | What decided it |
|---|---|---|
| REQ-1004 owner `view=manage`, 03:17:52.193Z | 200, telemetry `user01`, ALERT BOLA 0.73, `backendReached` true | Pass. Backend owner allow. |
| REQ-1005 user02 `view=manage`, 03:17:52.276Z | 403 `BOLA_AUTHORIZATION_DENIED`, telemetry `user02`, ALERT BOLA 0.73, `backendReached` true | Pass. Backend denial. No private fields. |
| REQ-1006 no token, 03:17:52.394Z | 401, telemetry `unknown`, ALERT BOLA 0.73, `backendReached` true | Pass. Backend authentication denial. |
| REQ-1007 invalid token, 03:17:52.495Z | 403 session invalid, telemetry `unknown`, ALLOW NORMAL 0.55, `backendReached` true | Pass. Backend rejected the token. |
| REQ-1008 `X-Authenticated-User: user01` only, 03:17:52.582Z | 401, telemetry `unknown`, ALLOW NORMAL 0.56, `backendReached` true | Pass. The header was ignored. |
| REQ-1009 user02 update, 03:17:52.669Z | 403 `BOLA_PERMISSION_DENIED`, `requesting_user` `user02`, telemetry `user02`, `backendReached` true | Pass. Direct read afterward was still title `BOLA identity probe`, owner `user01`. |
| REQ-1010 user02 delete, 03:17:52.766Z | 403 `BOLA_PERMISSION_DENIED`, telemetry `user02`, `backendReached` true | Pass. The book remained until REQ-1012. |
| REQ-1011 catalog, 03:17:52.854Z | 200, `total` 11, telemetry `unknown`, ALLOW BENIGN 0.99, `backendReached` true | Pass. |

Book `111` was removed by owner REQ-1012. Books `101` and `201` were unchanged. Gateway tests: 14 run, 0 failures, exit code 0. The validation replay and its live-feature limit are in `docs/BOLA_MITIGATION_VERIFICATION.md`.

## ATRDF review inspection

The review gateway on port 8081 was rebuilt from the current source and started as PID 25768 with `--gateway.atrdf.profile=experimental-jndi`. Production port 8080 is still PID 32176 and was not restarted. The 0.50 threshold and the model files were not changed. `REQUEST_ONLY_test.csv` was not opened.

The experimental marker now reads the path, query, and body as well as non-metadata headers. Percent-decoding is applied more than once. Test-correlation headers are still ignored. The marker remains a model input. On this profile only, `ReviewRequestGuard` can block after the model returns ALLOW. The ML class is not replaced by the rule. Telemetry stores `mlDecision`, `mlPredictedClass`, `binaryProbabilities`, `multiclassLabel`, `ruleId`, `ruleOutcome`, `decision`, and `backendReached` separately. The production profile records `ruleOutcome` `NOT_APPLICABLE` and does not run the rules. The review profile also lets an encoded slash reach the filter, then refuses a traversal path instead of forwarding it.

Focused tests, exit code 0:

```
Tests run: 30, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

That run included `ReviewRequestGuardTest`, `ReviewInspectionGatewayTest`, `JndiLookupMarkerTest`, `MlUnavailableGatewayTest`, `VerifiedIdentityTest`, `DecisionEngineTest`, and `FeatureExtractorTest`. `mvn -DskipTests package` then completed with BUILD SUCCESS.

Experiment `EXP-ATRDF-8081` is on PID 25768. These request IDs start at REQ-1003. Multiclass was not run on any of them because the binary score stayed under 0.50. The blocks below are rules, not ML detections. Comment count on book `101` was 1 before these posts and 1 after, read directly from the demo API.

| Case | Request | ML | Rule | Final | Backend |
|---|---|---|---|---|---|
| SQLI_001 | REQ-1003 `GET /api/books` with the saved search | ALLOW, BENIGN 0.556 / MALICIOUS 0.444 | `ATRDF-SQL-STRUCTURE` MATCH | HTTP 403 BLOCK | Not reached. The demo API search is a literal substring and has no SQL parser. The rule stopped the string before that lookup. |
| XSS_001 | REQ-1004 `POST /api/comments/book/101` | ALLOW, BENIGN 1.0 / MALICIOUS 0.0 | `ATRDF-MARKUP-SCRIPT` MATCH | HTTP 403 BLOCK | Not reached. The comment count stayed 1, so the markup was not stored. The page renders comment text as text. |
| COOKIE_001 | REQ-1005 `GET /api/books` with the saved cookie | ALLOW, BENIGN 0.71 / MALICIOUS 0.29 | `ATRDF-COOKIE-AUTHORITY` MATCH | HTTP 403 BLOCK | Not reached. The demo API does not grant a role from a cookie. The cookie was not forwarded. |
| LOGFORGE_001 | REQ-1006 `POST /api/comments/book/101` | ALLOW, BENIGN 1.0 / MALICIOUS 0.0 | `ATRDF-LOG-LINE` MATCH | HTTP 403 BLOCK | Not reached. The comment count stayed 1. The demo API logger already strips CR and LF from log messages, and this comment was not logged. |
| RCE_001 | REQ-1007 `GET /api/books` with the saved search | ALLOW, BENIGN 0.536 / MALICIOUS 0.464 | `ATRDF-COMMAND-CHAIN` MATCH | HTTP 403 BLOCK | Not reached. No command was run. The search contract is a literal substring. |
| TRAVERSAL_001 | REQ-1008 `GET /api/books/..%2F..%2F..%2Fetc%2Fpasswd` | ALLOW, BENIGN 0.69 / MALICIOUS 0.31 | `ATRDF-PATH-TRAVERSAL` MATCH | HTTP 403 BLOCK | Not reached. This is a gateway rule with a request id, not the earlier container HTTP 400. The demo API has no file read on this route. |
| LOG4J_001 | REQ-1009 `POST /api/comments/book/101` | ALLOW, BENIGN 0.58 / MALICIOUS 0.42 | `ATRDF-JNDI-LOOKUP` MATCH | HTTP 403 BLOCK | Not reached. The demo API is not a Java Log4j process and made no outbound lookup. The comment count stayed 1. |

REQ-1010 `GET /api/books` returned HTTP 200, `total` 10, ALLOW, BENIGN 0.99 / MALICIOUS 0.01, rule `NONE`, `backendReached` true. REQ-1011 `GET /api/books?search=protocol&ref=a+b;c` returned HTTP 200, `total` 1, ALLOW, BENIGN 0.97 / MALICIOUS 0.03, rule `NONE`, `backendReached` true. The semicolon in that search was not treated as a command.

The 35-case suite was sent live to this process as `EXP-ATRDF-SUITE-8081`, using the same routes, queries, and header profiles as `DeploymentShiftAtrdfSuiteTest`. All 35 returned HTTP 200, decision ALLOW, rule `NONE`, and `backendReached` true. Legitimate requests blocked: 0 of 35.

The open catalog at `http://localhost:5173/` rendered `Foundations of Network Protocol Security` by Dr. Evelyn Carter and the other seeded titles. The browser sent two catalog requests to port 8081: REQ-1047 and REQ-1048, both ALLOW, BENIGN 0.82 / MALICIOUS 0.18, rule `NONE`, `backendReached` true, telemetry status 304. Neither was blocked.

The model still classifies all seven lab requests as benign. The review rules are the blocks. A newline that is not paired with a bracketed log severity is not a log-line match. The production gateway does not apply these rules.

## Payload-feature candidate

A separate 20-feature candidate was trained for the review gateway. Production port 8080 is still PID 32176 and its model files were not replaced. The held-out file `REQUEST_ONLY_test.csv` was not opened. The seven lab requests were not added to training. The threshold stayed 0.50.

The candidate is `research/atrdf_payload_experiment/candidate_binary_rf_payload.joblib` and `candidate_multiclass_rf_payload.joblib`, trained with scikit-learn 1.2.2 in `.venv-repair`. The forest is 100 trees, depth 16, seed 42. The training partition is the existing 124,241 rows. The validation mask is the seed-42 15 percent draw and contains 21,972 rows.

The first 13 features are unchanged. Seven flags are appended, in this order: `sql_structure`, `markup_script`, `path_traversal`, `command_chain`, `cookie_signal`, `log_control`, `jndi_lookup`. Each flag is computed from the path, query, body, user agent, and non-metadata header values. The text is kept raw, percent-decoded once, percent-decoded again, and form-decoded. Matching is case-insensitive. Labels, test-case ids, and expected decisions are not inputs.

| Feature | 1 when |
|---|---|
| `sql_structure` | A quote is followed by `or`, or the text contains `union select`, or it contains both `select` and `--` |
| `markup_script` | The text contains a script tag, `alert(`, or an `onerror`, `onload`, `onclick`, or `onmouseover` handler |
| `path_traversal` | After decoding, the text contains `../` or `..\` |
| `command_chain` | `;`, `|`, `&&`, or a backtick is followed by `cat`, `nc`, `bash`, `sh`, `cmd`, `powershell`, `wget`, or `curl` |
| `cookie_signal` | The text contains `cookie`, or a cookie name is `admin` or `role` |
| `log_control` | The text contains `%0a`, `%0d`, a raw CR or LF, or the characters `\r` or `\n` |
| `jndi_lookup` | The text contains `${jndi:` with optional internal whitespace |

On the training partition, benign rows set none of these flags. SQL Injection sets `sql_structure` on all 6,339 rows. Directory Traversal sets `path_traversal` on all 3,151 rows. Cookie Injection sets `cookie_signal` on all 6,194 rows. Log Forging sets `log_control` on all 3,230 rows. XSS sets `markup_script` on 3,203 of 6,414 rows. RCE sets `markup_script` on 1,600 of 3,155 rows. `command_chain` is 0 on every training row. `jndi_lookup` is 0 on every training row, including all 2,986 LOG4J rows. Their binary importances are 0. Multiclass importances for those two flags are also 0. The forest cannot learn a pattern that never occurs in the training text.

Validation, measured at 0.50:

| Metric | Value |
|---|---|
| Accuracy | 0.9879 |
| Precision | 1.0 |
| Recall | 0.9434 |
| F1 | 0.9709 |
| False-positive rate | 0.0 |
| Confusion | TN 17,271, FP 0, FN 266, TP 4,435 |

Per-family binary recall on validation: Cookie Injection, Directory Traversal, Log Forging, RCE, SQL Injection, and XSS are 1.0. LOG4J is 0.3885 (435 rows). When the binary model calls a validation attack malicious, the multiclass label matches that family on every such row.

Python parity cases: 13 passed. Gateway tests after the profile wiring:

```
Tests run: 31, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

That run included `PayloadFeaturesTest` plus the previous identity, decision, extractor, JNDI, ML-unavailable, and review-rule tests. `mvn -DskipTests package` then completed with BUILD SUCCESS. The jar was started only on port 8081 as PID 26012:

`java -jar <review jar> --server.port=8081 --gateway.atrdf.profile=experimental-payload`

The ML service was restarted so it could load the new joblibs. It is PID 28800 on port 8000 and still serves the production and 14-feature models. The review rules remain a backup on this profile. A rule match is stored even when the model already blocked.

Experiment `EXP-PAYLOAD-8081` is on PID 26012. Comment count on book `101` was 1 before the posts and 1 after, read directly from the demo API. Login REQ-1001 was ALLOW, BENIGN 0.91 / MALICIOUS 0.09, and the three comment posts record `authenticatedUser` `user01`.

| Case | Request | ML binary | Multiclass | Rule | Final | Backend |
|---|---|---|---|---|---|---|
| SQLI_001 | REQ-1002 `GET /api/books` | BLOCK, BENIGN 0.17 / MALICIOUS 0.83 | SQL Injection | `ATRDF-SQL-STRUCTURE` MATCH | HTTP 403, ML BLOCK | Not reached. The search was not forwarded. |
| XSS_001 | REQ-1003 `POST /api/comments/book/101` | BLOCK, BENIGN 0.4299 / MALICIOUS 0.5701 | LOG4J | `ATRDF-MARKUP-SCRIPT` MATCH | HTTP 403, ML BLOCK | Not reached. The comment count stayed 1. |
| COOKIE_001 | REQ-1004 `GET /api/books` with the saved cookie | BLOCK, BENIGN 0.2195 / MALICIOUS 0.7805 | Cookie Injection | `ATRDF-COOKIE-AUTHORITY` MATCH | HTTP 401, ML BLOCK | Not reached. The cookie was not forwarded. |
| LOGFORGE_001 | REQ-1005 `POST /api/comments/book/101` | BLOCK, BENIGN 0.33 / MALICIOUS 0.67 | LOG4J | `ATRDF-LOG-LINE` MATCH | HTTP 403, ML BLOCK | Not reached. The comment count stayed 1. |
| RCE_001 | REQ-1006 `GET /api/books` with the saved search | BLOCK, BENIGN 0.24 / MALICIOUS 0.76 | LOG4J | `ATRDF-COMMAND-CHAIN` MATCH | HTTP 403, ML BLOCK | Not reached. No command was run. |
| TRAVERSAL_001 | REQ-1007 `GET /api/books/..%2F..%2F..%2Fetc%2Fpasswd` | BLOCK, BENIGN 0.2981 / MALICIOUS 0.7019 | LOG4J | `ATRDF-PATH-TRAVERSAL` MATCH | HTTP 403, ML BLOCK | Not reached. The encoded slash reached the filter and was not forwarded. |
| LOG4J_001 | REQ-1008 `POST /api/comments/book/101` | ALLOW, BENIGN 0.5199 / MALICIOUS 0.4801 | not run | `ATRDF-JNDI-LOOKUP` MATCH | HTTP 403, rule block | Not reached. No lookup was made. The comment count stayed 1. |

The binary model itself detects SQL Injection and Cookie Injection and names those families. It also scores XSS, Log Forging, RCE, and Directory Traversal as malicious, but the multiclass label on all four is LOG4J. LOG4J is the only lab family the binary model misses. The fallback rule blocks that one. `jndi_lookup` and `command_chain` have no positive training rows, so raising either flag on a live request does not move the forest. `markup_script` has multiclass importance 0.0149, while `path_length` has 0.1637, so a comment path that already resembles the LOG4J numeric shape keeps that label. The threshold was not lowered.

REQ-1044 `GET /api/books?search=protocol&ref=a+b;c` returned HTTP 200, `total` 1, ALLOW, BENIGN 0.5984 / MALICIOUS 0.4016, rule `NONE`, `backendReached` true.

The same 35-case suite, experiment `EXP-PAYLOAD-SUITE-8081`, no longer passes. 17 returned HTTP 200 with ALLOW and `backendReached` true. 18 were ML blocks, rule `NONE`, class LOG4J, backend not reached:

- `GET /api/comments/book/101` on H2, H3, H4, H5, and H6. Malicious probability about 0.6318.
- `GET /api/health` on H2, H3, H4, H5, and H6. Malicious probability 0.5213.
- `GET /` on H2, H3, and H6.
- `GET /api/comments/book/201` on H3 and H4, and `GET /api/comments/book/302` on H3 and H6. Malicious probability about 0.6319.
- `GET /api/books?category=Computer%20Science` on H3.

Catalog searches for protocol, maths, anomaly, gateway, and the other category values in the suite stayed ALLOW, with malicious probability about 0.40 to 0.45.

The open catalog at `http://localhost:5173/` did not render the seeded titles. The browser sent two `GET /api/books` requests, REQ-1045 and REQ-1046. Both were ML BLOCK, BENIGN 0.2506 / MALICIOUS 0.7494, multiclass LOG4J, rule `NONE`, HTTP 403, `backendReached` false. The page showed `Dangerous lookup pattern blocked.` The script suite's shorter header set still allows `/api/books`. The browser header set does not. `header_count` is the largest binary importance, 0.2414. This is a live false positive. The threshold was not changed to hide it.

## Context-balanced payload candidate

The first payload forest used path and header statistics to separate attack rows that contain no structural marker. Those rows include every LOG4J example in the training partition, because that text never contains `${jndi:`. Live catalog, health, and comment routes fell into the same region and were blocked as LOG4J. A second candidate was trained without replacing the first joblibs or the production models. It is `research/atrdf_payload_experiment/context/candidate_binary_rf_payload_context.joblib` and `candidate_multiclass_rf_payload_context.joblib`. scikit-learn 1.2.2, 100 trees, depth 16, seed 42, threshold 0.50. `REQUEST_ONLY_test.csv` was not opened, and the seven lab requests were not added as training rows.

The fit uses the original training mask, except 6,615 malicious training rows whose seven flags are all zero. Those rows stay in the validation score. In their place, each family gets 4,000 synthetic training rows copied from benign training features with that family's flag set to 1. The synthetic rows are weighted 4. Another 12,000 benign rows vary header count and path size across the live gateway range, with every flag left at 0. Validation is still the original 21,972 rows.

| Metric | Original validation rows |
|---|---|
| Accuracy | 0.9483 |
| Precision | 1.0 |
| Recall | 0.7581 |
| F1 | 0.8624 |
| False-positive rate | 0.0 |
| Confusion | TN 17,271, FP 0, FN 1,137, TP 3,564 |

The misses are the validation attacks that never set a structural flag: all 435 LOG4J rows, and the unmarked halves of XSS and RCE. Every flagged validation attack is detected, and its family label matches. Binary importance sits on the seven flags. The original 13 numeric features have importance 0 in this candidate.

`mvn -DskipTests package` completed with BUILD SUCCESS after the telemetry model name was set to `candidate_binary_rf_payload_context`. The review gateway is PID 32228 on port 8081 with `--gateway.atrdf.profile=experimental-payload`. The ML service is PID 23872 on port 8000. Production port 8080 is still PID 32176. The review rules still record a match, and the model decision is the one returned when both fire.

Experiment `EXP-CONTEXT-8081` is on PID 32228. Comment count on book `101` was 1 before the posts and 1 after. Login REQ-1001 was ALLOW, BENIGN 1.0 / MALICIOUS 0.0, and the comment posts record `authenticatedUser` `user01`.

| Case | Request | ML binary | Family and mitigation | Rule | Final | Backend |
|---|---|---|---|---|---|---|
| SQLI_001 | REQ-1002 | BLOCK, MALICIOUS 1.0 | SQL Injection, `BLOCK + parameterized query path` | `ATRDF-SQL-STRUCTURE` | HTTP 403, ML BLOCK | Not reached |
| XSS_001 | REQ-1003 | BLOCK, MALICIOUS 1.0 | XSS, `BLOCK / ALERT + safe rendering` | `ATRDF-MARKUP-SCRIPT` | HTTP 403, ML BLOCK | Not reached. Comment count stayed 1 |
| COOKIE_001 | REQ-1004 | BLOCK, MALICIOUS 1.0 | Cookie Injection, `BLOCK + session validation` | `ATRDF-COOKIE-AUTHORITY` | HTTP 401, ML BLOCK | Not reached |
| LOGFORGE_001 | REQ-1005 | BLOCK, MALICIOUS 1.0 | Log Forging, `BLOCK / ALERT + structured logging` | `ATRDF-LOG-LINE` | HTTP 403, ML BLOCK | Not reached. Comment count stayed 1 |
| RCE_001 | REQ-1006 | BLOCK, MALICIOUS 1.0 | RCE, `BLOCK (Execution: NOT PERFORMED)` | `ATRDF-COMMAND-CHAIN` | HTTP 403, ML BLOCK | Not reached. No command was run |
| TRAVERSAL_001 | REQ-1007 | BLOCK, MALICIOUS 1.0 | Directory Traversal, `BLOCK + path validation` | `ATRDF-PATH-TRAVERSAL` | HTTP 403, ML BLOCK | Not reached |
| LOG4J_001 | REQ-1008 | BLOCK, MALICIOUS 1.0 | LOG4J, `BLOCK / ALERT + safe logging` | `ATRDF-JNDI-LOOKUP` | HTTP 403, ML BLOCK | Not reached. No lookup was made. Comment count stayed 1 |

The model itself detects all seven families and supplies the mitigation text. The rules match as a labeled backup and do not replace the ML class.

The 35-case suite, experiment `EXP-CONTEXT-SUITE-8081`, returned HTTP 200, ALLOW, BENIGN 1.0 / MALICIOUS 0.0, and `backendReached` true for all 35 cases. REQ-1044 `GET /api/books?search=protocol&ref=a+b;c` was HTTP 200, ALLOW, malicious probability 0.0, rule `NONE`, `backendReached` true.

The catalog at `http://localhost:5173/` rendered `Foundations of Network Protocol Security` by Dr. Evelyn Carter and the other seeded titles. REQ-1045 was ALLOW, HTTP 200, BENIGN 1.0, `backendReached` true. REQ-1046 was ALLOW, telemetry status 304, BENIGN 1.0, `backendReached` true. Model name `candidate_binary_rf_payload_context`.

Rows in the original dataset that contain no structural marker, including the stored LOG4J rows, remain undetected by this candidate. That is the validation recall of 0.7581. The live lab requests contain the markers, and those are the requests this candidate detects.

## Revised context candidate

On the training mask, benign `header_count` runs from 5 to 16 with median 15. XSS, RCE, LOG4J, and the other attack families sit in the same 14–16 band. A browser catalog request carries a header count in that band, so `header_count` cannot separate it from those attacks. The earlier 20-feature forest gave `header_count` importance 0.2414 and scored the browser catalog as malicious 0.7494. The context forest gives `header_count` importance 0. Its probability for the browser catalog and for every case in the 35-case suite is malicious 0.0.

The training-mask rows that the first context model missed were inspected from request text. Every unmarked RCE row contains a template expression (`{{`, `__globals__`, `__builtins__`, or `__import__`). None of the 97,473 benign training-mask rows contain one. `command_chain` now includes that expression, after the same percent-decoding used for the other flags. The feature name and its position in the 20-feature vector are unchanged. Unmarked XSS rows are ordinary paths such as `/forum` with a normal browser user agent and an empty query and body. Unmarked LOG4J rows are ordinary URLs with no lookup marker. Those two groups have no request text that distinguishes them from legitimate browser traffic, so they were left out of the numeric split. The 0.50 threshold was not changed. The seven lab requests were not added as training rows. `REQUEST_ONLY_test.csv` was not opened.

Validation on the same 21,972 rows:

| Metric | Value |
|---|---|
| Accuracy | 0.9592 |
| Precision | 1.0 |
| Recall | 0.8092 |
| F1 | 0.8945 |
| False-positive rate | 0.0 |
| Confusion | TN 17,271, FP 0, FN 897, TP 3,804 |

Per-family binary recall: Cookie Injection, Directory Traversal, Log Forging, RCE, and SQL Injection are 1.0. XSS is 0.5038 (469 of 931 rows contain markup; the other 462 have no stored payload). LOG4J is 0.0 (435 rows, no stored lookup marker). When a validation attack is detected, the family label matches.

Python parity checks passed 14 cases. `PayloadFeaturesTest` passed, 1 test, 0 failures. `mvn -DskipTests package` completed with BUILD SUCCESS. The review gateway is PID 35312 on port 8081. The ML service is PID 24012 on port 8000. Production port 8080 is still PID 32176.

Experiment `EXP-CONTEXT2-8081` is on PID 35312. These request IDs are not the earlier events with the same numbers. Comment count on book `101` was 1 before the posts and 1 after. All seven lab cases were ML blocks at malicious probability 1.0, with the matching family and mitigation. The rules also matched and did not replace the ML class. The backend was not reached.

| Case | Request | ML class and mitigation | Rule | HTTP |
|---|---|---|---|---|
| SQLI_001 | REQ-1002 | SQL Injection, `BLOCK + parameterized query path` | `ATRDF-SQL-STRUCTURE` | 403 |
| XSS_001 | REQ-1003 | XSS, `BLOCK / ALERT + safe rendering` | `ATRDF-MARKUP-SCRIPT` | 403 |
| COOKIE_001 | REQ-1004 | Cookie Injection, `BLOCK + session validation` | `ATRDF-COOKIE-AUTHORITY` | 401 |
| LOGFORGE_001 | REQ-1005 | Log Forging, `BLOCK / ALERT + structured logging` | `ATRDF-LOG-LINE` | 403 |
| RCE_001 | REQ-1006 | RCE, `BLOCK (Execution: NOT PERFORMED)` | `ATRDF-COMMAND-CHAIN` | 403 |
| TRAVERSAL_001 | REQ-1007 | Directory Traversal, `BLOCK + path validation` | `ATRDF-PATH-TRAVERSAL` | 403 |
| LOG4J_001 | REQ-1008 | LOG4J, `BLOCK / ALERT + safe logging` | `ATRDF-JNDI-LOOKUP` | 403 |

The 35-case suite, experiment `EXP-CONTEXT2-SUITE-8081`, returned HTTP 200 and ALLOW for all 35, with malicious probability 0.0 and `backendReached` true. REQ-1044 `search=protocol&ref=a+b;c` was the same.

Reloading `http://localhost:5173/` rendered `Foundations of Network Protocol Security` by Dr. Evelyn Carter and the other seeded titles. The browser sent REQ-1045 and REQ-1046, both `GET /api/books`, both ALLOW, BENIGN 1.0 / MALICIOUS 0.0, rule `NONE`, telemetry status 304, `backendReached` true, model `candidate_binary_rf_payload_context`. The same probability was recorded for the 35-case suite. `header_count` did not move the score.

## Header-aware context candidate

The 462 missed XSS validation rows and all 435 missed LOG4J validation rows were read from the original ATRDF JSON, using the same seed-42 validation mask and the same record-id alignment as the saved training partition. `REQUEST_ONLY_test.csv` was not opened.

Every one of the 435 validation LOG4J rows, and all 2,551 training-mask LOG4J rows, contains `${jndi:` in a request header value. The header names that carry it are `Set-Cookie`, `Sec-Fetch-Site`, `Accept-Encoding`, and `Sec-Fetch-Dest`. The URL and body do not contain it. The clean CSV kept `header_count` and `user_agent` and dropped the other header values, so the earlier `jndi_lookup` flag stayed 0. The existing `${jndi:` pattern matches those header values. It matches none of the benign training or validation rows.

The 462 missed XSS rows do not contain a script tag, `alert(`, or an event-handler attribute in the URL, query, body, cookie, or any header value, including after percent-decoding. That content is absent from the raw records. No new XSS feature was invented for those rows.

Benign `Set-Cookie` values do collide with the broader patterns: article titles that contain both `Select` and `---`, the substring `cookie`, `%0d`, and `../` inside opaque tokens. Scanning `Set-Cookie` with those five patterns would mark benign rows. `Set-Cookie` is therefore included only for `markup_script` and `jndi_lookup`. Every other header value is included for all seven flags. With that split, benign training and validation rows gain no new flags from header values. Training and the live Java and Python extractors use this same split. The threshold remains 0.50. The seven lab requests were not added as training rows. The new joblibs are `research/atrdf_payload_experiment/context_headers/candidate_binary_rf_payload_headers.joblib` and `candidate_multiclass_rf_payload_headers.joblib`. Production models were not replaced.

Validation on the same 21,972 rows:

| Metric | Value |
|---|---|
| Accuracy | 0.9791 |
| Precision | 1.0 |
| Recall | 0.9021 |
| F1 | 0.9486 |
| False-positive rate | 0.0 |
| Confusion | TN 17,271, FP 0, FN 460, TP 4,241 |

Per-family precision, recall, and F1, with the family assigned only when the binary probability is at least 0.50:

| Family | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Cookie Injection | 1.0 | 1.0 | 1.0 | 968 |
| Directory Traversal | 1.0 | 1.0 | 1.0 | 464 |
| LOG4J | 1.0 | 1.0 | 1.0 | 435 |
| Log Forging | 1.0 | 1.0 | 1.0 | 459 |
| RCE | 1.0 | 1.0 | 1.0 | 488 |
| SQL Injection | 1.0 | 1.0 | 1.0 | 956 |
| XSS | 1.0 | 0.5059 | 0.6719 | 931 |

LOG4J is 435 of 435. XSS is 471 of 931. The 460 false negatives are the validation XSS rows whose raw requests contain no markup. When a validation attack is detected, the family label matches.

Python parity checks passed 20 cases. `PayloadFeaturesTest` passed, 1 test, 0 failures. `mvn -DskipTests package` completed with BUILD SUCCESS at 2026-10-11T13:13:37+05:30. The review gateway is PID 24400 on port 8081 with `--gateway.atrdf.profile=experimental-payload`. The ML service listener is PID 27256 on port 8000. Production port 8080 is still PID 32176.

Experiment `EXP-HEADERS-8081` is on PID 24400. These request IDs are not the earlier events with the same numbers. Comment count on book `101` was 1 before the posts and 1 after. Login REQ-1001 was ALLOW, BENIGN 1.0 / MALICIOUS 0.0. All seven lab cases were ML blocks at malicious probability 1.0, with the matching family and mitigation. The rules also matched and did not replace the ML class. The backend was not reached.

| Case | Request | ML class and mitigation | Rule | HTTP |
|---|---|---|---|---|
| SQLI_001 | REQ-1002 | SQL Injection, `BLOCK + parameterized query path` | `ATRDF-SQL-STRUCTURE` | 403 |
| XSS_001 | REQ-1003 | XSS, `BLOCK / ALERT + safe rendering` | `ATRDF-MARKUP-SCRIPT` | 403 |
| COOKIE_001 | REQ-1004 | Cookie Injection, `BLOCK + session validation` | `ATRDF-COOKIE-AUTHORITY` | 401 |
| LOGFORGE_001 | REQ-1005 | Log Forging, `BLOCK / ALERT + structured logging` | `ATRDF-LOG-LINE` | 403 |
| RCE_001 | REQ-1006 | RCE, `BLOCK (Execution: NOT PERFORMED)` | `ATRDF-COMMAND-CHAIN` | 403 |
| TRAVERSAL_001 | REQ-1007 | Directory Traversal, `BLOCK + path validation` | `ATRDF-PATH-TRAVERSAL` | 403 |
| LOG4J_001 | REQ-1008 | LOG4J, `BLOCK / ALERT + safe logging` | `ATRDF-JNDI-LOOKUP` | 403 |

The 35-case suite, experiment `EXP-HEADERS-SUITE-8081`, returned HTTP 200 and ALLOW for all 35, with malicious probability 0.0, rule `NONE`, and `backendReached` true. REQ-1044 `search=protocol&ref=a+b;c` was the same. Model name `candidate_binary_rf_payload_headers`.

Reloading `http://localhost:5173/` rendered `Foundations of Network Protocol Security` by Dr. Evelyn Carter and the other seeded titles. The browser sent REQ-1045 and REQ-1046, both `GET /api/books`, experiment `EXP-LIVE`, test case `CASE-WEB`, both ALLOW, BENIGN 1.0 / MALICIOUS 0.0, rule `NONE`, telemetry status 304, `backendReached` true, model `candidate_binary_rf_payload_headers`.

## XSS recall limit

The 460 XSS false negatives were reconciled against the header-aware predictions. Validation XSS is 931 rows. 469 contain markup in the path, query, body, or user agent. 462 do not. Two of those 462 pick up another structural flag from a header and are detected as XSS. The remaining 460 set no flag, and those are the false negatives. XSS recall stays 0.5059. This validation mask was already used to train the candidate, so it is not a fresh holdout.

The raw JSON for the training partition contains three XSS URLs. 3,211 are `GET http://127.0.0.1:5000/forum` with an empty query and body. The other 3,203 add a `message` query whose decoded text contains `<script>alert`. The plain URL is the missed group. Its response body is `text/html; charset=utf-8`. A broad token scan of the URL, headers, cookie, and body found no XSS syntax that is present on the plain rows and absent from benign rows. Benign rows never use the path `/forum`, so a path feature would raise recall on this split by memorizing the endpoint. That feature was not added. The threshold stayed 0.50.

The experimental model is still `research/atrdf_payload_experiment/context_headers/candidate_binary_rf_payload_headers.joblib`. Production models and port 8080 were not changed. Python parity passed 22 cases. `PayloadFeaturesTest` passed, 1 test, 0 failures, BUILD SUCCESS at 2026-10-11T13:51:10+05:30. The review gateway was not rebuilt because the feature formulas and the model file did not change. The census and the reason for leaving the model in place are in `research/atrdf_payload_experiment/XSS_RECALL_LIMIT.md`.

## Six-family experimental scope

XSS is no longer an evaluated class of the experimental ATRDF model. The 460 validation false negatives are `GET /forum` requests with no XSS payload in any request field, as recorded above. Those rows were excluded from the scoped training and validation sets. Their labels were not changed to benign. The original dataset files were not rewritten.

Excluded counts on the existing seed-42 mask: 5,483 XSS rows from the training mask and 931 XSS rows from the validation mask. Scoped validation is 21,041 rows (17,271 benign and 3,770 attacks). This mask was already used for the earlier payload candidates, so these figures are not a fresh holdout. `REQUEST_ONLY_test.csv` was not opened.

The previous header-aware joblibs were copied to `research/atrdf_payload_experiment/context_headers_backup/` before the new candidate was saved. The selected model is `research/atrdf_payload_experiment/context_six/candidate_binary_rf_payload_six.joblib` and `candidate_multiclass_rf_payload_six.joblib`. Classes, in order, are Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, and SQL Injection. Threshold 0.50. The seven structural flags are still extracted. `markup_script` stays because 246 validation RCE rows are identified only by that flag. A markup-only request therefore receives the RCE class. The saved XSS lab case has that shape, so its model output is not counted as an XSS detection or as a successful RCE detection.

Scoped validation:

| Metric | Value |
|---|---|
| Accuracy | 1.0 |
| Precision | 1.0 |
| Recall | 1.0 |
| F1 | 1.0 |
| False-positive rate | 0.0 |
| Binary confusion | TN 17,271, FP 0, FN 0, TP 3,770 |

Multiclass confusion, rows ordered Benign, Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection, is diagonal: 17,271, 968, 464, 435, 459, 488, 956. Each of the six families has precision, recall, and F1 of 1.0.

Python parity passed 22 cases. Gateway unit tests passed 32, with 0 failures: VerifiedIdentityTest, DecisionEngineTest, BenignAugmentationExtractorTest, FeatureExtractorTest, JndiLookupMarkerTest, PayloadFeaturesTest, MlUnavailableGatewayTest, ReviewInspectionGatewayTest, and ReviewRequestGuardTest. `mvn -DskipTests package` completed with BUILD SUCCESS at 2026-10-11T14:11:28+05:30. The review gateway is PID 17256 on port 8081. The ML service listener is PID 33372 on port 8000. Production port 8080 is still PID 32176.

Experiment `EXP-SIX-8081` is on PID 17256. Comment count on book `101` was 1 before the posts and 1 after. The six supported lab cases were ML blocks at malicious probability 1.0 with the matching family and mitigation. The rules also matched and did not replace the class. The backend was not reached. XSS_001 is out of scope: the model emitted RCE at malicious probability 1.0 because the only flag is `markup_script`, and rule `ATRDF-MARKUP-SCRIPT` also matched. That request is not counted as a supported detection. The comment was not stored.

| Case | Request | ML result | Rule | HTTP | Counted |
|---|---|---|---|---|---|
| SQLI_001 | REQ-1002 | SQL Injection, `BLOCK + parameterized query path` | `ATRDF-SQL-STRUCTURE` | 403 | Yes |
| XSS_001 | REQ-1003 | RCE at malicious 1.0, out of scope | `ATRDF-MARKUP-SCRIPT` | 403 | No |
| COOKIE_001 | REQ-1004 | Cookie Injection, `BLOCK + session validation` | `ATRDF-COOKIE-AUTHORITY` | 401 | Yes |
| LOGFORGE_001 | REQ-1005 | Log Forging, `BLOCK / ALERT + structured logging` | `ATRDF-LOG-LINE` | 403 | Yes |
| RCE_001 | REQ-1006 | RCE, `BLOCK (Execution: NOT PERFORMED)` | `ATRDF-COMMAND-CHAIN` | 403 | Yes |
| TRAVERSAL_001 | REQ-1007 | Directory Traversal, `BLOCK + path validation` | `ATRDF-PATH-TRAVERSAL` | 403 | Yes |
| LOG4J_001 | REQ-1008 | LOG4J, `BLOCK / ALERT + safe logging` | `ATRDF-JNDI-LOOKUP` | 403 | Yes |

The 35-case suite, experiment `EXP-SIX-SUITE-8081`, returned HTTP 200 and ALLOW for all 35, malicious probability 0.0, rule `NONE`, `backendReached` true. REQ-1045 `search=protocol&ref=a+b;c` was the same. Model name `candidate_binary_rf_payload_six`.

BOLA_001, REQ-1009, `PUT /api/books/201` by user01, used model `bola_rf_behavioral`. The model decision was BLOCK, the gateway decision was ALERT, the backend was reached, and HTTP status was 403. Book 201 kept the title `Applied Machine Learning in Anomaly Detection`.

Reloading `http://localhost:5173/` rendered `Foundations of Network Protocol Security` by Dr. Evelyn Carter and the other seeded titles. The browser sent REQ-1046 and REQ-1047, both `GET /api/books`, experiment `EXP-LIVE`, test case `CASE-WEB`, both ALLOW, BENIGN 1.0 / MALICIOUS 0.0, rule `NONE`, telemetry status 304, `backendReached` true, model `candidate_binary_rf_payload_six`. The lab screen labels XSS_001 as not an evaluated ATRDF model class.

## OWASP ZAP on the review gateway

ZAP 2.17.0 was not installed at the start of this check. Docker Desktop's engine was not running, so the official cross-platform zip was verified by SHA-256 `94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0` and unpacked under `%LOCALAPPDATA%\Programs\ZAP\ZAP_2.17.0`. The daemon was started with JDK 21 on `127.0.0.1:8091` because port 8090 was already used by an unrelated Wondershare process. `GET /JSON/core/view/version/` returned 2.17.0. The full command, scanner policy, and per-request evidence are in `docs/ZAP_ATRDF_VERIFICATION.md`.

The scan target was `http://127.0.0.1:8081`. Ports 8080, 5001, 5173, and 8000 were excluded. The active scan was GET-only. The OAST callback service was empty and the Log4Shell scanner was not enabled. The project manifest that points at port 8080 was not run.

The spider found 14 review-gateway URLs. Passive rules reported header findings only: Cross-Domain Misconfiguration (14, medium), missing `X-Content-Type-Options` (7, low), `X-Powered-By` leak (5, low), and missing `Content-Type` (5, informational). ZAP raised no confirmed injection alert.

The parameterized active scan, ZAP scan id 3, sent 133 GET requests to `/api/books?category=Technology`. The gateway blocked 12 as SQL Injection, 7 as Log Forging, 4 as Directory Traversal, and 14 as RCE, all with the backend not reached. Three of the RCE rows are ZAP XSS markup and are not counted as XSS or RCE detections. Eight Windows-path values were model-benign and were blocked by `ATRDF-PATH-TRAVERSAL`. Twenty-four time-based SQL, bare `cat /etc/passwd`, and template strings were allowed through as catalog filters. The demo API did not execute them. REQ-1121, a random unknown book id, was a BOLA-model block before the backend.

After that scan, experiment `EXP-ZAP-REG-8081` repeated the six in-scope cases. SQLI_001 REQ-1140, COOKIE_001 REQ-1141, RCE_001 REQ-1142, TRAVERSAL_001 REQ-1143, LOGFORGE_001 REQ-1144, and LOG4J_001 REQ-1145 were malicious probability 1.0, matching family and rule, backend false. LOG4J used `test-research-domain.invalid`. XSS_001 REQ-1146 was class RCE with rule `ATRDF-MARKUP-SCRIPT` and is not counted. Book 101 still had 1 comment.

user01 management read REQ-1147, edit-view REQ-1148, PUT REQ-1149, and DELETE REQ-1150 were model `bola_rf_behavioral`, gateway ALERT, HTTP 403, backend true, with `BOLA_AUTHORIZATION_DENIED` or `BOLA_PERMISSION_DENIED`. Book 201 kept `Applied Machine Learning in Anomaly Detection`. Book 301 kept `Cryptography and Public Key Infrastructure`. The owner read REQ-1151 was ALLOW and HTTP 200.

The 35-case suite `EXP-ZAP-SUITE2-8081` was 35/35 HTTP 200 ALLOW, malicious probability 0.0, backend true. REQ-1187 `search=protocol&ref=a+b;c` was ALLOW. Reloading `http://localhost:5173/` rendered the seeded titles. REQ-1320 and REQ-1321 were `GET /api/books`, ALLOW, BENIGN 1.0, rule `NONE`, status 304, backend true, model `candidate_binary_rf_payload_six`. Production PID 32176 and the SHA-256 hashes under `models/atrdf` and `models/bola` were unchanged.

## Review-gateway follow-up for the ZAP gaps

The demo API catalog filter is an in-memory substring check. The 24 payloads that reached it could not change a SQL statement or run a command. They were still suspicious, so `ReviewRequestGuard` now matches time-based SQL calls (`pg_sleep`, `DBMS_SESSION.SLEEP`, `sleep(`, `Thread.sleep`), bare `cat /etc/passwd`, separator-plus-`sleep` / `start-sleep`, template execution strings, and Windows or `WEB-INF` file targets. The candidate joblibs and the seven structural feature formulas were left as they were. The model still scores these shapes BENIGN. The review rule blocks them, and the backend is not reached.

On PID 32816, experiment `EXP-ZAP-FIX-8081`, the previously missed examples REQ-1011 through REQ-1026 were HTTP 403 with the matching rule and `backendReached` false. `category=Technology`, `search=sleep`, and `ref=a+b;c` stayed ALLOW. The Windows-path examples are benign to the model because `path_traversal` looks only for `../` and `..\`. The rule blocks them.

The review profile now echoes only `http://localhost:5173`, `http://127.0.0.1:5173`, `http://localhost:5174`, and `http://127.0.0.1:5174`. It sets `X-Content-Type-Options: nosniff`, drops `X-Powered-By`, and supplies a content type when the backend body is JSON and the header was absent. `Origin: https://evil.example` is not reflected. The same header check covered the spider routes, including `/`, `/health`, `/api/books`, comments, and telemetry. Port 8080 was not restarted, so its running jar still has the previous header behavior.

The six in-scope cases REQ-1032, REQ-1033, REQ-1034, REQ-1035, REQ-1038, and REQ-1039 were again malicious probability 1.0 with the matching rule and the backend not reached. XSS_001 REQ-1040 remained an out-of-scope RCE score plus `ATRDF-MARKUP-SCRIPT`. user01's cross-owner read, edit, and delete were HTTP 403. Book 201 and book 301 were unchanged, and book 101 still had one comment. Disposable book 111 was created, a cross-owner delete was rejected, the owner delete succeeded, and the row was then gone. The 35-case suite `EXP-ZAP-FIX-SUITE` was 35/35 ALLOW. The browser catalog reload was REQ-1083 and REQ-1084, both ALLOW. Gateway tests for the guard, the header behavior, and payload features passed 6 tests with 0 failures. Python payload parity passed 22 cases. Production PID 32176 was still the production jar.

## Final ZAP rerun

ZAP 2.17.0 was already listening on `127.0.0.1:8091`. A new session cleared the old alerts. The spider and active scan stayed on `http://127.0.0.1:8081`. Ports 8080, 5001, 8000, and 5173 were excluded. The active scan was GET-only against `/api/books?category=Technology`, policy `bounded-safe`, with the OAST service empty. Scan id 0 finished at 100%. The 15 enabled scanners sent 127 requests and raised 0 injection alerts. History was 168 GET messages. 155 joined to telemetry. The per-scanner counts and the ML-versus-rule table are in `docs/ZAP_ATRDF_VERIFICATION.md`.

The four earlier header alerts are absent on this scan: Cross-Domain Misconfiguration (10098), missing `X-Content-Type-Options` (10021), `X-Powered-By` (10037), and missing Content-Type (10019). Direct probes showed `nosniff` on every checked response, no `X-Powered-By`, and no reflection of `Origin: https://evil.example`. `http://localhost:5173` is echoed. Catalog and health JSON used `application/json`. An unapproved origin on `/health` is Spring's `Invalid CORS request` (HTTP 403), which does not reflect the origin.

One passive alert remains. Plugin 10055, CSP Failure to Define Directive with No Fallback, is medium on five HTML 404s: `/sitemap.xml`, `/robots.txt`, `/api`, `/api/comments`, and `/api/comments/book`. The body is `Cannot GET <path>`. There is no CSP header. `nosniff` is set, and the XSS scanner raised nothing. This is a hardening note on error pages, not an injection. No further code change is required.

On scan id 0 the model blocked SQL, RCE, log forging, directory traversal, and one cookie payload at malicious probability 1.0. Seventeen SQL-shaped, thirteen path-shaped, and thirteen command-shaped requests were ML ALLOW / BENIGN 0.0 and were blocked by `ATRDF-SQL-STRUCTURE`, `ATRDF-PATH-TRAVERSAL`, or `ATRDF-COMMAND-CHAIN` before the backend. Three markup strings were classed RCE with `ATRDF-MARKUP-SCRIPT` and are not counted as XSS or as RCE detections. REQ-1088 and REQ-1098 blocked `GET /api/books/101`, and REQ-1105 blocked an unknown book id, all by `bola_rf_behavioral` before the backend.

The 16 previously missed payloads, experiment `EXP-ZAP-FINAL-PAYLOADS`, are REQ-1260 through REQ-1275. Each was ML ALLOW, BENIGN, malicious probability 0.0, HTTP 403, backend false, with the matching review rule. `category=Technology` REQ-1276, `search=sleep` REQ-1278, and `ref=a+b;c` REQ-1279 stayed ALLOW with the backend reached.

Experiment `EXP-ZAP-FINAL-LAB`: SQLI_001 REQ-1281, COOKIE_001 REQ-1282, RCE_001 REQ-1283, TRAVERSAL_001 REQ-1284, LOGFORGE_001 REQ-1285, and LOG4J_001 REQ-1286 were malicious probability 1.0, the matching rule, and backend false. LOG4J used `test-research-domain.invalid`. XSS_001 REQ-1287 was class RCE with `ATRDF-MARKUP-SCRIPT` and is not counted. The 35-case suite REQ-1288 through REQ-1322 was 35/35 HTTP 200 ALLOW, malicious probability 0.0, rule `NONE`, backend true.

user01 management read REQ-1340 and edit-view REQ-1341 returned `BOLA_AUTHORIZATION_DENIED`. PUT REQ-1342 and DELETE REQ-1343 returned `BOLA_PERMISSION_DENIED`. All four were model BLOCK, gateway ALERT, HTTP 403, backend true. The owner read REQ-1344 was HTTP 200. The model decision on that owner read remained BLOCK; the gateway forwarded it as ALERT. Book 201 stayed `Applied Machine Learning in Anomaly Detection`. Book 301 stayed `Cryptography and Public Key Infrastructure`. Book 101 stayed `Foundations of Network Protocol Security` with 1 comment.

`ReviewRequestGuardTest`, `ReviewInspectionGatewayTest`, and `PayloadFeaturesTest` passed: 6 tests, 0 failures, BUILD SUCCESS at 2026-10-11T15:21:40+05:30. Python payload parity passed 22 cases. Reloading `http://localhost:5173/` rendered the seeded catalog. REQ-1335, REQ-1336, and REQ-1337 were `GET /api/books`, ALLOW, BENIGN, rule `NONE`, backend true, model `candidate_binary_rf_payload_six`. Review PID 32816 and production PID 32176 were unchanged. The SHA-256 hashes under `models/atrdf` and `models/bola` matched the pre-scan snapshot.

## Public book read and the CSP 404s

`GET /api/books/101` is the public catalog record. The demo API checks a JWT and the owner only for `view=manage`, `access=edit`, PUT, and DELETE. The BOLA model still scores an anonymous read of book 101 as BLOCK, because the caller is `unknown` and the owner is user01. That score was the HTTP result on REQ-1088 and REQ-1098. On the review profiles the gateway now records the model block and forwards the read. The mitigation is `ALERT + public catalog read`. Management and mutation routes still use `ALERT + backend authorization`. The production profile code still hard-blocks this case, and port 8080 was not restarted.

Review PID 28796 replaced PID 32816 on port 8081. REQ-1001 returned HTTP 200 and `Foundations of Network Protocol Security`, with ML BLOCK, gateway ALERT, and the backend reached. An unknown id, REQ-1002, was the same model block and gateway ALERT, then HTTP 404 from the demo API. user01's cross-owner read REQ-1012, edit-view REQ-1013, PUT REQ-1014, and DELETE REQ-1015 stayed HTTP 403 with `BOLA_AUTHORIZATION_DENIED` or `BOLA_PERMISSION_DENIED`, ML BLOCK, gateway ALERT, backend true. The owner read REQ-1016 was HTTP 200. Book 201, book 301, and book 101's single comment were unchanged.

The five HTML 404s now include `default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'`. JSON responses do not. A ZAP session that only fetched those five URLs, `/api/books`, and `/api/books/101` finished its passive queue with no alerts, so plugin 10055 did not recur. Production `/robots.txt` on port 8080 still has neither that policy nor `nosniff`.

SQLI_001 REQ-1018, COOKIE_001 REQ-1019, RCE_001 REQ-1020, TRAVERSAL_001 REQ-1021, LOGFORGE_001 REQ-1022, and LOG4J_001 REQ-1023 were again malicious probability 1.0 with the matching rule and the backend not reached. XSS_001 REQ-1024 stayed out of scope. The 35-case suite REQ-1028 through REQ-1062 was 35/35 ALLOW. Gateway tests including the new public-read and CSP cases passed 15 tests with 0 failures at 2026-10-11T15:37:37+05:30. Python payload parity passed 22 cases. The catalog at `http://localhost:5173/` rendered the seeded titles. Production PID 32176 and the model files were unchanged.

## BOLA cases through ZAP

ZAP 2.17.0 sent the cases with `sendRequest` to `http://127.0.0.1:8081` only. Logins were `POST /api/auth/login` on that gateway. Tokens were not recorded. Experiment `EXP-ZAP-BOLA`. Book 101 stayed `Foundations of Network Protocol Security`, owned by user01. User01 created disposable book 111 for the edit and delete attempts. User02 could not change or remove it. User01 deleted it afterward, and a direct read then returned 404. The catalog returned 10 books.

User01's own management read, ZAP message 17, REQ-1075, was ML BLOCK, BOLA 1.0, gateway ALERT, backend reached, HTTP 200. User02's management read of book 101, message 18, REQ-1076, was the same model block and gateway ALERT, then backend `BOLA_AUTHORIZATION_DENIED`, HTTP 403. User02's PUT of book 111, message 20, REQ-1078, was BOLA 0.99 and backend `BOLA_PERMISSION_DENIED`. The title was still `ZAP BOLA disposable record` afterward. User02's DELETE, message 21, REQ-1079, was BOLA 0.98 and the same permission denial. The book was still present. A management read with no token, message 22, REQ-1080, reached the backend and returned HTTP 401 `Authentication required. Please log in.` The anonymous public read, message 23, REQ-1081, was ML BLOCK, BOLA 1.0, gateway ALERT with `ALERT + public catalog read`, HTTP 200. That alert is not a BOLA vulnerability. No review rule matched. `VerifiedIdentityTest` passed 5 tests with 0 failures at 2026-10-11T16:06:15+05:30. `http://127.0.0.1:5173/` rendered the seeded catalog and did not show book 111. Production PID 32176 was unchanged. The message ids and probability split are in `docs/ZAP_ATRDF_VERIFICATION.md`.

## Six ATRDF families through ZAP

The catalog page no longer has the Security Lab or the Edit (BOLA) button. Attack checks were sent with ZAP `sendRequest` to `http://127.0.0.1:8081`. XSS was not included. Each of the six families was a model block at malicious probability 1.0, and the matching rule also matched. The backend was not reached. SQLI_001 was ZAP message 25, REQ-1093, class SQL Injection, rule `ATRDF-SQL-STRUCTURE`, HTTP 403. TRAVERSAL_001 was message 26, REQ-1094, Directory Traversal, `ATRDF-PATH-TRAVERSAL`. RCE_001 was message 27, REQ-1095, RCE, `ATRDF-COMMAND-CHAIN`. COOKIE_001 was message 32, REQ-1096, Cookie Injection, `ATRDF-COOKIE-AUTHORITY`, HTTP 401. LOGFORGE_001 was message 33, REQ-1097, Log Forging, `ATRDF-LOG-LINE`. LOG4J_001 was message 35, REQ-1098, LOG4J, `ATRDF-JNDI-LOOKUP`, using `test-research-domain.invalid`. The RCE string stayed query text on `127.0.0.1`.

`category=Technology`, `search=sleep`, and `ref=a+b;c` were ZAP messages 36 through 38, REQ-1099 through REQ-1101, all ALLOW. The 35-case suite REQ-1102 through REQ-1136 was 35/35 HTTP 200 ALLOW. Book 101 and book 201 kept their titles and owners, and book 101 still had one comment. The owner management read REQ-1139 stayed HTTP 200. User02's management read REQ-1140 stayed HTTP 403 `BOLA_AUTHORIZATION_DENIED`. The catalog page still rendered the seeded titles. Production PID 32176 was unchanged.

## Cookie Injection 401 on REQ-1096

The 401 is the gateway status for a Cookie Injection block. Telemetry for REQ-1096, still on review PID 28796, records `statusCode` 401 and `backendReached` false. The decision is BLOCK, class Cookie Injection, malicious probability 1.0, mitigation `BLOCK + session validation`, rule `ATRDF-COOKIE-AUTHORITY`. ZAP message 32 stored the body `Invalid session state. Reauthentication required.` with code `Cookie Injection` and `request_id` REQ-1096. That body is written by the gateway before `forwardToDemoApi`. The demo API sentence `Authentication required. Please log in.` was the body of the earlier backend 401, REQ-1080, where `backendReached` was true.

The filter does not emit a per-request log line, and the review process was started without a captured console log. The demo API log has no entry at 10:42:56.571Z. Ordinary catalog reads are not logged there, so that silence matches the telemetry flag and is not an independent proof. Production PID 32176 and its model files were not changed.

## Frontend passive scan

ZAP 2.17.0 spider scan id 0 targeted `http://127.0.0.1:5173/` only. Context `frontend5173` included that origin. Ports 8080, 8081, and 5001 were excluded for the spider and the exclude list was then cleared. No active scan ran. The passive queue finished at 0.

HTTP 200 responses were ZAP messages 42 (`/`), 44 (`/robots.txt`), 45 (`/sitemap.xml`), 48 (`/src/main.jsx`), and 50 (`/@vite/client`). The robots and sitemap URLs returned the Vite HTML document. Messages 43, 49, and 51 have status 0. The spider did not follow JavaScript imports, so it did not scan the catalog API. Seventeen passive alerts were recorded on the Vite server: plugin 10021 missing `nosniff` on all five HTTP 200 responses, and plugins 10020, 10038, 90003, and 10109 on the three HTML responses. Those headers were left as the development server sends them.

The open catalog had no attack-launch button or payload panel. Search for `Anomaly` returned `Applied Machine Learning in Anomaly Detection`. View Details showed owner user02 and zero comments. REQ-1144 and REQ-1145 loaded the catalog, ALLOW, backend true. REQ-1146 was the search, ALLOW, HTTP 200, backend true. REQ-1147 read comments for book 201, ALLOW, HTTP 200, backend true. The subtitle still names port 8080, while these requests were inspected on port 8081. An unused `Navbar.jsx` link to a security lab is not rendered. Production remained PID 32176.

## Built frontend on port 4173

The catalog subtitle no longer names a port. It reads `All catalog operations are inspected by the security gateway.` The unreachable-gateway message no longer names a port. The unused Security Lab link was removed from `Navbar.jsx`, which `main.jsx` still does not mount. The unused security-lab stylesheet rules were removed. `npm run build` produced `frontend/dist`. The bundle contains `http://127.0.0.1:8081` and does not contain `localhost:8080`. `vite preview` serves that build at `http://127.0.0.1:4173/`.

The first load from that origin failed in the browser because the review gateway allowlist did not include port 4173. The review allowlist now includes `http://127.0.0.1:4173` and `http://localhost:4173`. Review PID 22888 replaced PID 28796 on port 8081 with the same `experimental-payload` profile. Production PID 32176 was not restarted, and its jar was not replaced.

After that restart, `http://127.0.0.1:4173/` rendered the ten seeded titles. The Technology filter left four technology books. Search for `Anomaly` left `Applied Machine Learning in Anomaly Detection`, with View Details and no Edit. Details showed owner user02 and zero comments. No comment was submitted. Browser catalog calls were REQ-1001 and REQ-1050 through REQ-1054, all ALLOW, BENIGN, rule NONE, backend true. The page font resolved to Inter, so the font hosts allowed by the preview policy loaded.

ZAP 2.17.0 passive spider scan 1 recorded the built site before response headers were added. It had the same missing `nosniff`, frame policy, and CSP alerts as the Vite dev server, plus plugin 10027 on the bundled script. Preview headers were then set in `vite.config.js` and the preview server was restarted. Spider scan 2, context `frontend4173b`, fetched `/`, `/robots.txt`, `/sitemap.xml`, `/assets`, `/assets/index-WAjVMVRh.js`, and `/assets/index-ZmyZF5Ip.css`. No active scan ran. Ports 8080 and 8081 were excluded from the spider. The passive queue finished at 0.

The HTML response now sends `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and this policy: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' http://127.0.0.1:8081 https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`. Plugins 10021, 10020, and 10038 were absent on that second scan. Remaining alerts are plugin 10055 because `style-src` includes `'unsafe-inline'` for the catalog's style attributes, plugin 90003 because the Google font stylesheet and the local script tag have no integrity attribute, plugin 10109 as an informational modern-application note, and plugin 10027 because the bundled React source contains the word `select` in an SVG namespace string. Integrity attributes were not added. `/robots.txt`, `/sitemap.xml`, and `/assets` return the same HTML document. The Vite dev server on port 5173 was not given this policy, because its development client uses inline scripts and a websocket. The earlier 5173 findings stay specific to that development server.

Experiment `EXP-ZAP-PREVIEW` on review PID 22888 sent the six families through ZAP `sendRequest` to `http://127.0.0.1:8081`. XSS was not sent. Each family was a model block at malicious probability 1.0 with the matching rule and `backendReached` false. SQLI_001 was message 124, REQ-1002, SQL Injection, `ATRDF-SQL-STRUCTURE`, HTTP 403. TRAVERSAL_001 was message 125, REQ-1003, Directory Traversal, `ATRDF-PATH-TRAVERSAL`. RCE_001 was message 126, REQ-1004, RCE, `ATRDF-COMMAND-CHAIN`. COOKIE_001 was message 127, REQ-1005, Cookie Injection, `ATRDF-COOKIE-AUTHORITY`, HTTP 401. LOGFORGE_001 was message 128, REQ-1006, Log Forging, `ATRDF-LOG-LINE`. LOG4J_001 was message 129, REQ-1007, LOG4J, `ATRDF-JNDI-LOOKUP`, using `test-research-domain.invalid`. `category=Technology`, `search=sleep`, and `ref=a+b;c` were messages 130 through 132, REQ-1008 through REQ-1010, all ALLOW. The 35-case suite was messages 133 through 167, REQ-1011 through REQ-1045, 35/35 HTTP 200 ALLOW, malicious probability 0.0, rule NONE, backend true.

User01's management read of book 101, message 170, REQ-1048, was ML BLOCK, BOLA 0.73 / NORMAL 0.27, gateway ALERT, backend true, HTTP 200, title returned. User02's management read, message 171, REQ-1049, was ML BLOCK, BOLA 1.0, gateway ALERT, backend `BOLA_AUTHORIZATION_DENIED`, HTTP 403. Book 101 stayed `Foundations of Network Protocol Security`, owner user01, with 1 comment. Book 201 stayed `Applied Machine Learning in Anomaly Detection`, owner user02. Production PID 32176 and the model files were unchanged.

## Submission reconciliation

The report, slides, diagrams, and demo checklist that use this evidence are:

- `submission/report/MTECH_RESEARCH_REPORT.md`
- `submission/presentation/MTECH_GUIDE_PRESENTATION.pptx`
- `submission/diagrams/01_system_architecture.svg`
- `submission/diagrams/02_request_flow.svg`
- `submission/diagrams/03_atrdf_detection.svg`
- `submission/diagrams/04_bola_authorization.svg`
- `submission/diagrams/05_zap_workflow.svg`
- `submission/demo/DEMO_CHECKLIST.md`

The same three scopes are used in each of those files.

Scoped validation of `candidate_binary_rf_payload_six`, from `SIX_FAMILY_SCOPE.md`: 21,041 rows, accuracy, precision, recall, and F1 of 1.0, false-positive rate 0.0, TN 17,271, FP 0, FN 0, TP 3,770. Family supports are SQL Injection 956, Directory Traversal 464, RCE 488, Cookie Injection 968, Log Forging 459, and LOG4J 435, each at precision, recall, and F1 of 1.0. The mask was already used while the payload candidates were built. `REQUEST_ONLY_test.csv` was not opened for this candidate, so the submission states no independent-test score for it.

The locked 13-feature test evaluation, from `FINAL_TEST_REPORT.md`: 36,554 rows, threshold 0.50, precision 1.0, recall 0.9389856362018558, F1 0.9685328438442375, false-positive rate 0.0, TN 28,687, FP 0, FN 480, TP 7,387. End-to-end LOG4J recall is 0.358768. `docs/RESEARCH_RESULTS.md` Table 5 lists recall 1.0 on the same supports. The locked matrix is the figure used here. That pass scored the frozen 13-feature forests. It did not score the six-family candidate, and the test file was not reopened.

Live gateway evidence is `EXP-ZAP-PREVIEW`: messages 124–129 and REQ-1002 through REQ-1007 for the six families, REQ-1011 through REQ-1045 for the 35/35 benign suite, and REQ-1048 / REQ-1049 for owner and cross-owner management reads. ZAP findings, ML predictions, deterministic-rule matches, and backend authorization results stay separate. The local checks do not establish that every attack is blocked or that vulnerabilities are absent.

The Vite development server on port 5173 still has the earlier missing `nosniff`, anti-clickjacking, and CSP findings. The built preview on port 4173 sends `nosniff`, `X-Frame-Options: DENY`, and the preview Content Security Policy. Plugin 10055 remains because `style-src` includes `'unsafe-inline'`, which the catalog style attributes require. Plugin 90003 remains because the Google Fonts stylesheet has no integrity hash and is not a stable byte string. Those alerts were not removed. Production PID 32176, port 8080, and the model files under `models/atrdf` and `models/bola` were not changed.
