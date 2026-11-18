# Controlled benign-read suite

These rates are for this 35-case suite only. They are not population false-positive rates and they are not the untouched test split.

## Commands

Java extractor, from `gateway`:

```
"C:\Program Files\JetBrains\IntelliJ IDEA Community Edition 2024.1.4\plugins\maven\lib\maven3\bin\mvn.cmd" -Dtest=DeploymentShiftAtrdfSuiteTest test
```

Result: Tests run: 1, Failures: 0, Errors: 0, BUILD SUCCESS.

Offline scoring, active models not loaded for replacement:

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\score_controlled_suite.py
```

Threshold 0.50. `REQUEST_ONLY_test.csv` was not read. Candidates were not retrained.

## Suite

`DeploymentShiftAtrdfSuiteTest` calls `FeatureExtractor.extractAtrdfFeatures` on GET requests to `http://127.0.0.1:8080`. Every `specification_label` is BENIGN and is not a model input. Extraction errors: 0.

Header profiles, counted by the extractor:

| Profile | Headers |
|---|---|
| H2 | Host, User-Agent |
| H3 | H2 + Accept |
| H4 | H3 + Accept-Language |
| H5 | H4 + Accept-Encoding |
| H6 | H5 + Connection |

Routes are public reads in `demo_api/server.js`: `/`, `/api/health`, `/api/books` with seed search and category values, and `/api/comments/book/101`, `/201`, and `/302`. `/api/books/{id}` is omitted because `SecurityGatewayFilter` sends that path to BOLA. `/api/profile` and `/api/users/me` require authentication and were not included.

## Controlled-suite totals

| Candidate | False positives | Rate |
|---|---:|---:|
| A, 13 features | 34 / 35 | 0.971429 |
| B, no header_count | 3 / 35 | 0.085714 |

The three Candidate B false positives are C16, C17, and C18, all `GET /`, probability 0.826167. Candidate A allows only C26, `GET /api/books?search=gateway&category=Technology`, probability 0.490176.

Within a route, header counts 2–6 did not change either candidate's probability.

## Cases

| Case | Profile | Count | Route | Query | A probability | A | B probability | B |
|---|---|---:|---|---|---:|---|---:|---|
| C01 | H2 | 2 | /api/books | | 0.520000 | MALICIOUS | 0.020240 | BENIGN |
| C02 | H2 | 2 | /api/comments/book/101 | | 0.650475 | MALICIOUS | 0.021141 | BENIGN |
| C03 | H2 | 2 | /api/health | | 0.580000 | MALICIOUS | 0.067713 | BENIGN |
| C04 | H3 | 3 | /api/books | | 0.520000 | MALICIOUS | 0.020240 | BENIGN |
| C05 | H3 | 3 | /api/comments/book/101 | | 0.650475 | MALICIOUS | 0.021141 | BENIGN |
| C06 | H3 | 3 | /api/health | | 0.580000 | MALICIOUS | 0.067713 | BENIGN |
| C07 | H4 | 4 | /api/books | | 0.520000 | MALICIOUS | 0.020240 | BENIGN |
| C08 | H4 | 4 | /api/comments/book/101 | | 0.650475 | MALICIOUS | 0.021141 | BENIGN |
| C09 | H4 | 4 | /api/health | | 0.580000 | MALICIOUS | 0.067713 | BENIGN |
| C10 | H5 | 5 | /api/books | | 0.520000 | MALICIOUS | 0.020240 | BENIGN |
| C11 | H5 | 5 | /api/comments/book/101 | | 0.650475 | MALICIOUS | 0.021141 | BENIGN |
| C12 | H5 | 5 | /api/health | | 0.580000 | MALICIOUS | 0.067713 | BENIGN |
| C13 | H6 | 6 | /api/books | | 0.520000 | MALICIOUS | 0.020240 | BENIGN |
| C14 | H6 | 6 | /api/comments/book/101 | | 0.650475 | MALICIOUS | 0.021141 | BENIGN |
| C15 | H6 | 6 | /api/health | | 0.580000 | MALICIOUS | 0.067713 | BENIGN |
| C16 | H2 | 2 | / | | 0.695000 | MALICIOUS | 0.826167 | MALICIOUS |
| C17 | H3 | 3 | / | | 0.695000 | MALICIOUS | 0.826167 | MALICIOUS |
| C18 | H6 | 6 | / | | 0.695000 | MALICIOUS | 0.826167 | MALICIOUS |
| C19 | H3 | 3 | /api/books | search=protocol | 0.540846 | MALICIOUS | 0.036608 | BENIGN |
| C20 | H3 | 3 | /api/books | search=maths | 0.550634 | MALICIOUS | 0.036777 | BENIGN |
| C21 | H3 | 3 | /api/books | category=Technology | 0.520634 | MALICIOUS | 0.054063 | BENIGN |
| C22 | H3 | 3 | /api/books | category=Science | 0.530634 | MALICIOUS | 0.052709 | BENIGN |
| C23 | H3 | 3 | /api/books | category=Engineering | 0.520634 | MALICIOUS | 0.051788 | BENIGN |
| C24 | H3 | 3 | /api/books | category=Mathematics | 0.520634 | MALICIOUS | 0.041410 | BENIGN |
| C25 | H3 | 3 | /api/books | category=Computer%20Science | 0.570361 | MALICIOUS | 0.061496 | BENIGN |
| C26 | H3 | 3 | /api/books | search=gateway&category=Technology | 0.490176 | BENIGN | 0.010995 | BENIGN |
| C27 | H3 | 3 | /api/books | category=All | 0.540634 | MALICIOUS | 0.052084 | BENIGN |
| C28 | H3 | 3 | /api/comments/book/201 | | 0.650475 | MALICIOUS | 0.020209 | BENIGN |
| C29 | H3 | 3 | /api/comments/book/302 | | 0.640705 | MALICIOUS | 0.020665 | BENIGN |
| C30 | H2 | 2 | /api/books | search=protocol | 0.540846 | MALICIOUS | 0.036608 | BENIGN |
| C31 | H6 | 6 | /api/books | search=protocol | 0.540846 | MALICIOUS | 0.036608 | BENIGN |
| C32 | H5 | 5 | /api/books | category=Technology | 0.520634 | MALICIOUS | 0.054063 | BENIGN |
| C33 | H4 | 4 | /api/comments/book/201 | | 0.650475 | MALICIOUS | 0.020209 | BENIGN |
| C34 | H6 | 6 | /api/comments/book/302 | | 0.640705 | MALICIOUS | 0.020665 | BENIGN |
| C35 | H4 | 4 | /api/books | search=anomaly | 0.530634 | MALICIOUS | 0.039985 | BENIGN |

Full precision is in `controlled_suite_results.json`.
