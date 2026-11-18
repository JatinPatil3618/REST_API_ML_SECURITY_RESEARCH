# LOG4J false-negative diagnostic

Validation only. `REQUEST_ONLY_test.csv` was not opened. No model was fit, and no active artifact or threshold was changed.

## Commands

Alignment used the research environment (scikit-learn 1.9.1), replaying `train_test_split(test_size=0.20, random_state=42, stratify=label)` from `atrdf4_features.csv`. Held-out ids were not written. Train rows matched `REQUEST_ONLY_train.csv`: 146,213 rows, labels equal, maximum absolute feature difference `8.88e-16`.

```
ATRDF_Research\.venv\Scripts\python.exe research\atrdf_header_count_ablation\log4j_fn_diagnostic\map_train_record_ids.py
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\log4j_fn_diagnostic\diagnose_log4j_false_negatives.py
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\log4j_fn_diagnostic\summarize_marker_headers.py
```

Scoring used `.venv-repair` (scikit-learn 1.2.2). The validation split is the existing one: `REQUEST_ONLY_train.csv`, `test_size=0.1`, `random_state=42`, `stratify=is_malicious`. Fit rows 131,591 were not scored. Validation rows 14,622. Threshold 0.50. Candidate A and the frozen production forest missed the same 203 LOG4J rows.

## Where the classes overlap

Training CSV: 114,744 Benign, 2,986 LOG4J. Validation: 11,475 Benign, 319 LOG4J, of which Candidate A detects 116 and misses 203.

Missed LOG4J scores are not near the threshold. The highest missed score is 0.0752. The lowest detected LOG4J score is 0.5626. Median scores are 0.0207 missed and 0.9412 detected.

| Group | Count | header_count | URL length median | URL special median | URL digit median | User-Agent entropy median | Body entropy |
|---|---:|---|---:|---:|---:|---:|---|
| LOG4J detected | 116 | 14: 41, 15: 10, 16: 65 | 47 | 11 | 11 | 5.099 | 0 |
| LOG4J missed | 203 | 15: 203 | 56 | 12 | 12 | 5.105 | 0 |
| Benign, header_count 15 | 8,186 | 15 | 55 | 12 | 12 | 5.093 | median 0 |
| Benign, all validation | 11,475 | 5: 1,676, 15: 8,186, 16: 1,613 | 55 | — | — | — | 9,862 at 0 |

Every missed LOG4J row is inside the benign min–max box on all 13 features. About 94% of missed rows also sit inside the benign 5th–95th percentile on URL entropy, URL length, and URL digits. Cookie is absent on every validation LOG4J and benign row. Query length median is 0 in both the misses and the header_count-15 benign rows.

The 10 detected LOG4J rows that also have header_count 15 are shorter (URL length median 37). The 203 misses match the dominant benign header_count-15 profile. Body length, body punctuation, content-type, and authorization were engineered and then left out of the 13 features; on these LOG4J rows they are all zero, so they do not separate the misses either.

## What the raw records contain

Record ids come from the alignment above (`record_id` is the 1-based JSON position). Counts below are presence checks. Request text was not stored.

Every training-split LOG4J record, 2,986 of 2,986, is a GET with an empty body. Each one contains both `${` and `jndi` in a header value. The URL, the User-Agent, the header names, and the body contain neither token. The same is true of all 116 detected and all 203 missed validation rows.

Header value that carries both tokens:

| Validation group | Header | Rows |
|---|---|---:|
| Detected | sec-fetch-site | 65 |
| Detected | accept-encoding | 41 |
| Detected | set-cookie | 7 |
| Detected | sec-fetch-dest | 3 |
| Missed | set-cookie | 142 |
| Missed | sec-fetch-dest | 61 |

The 41 `accept-encoding` rows are the header_count 14 detections. The 65 `sec-fetch-site` rows are the header_count 16 detections. `cookie_present` stays 0 when the text is in `Set-Cookie`, because preprocessing sets that flag only for a header named `cookie`.

On the training CSV, 24 of 114,744 benign rows contain `jndi` in a header value, and none contain `${`. On validation, 3 of 11,475 benign rows contain `jndi`, all in `set-cookie`, and none contain `${`.

## What runtime can see

`FeatureExtractor.extractAtrdfFeatures` already receives the servlet request, so every header name and value is available before a response. The saved 13 features keep only three header facts: `header_count`, `cookie_present`, and `user_agent_entropy`. Preprocessing drops the other header values before feature extraction. The aggregate URL and body features stay at benign values because the distinctive text is in those dropped header values.

A compact indicator is supported for header values: 1 when any header value contains both `${` and `jndi`, otherwise 0. On this training split that flag is 1 for 2,986 of 2,986 LOG4J rows and 0 for 114,744 of 114,744 benign rows. The `jndi` substring alone is not that flag; it collides with 24 benign rows. This corpus does not place the tokens in the URL, User-Agent, or body, so those fields do not add a measured signal here.

## Next change

Add that one header-value indicator as a temporary candidate feature and fit it only on the existing fit rows. Evaluate on this validation split. Keep `header_count` in the candidate: the detected LOG4J rows are currently separated by header-count patterns of 14 and 16, and removing it previously cut LOG4J recall. Do not change the production threshold or the active model. Do not treat the training-split marker counts as an accuracy result; that requires the candidate run.
