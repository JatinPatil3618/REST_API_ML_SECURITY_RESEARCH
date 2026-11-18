# LOG4J missed-row header diagnostic

Validation only. `REQUEST_ONLY_test.csv` was not opened. No model was fit, and no active artifact or threshold was changed.

The 203 rows are the Candidate A validation misses at threshold 0.50. The frozen production forest misses the same rows. Split: `REQUEST_ONLY_train.csv`, `test_size=0.1`, `random_state=42`, `stratify=is_malicious` (14,622 validation rows). Record ids are the alignment already checked against that training file.

```
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\log4j_false_negative_diagnostic\inspect_fn_header_patterns.py
.venv-repair\Scripts\python.exe research\atrdf_header_count_ablation\log4j_false_negative_diagnostic\redact_skeletons.py
```

## 1. Headers and value patterns on the 203 misses

Every missed row contains the adjacent character sequence `${jndi:` in exactly one header value. `jndi` begins immediately after `${`. No missed row uses a percent-encoded form of that prefix.

| Indicator | Rows | Percent of 203 |
|---|---:|---:|
| `${jndi:` in any header value | 203 | 100% |
| That sequence in `set-cookie` | 142 | 69.95% |
| That sequence in `sec-fetch-dest` | 61 | 30.05% |
| Value uses a `://` scheme form | 65 | 32.02% |
| Scheme token `ldaphttp` | 58 | 28.57% |
| Scheme token `ldaphttps` | 7 | 3.45% |
| Dotted name after `${jndi:` and no `://` in the first 80 characters | 138 | 67.98% |

`set-cookie` and `sec-fetch-dest` are both present on all 203 rows, as are `sec-fetch-site`, `accept-encoding`, and `user-agent`. The marker is not in those other three. There is no `cookie` header on any of the 203, and `cookie_present` is 0. `header_count` is 15 on all 203.

Placement:

- All 142 `set-cookie` hits sit after a semicolon already in the value. The marker does not start the value and does not sit directly after `=`.
- All 61 `sec-fetch-dest` hits are embedded after other text. One measured prefix is 8 characters; the value itself is not only the marker.
- Marker-value lengths run from 34 to 1,068 (median 577) across 174 distinct lengths. The tails differ. The shared part is the `${jndi:` prefix.

The 65 scheme-form rows use the concatenated tokens `ldaphttp://` and `ldaphttps://`. Those spellings are specific to this corpus. The other 138 rows still share `${jndi:` and then a dotted name.

## 2. Same indicators on benign rows and other attacks

Counts are validation rows only.

| Group | Rows | `${` and `jndi` together | `jndi` without `${` |
|---|---:|---:|---:|
| LOG4J missed | 203 | 203 (100%) | 0 |
| LOG4J detected | 116 | 116 (100%) | 0 |
| Benign | 11,475 | 0 (0%) | 3 (0.026%) |
| Cookie Injection | 614 | 4 (0.65%) | 0 |
| Directory Traversal | 323 | 4 (1.24%) | 0 |
| Log Forging | 304 | 1 (0.33%) | 0 |
| RCE | 333 | 1 (0.30%) | 0 |
| SQL Injection | 614 | 6 (0.98%) | 0 |
| XSS | 640 | 3 (0.47%) | 1 (0.16%) |

The 3 benign hits and the 1 XSS hit are `jndi` inside a longer token in `set-cookie`, with no `${`. The 19 non-LOG4J rows that do contain both tokens use the same header-value marker (4 Cookie Injection, 4 Directory Traversal, 1 Log Forging, 1 RCE, 6 SQL Injection, 3 XSS).

Header names are common on benign traffic. `set-cookie` and `sec-fetch-dest` are each present on 9,799 of 11,475 benign validation rows (85.39%). `accept-encoding` and `user-agent` are present on all 11,475. Presence of the header name does not separate the classes.

Detected LOG4J rows also all contain `${jndi:`, but the carrying header is usually different: `sec-fetch-site` 65, `accept-encoding` 41, `set-cookie` 7, `sec-fetch-dest` 3.

## 3. General header pattern, or a LOG4J marker?

The header names are ordinary browser headers. A rule on the name `set-cookie` or `sec-fetch-dest` would match most benign validation rows.

The value sequence `${jndi:` is a LOG4J lookup marker. It is present in every missed LOG4J row and in none of the 11,475 benign validation rows. It is uncommon but not absent in other attack labels (19 of 2,828 non-LOG4J attack rows). The concatenated scheme spellings `ldaphttp` and `ldaphttps` cover 65 of the 203 misses and look specific to how this dataset was built. They are not required for the shared prefix.

## 4. Sanitized examples

Prefixes and destinations are removed. Lengths are the measured value lengths.

- `set-cookie`: `[redacted prefix, 754 characters]${jndi:ldaphttp://[redacted]` (value length 854). This is the scheme-form family.
- `set-cookie`: `[redacted prefix, 671 characters]${jndi:[dotted name]/[redacted]` (value length 726). This is the dotted-name family. The prefix already contains a semicolon.
- `sec-fetch-dest`: `[8 characters of other text]${jndi:[dotted name]/[redacted]` (value length 47).

## 5. The 13 features discard this information

The live feature list keeps only `header_count`, `cookie_present`, and `user_agent_entropy` from headers. `cookie_present` is true only for a header named `cookie`. These misses use `set-cookie`, so that flag stays 0. User-Agent entropy does not read `set-cookie` or `sec-fetch-dest`. URL and body features do not read header values. Preprocessing keeps User-Agent, Host, and Content-Type text and drops the other header values before the 13 features are built.

On these 203 rows the kept header facts are the benign ones: `header_count` 15 and `cookie_present` 0. The lookup text is not represented.

## 6. Limits on generalization

This is a validation-split description. It says nothing about the locked test split, and it is not a trained-model result.

What this split supports:

- Every one of these 203 misses carries `${jndi:` in a header value.
- Requiring both `${` and `jndi` excludes the 3 benign validation rows that contain `jndi` only as part of a longer token.
- The header name alone is a poor indicator, because those names are present on about 85% of benign validation rows.

What this split does not support:

- That the same header names, or header count 15, will appear in live gateway traffic. These rows all have the dataset's long browser header bundle.
- That `ldaphttp://` or `ldaphttps://` will appear outside this corpus. Only 65 of 203 misses use those spellings.
- That an exact copy of any full header value will match unseen rows. The measured lengths have 174 distinct values.
- That the marker is exclusive to the LOG4J label. Nineteen validation rows with other attack labels carry the same token pair.
- That obfuscated or encoded variants would be caught. These 203 rows use the literal adjacent prefix. Encoded forms were not present here.
- That adding the indicator improves detection. That requires a separate candidate fit on the existing fit rows and a validation score. Production artifacts stay unchanged.
