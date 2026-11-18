# XSS recall limit on the payload candidate

The header-aware candidate remains the experimental model. No replacement was trained. A path or header-count feature could raise XSS recall on this split only by treating a payload-free `GET /forum` as an attack, and benign rows in the same split never use that path. That would memorize the dataset endpoint rather than detect XSS.

This split is the same seed-42 validation mask already used to build the payload candidates. It is not a fresh holdout. `REQUEST_ONLY_test.csv` was not opened.

## Reconciled counts

The candidate scores a row as malicious only when at least one of the seven structural flags is 1. On the validation mask its XSS false negatives are exactly the unflagged XSS rows.

| Group | Rows |
|---|---|
| Validation XSS | 931 |
| Markup in path, query, body, or user agent | 469 |
| No markup in those fields | 462 |
| Detected by the header-aware model | 471 |
| False negatives | 460 |

The two extra detections are plain forum requests whose header text sets some other structural flag. They are labeled XSS by the multiclass model. The other 460 set no flag. Reported XSS recall is 471/931 = 0.5059. Precision on that family is 1.0, and the validation false-positive rate is 0.0.

Training-mask XSS, same partition: 2,734 rows contain markup and 2,749 do not. Every XSS row in the partition has path `/forum`. Benign rows with that path: 0.

Reproduce the clean-text counts with:

```text
.venv-repair\Scripts\python.exe research\atrdf_payload_experiment\xss_unflagged_census.py
```

## What the raw records contain

The original JSON for this partition has three XSS URL templates and no others:

| Raw URL | Rows |
|---|---|
| `http://127.0.0.1:5000/forum` | 3,211 |
| `http://127.0.0.1:5000/forum?message=` plus an encoded `</p><script>alert()</script><p>` | 1,634 |
| `http://127.0.0.1:5000/forum?message=` plus an encoded `</h2><h2><script>alert(1)</script>` | 1,569 |

3,211 + 1,634 + 1,569 = 6,414, which is the full XSS class in the saved training partition (2,749 + 462 plain, and 2,734 + 469 with markup). The plain template is the false-negative group. Its query and body are empty. The clean CSV URL length matches the raw URL length, so preprocessing did not drop a query.

A token scan of the raw request, including every header value and the cookie, found no script tag, `alert(`, event handler, `javascript:`, SVG or iframe markup, HTML entity, or percent-encoded angle bracket on those plain rows. The same tokens are present on the encoded `message` rows, which the current `markup_script` flag already detects. Tokens that do appear on a plain row, such as `style=`, `src=`, or the letters `xss` inside a cookie, also appear on hundreds of benign rows.

The response body on these XSS records is the 24-character text `text/html; charset=utf-8`. It is not an XSS payload, and response text is not used as a feature.

Header names are ordinary browser headers. User agents vary and overlap normal browser agents. There are thousands of distinct cookie and timestamp combinations, which identifies individual rows rather than the attack.

## Decision

No new feature was added. The live lab XSS case carries a script tag in the comment body and is already blocked by `markup_script` at malicious probability 1.0. The header-aware seven-class artifacts were copied to `context_headers_backup/` and left unchanged. The experimental model that followed is the six-family candidate in `SIX_FAMILY_SCOPE.md`. Production models were not rewritten.
