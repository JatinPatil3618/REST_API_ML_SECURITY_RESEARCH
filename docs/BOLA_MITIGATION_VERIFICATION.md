# BOLA mitigation verification

Authorization was tested on the running demo API at `http://127.0.0.1:5001`. The production gateway on port 8080 was not restarted or reconfigured. The ML score was not used as the authorization decision.

## Routes

Defined in `demo_api/server.js`:

| Route | Auth | Owner check |
|---|---|---|
| `POST /api/auth/login` | Password check against the seeded users | Not an object route |
| `GET /api/books/:id` | None for a normal catalog read | Returns the public book. `view=manage` and `access=edit` require a verified JWT, then allow only `book.owner` |
| `POST /api/books` | Verified JWT | New book owner is the token subject |
| `PUT /api/books/:id` | Verified JWT | 403 unless `book.owner` is the token subject |
| `DELETE /api/books/:id` | Verified JWT | 403 unless `book.owner` is the token subject |

The gateway BOLA route is `GET/POST/PUT/DELETE` matching `/api/books/` plus digits. That path selects the BOLA model. It does not decide ownership.

## Defect found

`authenticateToken` and `optionalAuth` treated `X-Authenticated-User` as a logged-in user when no Bearer token was present. With only that header set to `user02`, `PUT /api/books/201` returned 200 and changed the seeded title. The title was restored with user02's real token before the fix.

## Code changed

`demo_api/server.js` sets `req.user` only after `jwt.verify` succeeds. A missing token on a protected route returns 401. An invalid token returns 403. The custom user header is ignored. `view=manage` and `access=edit` on `GET /api/books/:id` use that same JWT check and then compare the token subject with `book.owner`. The demo API was restarted on port 5001.

## Results after the fix

Tokens came from `POST /api/auth/login` for `user01` and `user02`. A disposable book, id `111`, was created by `user01`, then deleted by `user01`. Seeded books `101` and `201` kept their original titles and owners.

| Case | Identity | HTTP | Backend effect | Data changed |
|---|---|---|---|---|
| Owner `GET /api/books/111` | user01 JWT | 200 | Read ran | No |
| user02 `GET /api/books/111` | user02 JWT | 200 | Public catalog read ran | No |
| user02 `GET /api/books/111?view=manage` | user02 JWT | 403 `BOLA_AUTHORIZATION_DENIED` | Private read refused | No |
| Owner `GET /api/books/111?view=manage` | user01 JWT | 200 | Read ran | No |
| `GET /api/books/111?view=manage` with only `X-Authenticated-User: user01` | None | 200 at that time | Returned the public record. Closed by the management-view check below | No |
| user02 `PUT /api/books/111` | user02 JWT | 403 `BOLA_PERMISSION_DENIED` | Update refused | No |
| user02 `DELETE /api/books/111` | user02 JWT | 403 `BOLA_PERMISSION_DENIED` | Delete refused | No |
| `PUT` with no token | None | 401 | Update refused | No |
| `PUT` with `Bearer not-a-jwt` | None | 403 | Update refused | No |
| `PUT /api/books/111` with only `X-Authenticated-User: user01` | None | 401 | Update refused | No |
| `PUT /api/books/201` with only `X-Authenticated-User: user02` | None | 401 | Update refused | No |
| Owner `PUT /api/books/111` | user01 JWT | 200 | Update ran, then the title was restored | Temporary, then restored |
| Owner `DELETE /api/books/111` | user01 JWT | 200 | Delete ran | Disposable book removed |

## Tests run

The write and delete sequence above was the earlier live check. The management-view regression is recorded in the next sections.

## Management view

`GET /api/books/:id?view=manage` and `GET /api/books/:id?access=edit` now require a verified JWT before any management response. A missing token returns 401 `Authentication required. Please log in.` An invalid token returns 403 `Session invalid or expired. Reauthentication required.` A verified non-owner returns 403 `BOLA_AUTHORIZATION_DENIED` with the book id and no title, author, description, rating, date, or owner. `X-Authenticated-User` is ignored. A normal `GET /api/books/:id` is still the public catalog record.

Live check on port 5001 used a disposable book `111` owned by user01. It was deleted afterward. Seeded books `101` and `201` were read only and kept their titles and owners.

| Case | Identity | HTTP | Private fields |
|---|---|---|---|
| `GET /api/books/111` | None | 200 public record | Catalog fields returned |
| `GET /api/books/111?view=manage` | user01 JWT | 200 | Owner record returned |
| `GET /api/books/111?view=manage` | user02 JWT | 403 `BOLA_AUTHORIZATION_DENIED` | None |
| `GET /api/books/111?access=edit` | user02 JWT | 403 `BOLA_AUTHORIZATION_DENIED` | None |
| `GET /api/books/111?view=manage` | No token | 401 | None |
| `GET /api/books/111?view=manage` | `Bearer not-a-jwt` | 403 session error | None |
| `GET /api/books/111?view=manage` | `X-Authenticated-User: user01` only | 401 | None |

## Tests run

`node --test test/book-management-access.test.js` from `demo_api` passed 7 tests and failed 0. That file covers the same management-view cases against an in-process app and its own disposable book. The live table above was then repeated on port 5001.

## Remaining issues

A normal `GET /api/books/:id` remains a public catalog read. Update and delete stay owner-only. The live tracker does not compute the training ownership features. That limit is stated in the detector section and in the status at the end. It is not an authorization bypass.

## Telemetry identity

`extractUsername` trusted `X-Authenticated-User` and otherwise labeled every Bearer token as `user01`. Telemetry and the BOLA session window used that guess.

`VerifiedIdentityResolver` now calls the demo API `GET /api/profile` with only the `Authorization` header. The username is recorded only when that verified response includes one. A missing token, an invalid token, a failed profile call, or a lone `X-Authenticated-User` header is recorded as `unknown`. The gateway does not decode the JWT. The demo API still performs `jwt.verify` and the owner comparison.

Command, from `gateway`, exit code 0:

`mvn -Dtest=VerifiedIdentityTest,MlUnavailableGatewayTest,DecisionEngineTest test`

```
VerifiedIdentityTest: Tests run: 5, Failures: 0, Errors: 0, Skipped: 0
DecisionEngineTest: Tests run: 5, Failures: 0, Errors: 0, Skipped: 0
MlUnavailableGatewayTest: Tests run: 4, Failures: 0, Errors: 0, Skipped: 0
Tests run: 14, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

`VerifiedIdentityTest` covers a verified `user01`, a verified `user02` while the spoof header says `user01`, a missing token, an invalid token, and a header-only spoof. The package command was `mvn -DskipTests package`, exit code 0. The jar was started only on port 8081.

## BOLA detector

The saved contract is the 14 names in `models/bola/feature_list.json`, in that order. `BolaSessionTracker.recordAndExtract` emits those names, and `ml_service` `predict_bola` scores `bola_rf_behavioral.joblib` at probability 0.50. The username is not a model input. `preprocessing.json` contains scaler values, but the training script fit the forest on the raw features and the live predict path does not apply that scaler.

The highest saved importances are `cross_owner_count_recent` (0.2063), `same_owner_ratio_recent` (0.1974), `cross_owner_ratio_recent` (0.1725), and `owner_switch` (0.1279). No script in this repository computes those columns. `docs/FEATURES.md` describes them in prose. `scripts/train_and_evaluate_all.py` reads `data/raw/vampi/vampi_v6_2_50000_ML_READY.csv` after the columns already exist.

On the aligned validation rows only, two definitions match the stored columns and the prose: `object_switch` is 1 when the current `requested_object` differs from the previous request, and `owner_switch` is 1 when the current `object_owner` differs from the previous request. That held for all 4,455 consecutive validation pairs. `same_owner_ratio_recent` equals `1 - cross_owner_ratio_recent` on those same pairs. `session_length` equals the number of rows in the session for all 5,030 validation rows.

The ownership features do not match a recoverable formula. Counting rows in the last 10 where `object_owner` differs from `authenticated_user` agreed with `cross_owner_count_recent` on 2,469 of 5,030 rows. Dividing that count by the current window length agreed with `cross_owner_ratio_recent` on 2,614 of 4,455 pairs. Dividing by the constant window size 10 agreed on 2,038 of 4,455. The live tracker also differs from the columns that do match: it sets `object_switch` and `owner_switch` when any switch occurs inside the window, and it caps `session_length` at 50. Owners come from a hardcoded map of seed ids `101`, `102`, `201`, `202`, `301`, `302`, `401`, `402`, `501`, and `502`. Any other id is `unknown` and is omitted from the cross-owner count. The demo API book list is trustworthy for the books it holds, but it does not supply the missing ratio formula. The tracker was not rewritten.

Validation scoring used the same CSV and the saved forest. The metadata file was written by `scripts/train_and_evaluate_all.py`. That script sets seed 42, draws one uniform value per ATRDF training row, and then shuffles VAmPI sessions. `REQUEST_ONLY_train.csv` has 146,213 data rows, so the replay consumed 146,213 draws before the shuffle. The test file was not opened. The earlier 4,925-row replay shuffled immediately after seed 42, which is a different procedure and is not the saved partition.

This replay selected 575 validation sessions and 5,030 rows (2,469 NORMAL, 2,561 BOLA), matching `validation_samples` in `models/bola/model_metadata.json`. Only those rows were scored, at threshold 0.50, with scikit-learn 1.2.2 from `.venv-repair`. Confusion matrix: TN 2469, FP 0, FN 0, TP 2561. BOLA precision, recall, and F1 were 1.0. NORMAL precision, recall, and F1 were 1.0. Those scores are on the precomputed CSV columns. They are not a score of the live gateway features. The model was not retrained. `results/tables/bola_results.csv` remains the training script's test-partition output and was not used here.

No gateway code changed for this check, so the 14 gateway tests were not run again. No new feature tests were added, because a test would have to freeze a formula the columns do not support.

## Identity check through the review gateway

Review gateway PID 24388 on port 8081, `--gateway.atrdf.profile=experimental-jndi`. Production PID 32176 on port 8080 was not restarted and still has no profile override. Experiment `EXP-BOLA-IDENTITY-8081`. These request IDs belong to this process. Disposable book `111`, title `BOLA identity probe`, owner `user01`, was created by REQ-1003 and deleted by `user01` in REQ-1012. A direct read then returned 404. Books `101` and `201` kept their titles and owners. After the denied update and delete, a direct read still showed title `BOLA identity probe` and owner `user01`.

| Case | HTTP | Telemetry identity | Backend |
|---|---|---|---|
| REQ-1004 owner `view=manage` | 200, title `BOLA identity probe`, owner `user01` | `user01`. ALERT, BOLA 0.73 / NORMAL 0.27, `backendReached` true, status 200 | Pass. Backend owner allow. The 0.73 score is an alert. |
| REQ-1005 user02 `view=manage` | 403 `BOLA_AUTHORIZATION_DENIED`, keys `error`, `code`, `bookId` | `user02`. ALERT, BOLA 0.73 / NORMAL 0.27, `backendReached` true, status 403 | Pass. Backend denial. No private fields. |
| REQ-1006 no token | 401 `Authentication required. Please log in.` | `unknown`. ALERT, BOLA 0.73, `backendReached` true, status 401 | Pass. Backend authentication denial. |
| REQ-1007 `Bearer not-a-jwt` | 403 `Session invalid or expired. Reauthentication required.` | `unknown`. ALLOW, NORMAL 0.55 / BOLA 0.45, `backendReached` true, status 403 | Pass. Backend rejected the token. |
| REQ-1008 `X-Authenticated-User: user01` only | 401 `Authentication required. Please log in.` | `unknown`. ALLOW, NORMAL 0.56 / BOLA 0.44, `backendReached` true, status 401 | Pass. The header was not an identity. |
| REQ-1009 user02 `PUT` | 403 `BOLA_PERMISSION_DENIED`, `requesting_user` `user02` | `user02`. ALLOW, NORMAL 0.55 / BOLA 0.45, `backendReached` true, status 403 | Pass. No data change. |
| REQ-1010 user02 `DELETE` | 403 `BOLA_PERMISSION_DENIED`, `requesting_user` `user02` | `user02`. ALLOW, NORMAL 0.56 / BOLA 0.44, `backendReached` true, status 403 | Pass. The book remained until the owner delete. |
| REQ-1011 `GET /api/books` | 200, `total` 11 while book `111` existed | `unknown` because no token was sent. ALLOW, BENIGN 0.99, `backendReached` true | Pass. Catalog reached the backend. |

Passed: verified `user01`, verified `user02`, missing token, invalid token, header spoof, owner read, cross-owner read, cross-owner update, cross-owner delete, and catalog. None of those authorization or identity cases failed.

## Status

BOLA authorization is verified. A verified JWT and the book owner decide management reads, updates, and deletes. Telemetry records that verified username, or `unknown` when verification fails. Production port 8080, the production models, and the 0.50 threshold were not changed.

The live BOLA detector is not a match for the training features. The 14 names and their order match, and the saved forest scores the aligned 5,030-row validation partition at 1.0 using the stored columns. The formulas for `cross_owner_count_recent` and `cross_owner_ratio_recent` cannot be recovered from the repository or from those columns. `BolaSessionTracker` was left as it is. A model BLOCK on book management and book mutation routes stays an alert, and the backend response is preserved. That alert is not the authorization control.
