# Feature Space Definition & Mathematical Specifications

## 1. Request-Only Pre-Response Feature Set (13 Features)
This feature space is designed for zero-latency, pre-response inline inference inside the Spring Boot Security Gateway. It operates strictly prior to forwarding requests to the protected service.

1. **`url_entropy`**: Shannon entropy of the raw request URL:
   $$H(S) = -\sum_{c \in \Sigma} p(c) \log_2 p(c)$$
   where $p(c) = \frac{\text{count}(c)}{|S|}$ and $H("") = 0.0$.
2. **`header_count`**: Integer count of all HTTP headers present in the incoming envelope.
3. **`path_length`**: Character count of the URI path segment excluding query string.
4. **`url_special_count`**: Count of reserved and syntactic punctuation symbols (`<`, `>`, `'`, `"`, `;`, `-`, `/`, `\`, `%`, `=`, `(`, `)`, `{`, `}`, `$`, ````, `&`, `|`, `!`, `?`).
5. **`url_length`**: Total character length of the raw URL.
6. **`path_segment_count`**: Count of non-empty path chunks separated by forward slashes.
7. **`cookie_present`**: Binary flag ($1$ if `Cookie` header exists and is non-empty, $0$ otherwise).
8. **`query_length`**: Total length of the query string.
9. **`url_digit_count`**: Count of ASCII numeric characters `0-9` within the URL.
10. **`user_agent_entropy`**: Shannon entropy of the `User-Agent` header.
11. **`query_parameter_count`**: Number of parsed query parameter keys.
12. **`request_body_entropy`**: Shannon entropy of the buffered request payload.
13. **`request_body_digit_count`**: Count of numeric digits within the request body.

---

## 2. BOLA Behavioral Feature Set ($W=10$)
Captures temporal, sequential access patterns within an authenticated session. To eliminate ID memorization, all explicit identifiers (`user_id`, `requested_object`) and direct authorization match flags are excluded from the model input.

1. **`request_frequency`**: Requests per second observed across the active session timeline.
2. **`unique_objects_recent`**: Count of distinct object identifiers requested within the rolling window.
3. **`object_switch`**: Binary indicator of whether the current target object differs from the previous request.
4. **`unique_owners_recent`**: Count of distinct resource owners targeted within the rolling window.
5. **`owner_switch`**: Binary indicator of whether the target owner differs from the previous request.
6. **`cross_owner_count_recent`**: Number of requests in the rolling window targeting objects owned by other entities.
7. **`cross_owner_ratio_recent`**: Ratio of cross-owner requests to total window size ($\frac{\text{cross\_owner}}{W}$).
8. **`same_owner_ratio_recent`**: Ratio of self-owned requests to total window size ($1 - \text{cross\_owner\_ratio}$).
9. **`same_object_repeat_ratio`**: Frequency of repetitive requests targeting the exact same object.
10. **`time_since_previous_request`**: Inter-arrival delta in seconds.
11. **`request_burst_rate`**: Instantaneous velocity ($\frac{1}{\Delta t}$).
12. **`hour`**: Integer hour of day ($0-23$).
13. **`session_length`**: Cumulative number of requests in current authenticated session.
14. **`request_index`**: Monotonic request index within the session.
