# Dataset Ingestion and Specifications

## 1. ATRDF Dataset 4 (Input / Payload Manipulation)
- **Source**: Researched ATRDF Dataset 4 corpus.
- **Total Records**: 182,767 records.
  - Training Partition: 146,213 records (80.0%)
  - Testing Partition: 36,554 records (20.0%)
- **Class Breakdown**:
  - `Benign`: 143,431 records (78.48%) [Train: 114,744 | Test: 28,687]
  - `XSS`: 8,017 records (4.39%) [Train: 6,414 | Test: 1,603]
  - `SQL Injection`: 7,924 records (4.34%) [Train: 6,339 | Test: 1,585]
  - `Cookie Injection`: 7,742 records (4.24%) [Train: 6,194 | Test: 1,548]
  - `Log Forging`: 4,037 records (2.21%) [Train: 3,230 | Test: 807]
  - `RCE`: 3,944 records (2.16%) [Train: 3,155 | Test: 789]
  - `Directory Traversal`: 3,939 records (2.16%) [Train: 3,151 | Test: 788]
  - `LOG4J`: 3,733 records (2.04%) [Train: 2,986 | Test: 747]
- **Leakage Prevention**: Canonical request grouping hashes `(method, normalized_url, headers, body)` to ensure duplicate-equivalent requests never span across train and test partitions.
- **Feature Spaces**:
  - `REQUEST_ONLY` (13 Features - Live Gateway Target):
    `url_entropy`, `header_count`, `path_length`, `url_special_count`, `url_length`, `path_segment_count`, `cookie_present`, `query_length`, `url_digit_count`, `user_agent_entropy`, `query_parameter_count`, `request_body_entropy`, `request_body_digit_count`.
  - `FULL_25` (25 Features - Offline Comparison): Includes response-derived fields (`response_status_code`, `response_body_length`, `response_body_entropy`, `response_is_2xx`, `response_is_3xx`, `response_is_4xx`, `response_is_5xx`) and redundant combinations.
  - `REDUCED_18` (18 Features - Offline Ablation): Pruned based on Pearson correlation threshold (|r| > 0.90).
- **Constant Features Dropped**:
  `request_body_special_count`, `authorization_present`, `content_type_present`.

## 2. VAmPI BOLA Dataset (Access-Control / Behavioral Logic)
- **Source**: `vampi_v6_2_50000_ML_READY.csv`
- **Total Records**: 50,000 records across 5,750 unique user sessions.
- **Label Distribution**:
  - `NORMAL`: 25,000 requests (50.0%)
  - `BOLA`: 25,000 requests (50.0%)
- **Session-Level Partitioning**: Strict session-level splitting (80% train, 10% validation, 10% test) ensures that requests belonging to any session $S_i$ exist exclusively within one partition, eliminating temporal correlation leakage.
- **Feature Set ($W=10$)**:
  - Rolling Behavioral Features:
    `request_frequency`, `unique_objects_recent`, `object_switch`, `unique_owners_recent`, `owner_switch`, `cross_owner_count_recent`, `cross_owner_ratio_recent`, `same_owner_ratio_recent`, `same_object_repeat_ratio`, `time_since_previous_request`, `request_burst_rate`.
  - Contextual Session Features:
    `hour`, `session_length`, `request_index`.
  - **Excluded**: Explicit user identity (`authenticated_user`), object ID (`requested_object`), object owner (`object_owner`), and direct authorization match (`object_access_match`) are withheld from the model input to prevent superficial ID memorization.
