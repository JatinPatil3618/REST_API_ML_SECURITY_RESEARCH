"""
Canonical feature set definitions used across the entire project.
These must match exactly what the Java gateway extracts at runtime.
"""

# ============================================================
# ATRDF FEATURE SETS
# ============================================================

# 13 request-only features — used by the live gateway model
REQUEST_ONLY_13 = [
    "url_entropy",
    "header_count",
    "path_length",
    "url_special_count",
    "url_length",
    "path_segment_count",
    "cookie_present",
    "query_length",
    "url_digit_count",
    "user_agent_entropy",
    "query_parameter_count",
    "request_body_entropy",
    "request_body_digit_count",
]

# 25 full features (includes response features — offline only)
FULL_25 = [
    "url_length",
    "decoded_url_length",
    "path_length",
    "path_segment_count",
    "query_length",
    "query_parameter_count",
    "request_body_length",
    "request_body_digit_count",
    "request_body_entropy",
    "url_digit_count",
    "url_special_count",
    "url_entropy",
    "combined_request_length",
    "combined_request_entropy",
    "header_count",
    "cookie_present",
    "user_agent_length",
    "user_agent_entropy",
    # Response features (offline only)
    "response_status_code",
    "response_body_length",
    "response_body_entropy",
    "response_is_2xx",
    "response_is_3xx",
    "response_is_4xx",
    "response_is_5xx",
]

# Reduced 18 features (offline ablation)
REDUCED_18 = [f for f in FULL_25 if f not in [
    "decoded_url_length",      # redundant with url_length
    "combined_request_length", # derived from others
    "combined_request_entropy",# derived from others
    "user_agent_length",       # lower predictive value
    "request_body_length",     # covered by entropy + digit count
    "response_body_length",    # response-only
    "response_body_entropy",   # response-only
]]

# Label column
ATRDF_LABEL_COL = "label"
ATRDF_BINARY_COL = "is_malicious"

# Class labels (discovered from dataset)
ATRDF_CLASSES = [
    "Benign",
    "XSS",
    "SQL Injection",
    "Cookie Injection",
    "Log Forging",
    "RCE",
    "Directory Traversal",
    "LOG4J",
]

ATRDF_ATTACK_CLASSES = [c for c in ATRDF_CLASSES if c != "Benign"]

# ============================================================
# BOLA BEHAVIORAL FEATURE SET
# ============================================================
BOLA_BEHAVIORAL_FEATURES = [
    "request_frequency",
    "unique_objects_recent",
    "object_switch",
    "unique_owners_recent",
    "owner_switch",
    "cross_owner_count_recent",
    "cross_owner_ratio_recent",
    "same_owner_ratio_recent",
    "same_object_repeat_ratio",
    "time_since_previous_request",
    "request_burst_rate",
    "hour",
    "session_length",
    "request_index",
]

BOLA_LABEL_COL = "label"
BOLA_SESSION_COL = "session_id"
BOLA_CLASSES = {0: "NORMAL", 1: "BOLA"}

# ============================================================
# Explicitly excluded from BOLA training
# (prevent ID memorization / authorization leakage)
# ============================================================
BOLA_EXCLUDED_FEATURES = [
    "timestamp", "api", "host", "port",
    "authenticated_user", "object_owner",
    "object_access_match",           # this IS the authorization outcome
    "requested_object",              # object ID would memorize ownership
    "status_code",                   # response-derived
    "response_size",                 # response-derived
    "request_time_ms",               # response-derived
    "user_agent",                    # not a behavioral pattern
    "session_type", "attack_type", "attack_stage",
    "classification", "target",
    "attack_start_index",
]
