"""Header-value marker used only by the experimental 14-feature ATRDF profile."""

import re
from urllib.parse import unquote

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
JNDI_LOOKUP_MARKER = "jndi_lookup_marker"
EXPERIMENTAL_FEATURES = REQUEST_ONLY_13 + [JNDI_LOOKUP_MARKER]
EXPERIMENTAL_THRESHOLD = 0.50
PROFILE_PRODUCTION = "production"
PROFILE_EXPERIMENTAL = "experimental-jndi"
ATTACK_CLASSES = [
    "Cookie Injection",
    "Directory Traversal",
    "LOG4J",
    "Log Forging",
    "RCE",
    "SQL Injection",
    "XSS",
]
JNDI_LOOKUP_PATTERN = re.compile(r"\$\{\s*jndi\s*:", re.IGNORECASE)


def value_has_jndi_lookup(value):
    text = "" if value is None else str(value)
    if JNDI_LOOKUP_PATTERN.search(text):
        return True
    decoded = unquote(text)
    return decoded != text and JNDI_LOOKUP_PATTERN.search(decoded) is not None


def jndi_lookup_marker(header_values):
    """1 when any header value matches the lookup pattern. Labels are not read."""
    for value in header_values:
        if value_has_jndi_lookup(value):
            return 1
    return 0
