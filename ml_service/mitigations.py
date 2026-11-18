"""Family mitigation catalog.

The `mitigation` string is the original project text (kept for telemetry
compatibility). `techniques` are the actions the gateway actually runs.
"""

CATALOG = {
    "SQL Injection": {
        "mitigation": "BLOCK + parameterized query path",
        "techniques": ["hard_block", "reject_untrusted_query", "no_sql_execution"],
    },
    "Cookie Injection": {
        "mitigation": "BLOCK + session validation",
        "techniques": ["hard_block", "invalidate_session_cookie", "require_reauthentication"],
    },
    "Log Forging": {
        "mitigation": "BLOCK / ALERT + structured logging",
        "techniques": ["hard_block", "redact_control_characters"],
    },
    "RCE": {
        "mitigation": "BLOCK (Execution: NOT PERFORMED)",
        "techniques": ["hard_block", "never_execute_command"],
    },
    "Directory Traversal": {
        "mitigation": "BLOCK + path validation",
        "techniques": ["hard_block", "reject_path_escape"],
    },
    "LOG4J": {
        "mitigation": "BLOCK / ALERT + safe logging",
        "techniques": ["hard_block", "drop_jndi_lookup", "redact_control_characters"],
    },
    "XSS": {
        "mitigation": "BLOCK / ALERT + safe rendering",
        "techniques": ["hard_block", "content_security_policy"],
    },
    "BOLA": {
        "mitigation": "BLOCK + authorization",
        "techniques": ["alert_and_authorize", "backend_owner_check"],
    },
    "BENIGN": {
        "mitigation": "ALLOW",
        "techniques": ["forward"],
    },
}

DEFAULT_BLOCK = {
    "mitigation": "BLOCK",
    "techniques": ["hard_block"],
}


def describe(predicted_class=None):
    if not predicted_class:
        return dict(DEFAULT_BLOCK)
    key = predicted_class.strip()
    if key in CATALOG:
        entry = CATALOG[key]
        return {"mitigation": entry["mitigation"], "techniques": list(entry["techniques"])}
    if key.upper() == "BOLA":
        entry = CATALOG["BOLA"]
        return {"mitigation": entry["mitigation"], "techniques": list(entry["techniques"])}
    return dict(DEFAULT_BLOCK)
