"""Payload-structure features for the experimental ATRDF candidate.

The functions read request text only. Labels, test-case ids, and expected
predictions are not inputs. The review six-family forest uses the 10
request statistics that are not family proxies. header_count,
url_special_count, and cookie_present stay in the extracted payload for
production 13-feature scoring only. These seven flags are review-rule
inputs, not that forest's features.
"""

import re
from urllib.parse import unquote, unquote_plus

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
FAMILY_PROXY_FEATURES = [
    "header_count",
    "url_special_count",
    "cookie_present",
]
REQUEST_ONLY_10 = [name for name in REQUEST_ONLY_13 if name not in FAMILY_PROXY_FEATURES]
PAYLOAD_FEATURES = [
    "sql_structure",
    "markup_script",
    "path_traversal",
    "command_chain",
    "cookie_signal",
    "log_control",
    "jndi_lookup",
]
PAYLOAD_MODEL_FEATURES = REQUEST_ONLY_13 + PAYLOAD_FEATURES
PROFILE_PAYLOAD = "experimental-payload"
PAYLOAD_THRESHOLD = 0.50
# Indices 0-5 match the historical seven-class order. XSS is not an evaluated class.
SCOPED_ATTACKS = [
    "Cookie Injection",
    "Directory Traversal",
    "LOG4J",
    "Log Forging",
    "RCE",
    "SQL Injection",
]

SQL_OR = re.compile(r"'\s*or\s+", re.IGNORECASE)
SQL_SELECT_COMMENT = re.compile(r"\bselect\b", re.IGNORECASE)
SQL_LINE_COMMENT = re.compile(r"--")
SQL_UNION = re.compile(r"\bunion\s+select\b", re.IGNORECASE)
MARKUP = re.compile(r"<\s*script\b|\balert\s*\(|\bon(?:error|load|click|mouseover)\s*=", re.IGNORECASE)
TRAVERSAL = re.compile(r"\.\./|\.\.\\")
COMMAND = re.compile(r"(?:;|\||&&|`)\s*(?:cat|nc|bash|sh|cmd|powershell|wget|curl)\b", re.IGNORECASE)
TEMPLATE = re.compile(r"\{\{|__globals__|__builtins__|__import__", re.IGNORECASE)
COOKIE_WORD = re.compile(r"cookie", re.IGNORECASE)
LOG_CONTROL = re.compile("%0a|%0d|\r|\n|\\\\r|\\\\n", re.IGNORECASE)
JNDI = re.compile(r"\$\{\s*jndi\s*:", re.IGNORECASE)
COOKIE_AUTHORITY = {"admin", "role"}


def unfold(value):
    """Raw text plus percent-decoding, a second decode, and form decoding."""
    raw = "" if value is None else str(value)
    once = unquote(raw)
    twice = unquote(once)
    form = unquote_plus(raw)
    return "\x01".join((raw, once, twice, form))


def content_text(path, query, body, user_agent, header_values):
    parts = [path, query, body, user_agent]
    if header_values:
        parts.extend(header_values)
    return "\x01".join(unfold(part) for part in parts)


def header_text(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(header_text(item) for item in value)
    return str(value)


def split_stored_headers(headers):
    """Split raw request headers the same way the live gateway does.

    User-Agent stays in its own field. Cookie contributes names only.
    Set-Cookie values are returned separately because benign session tokens
    in this corpus collide with the broader patterns, while lookup and markup
    markers in those values do not.
    """
    values = []
    lookup_values = []
    cookie = ""
    for name, value in (headers or {}).items():
        low = str(name).lower()
        text = header_text(value)
        if low == "cookie":
            cookie = text
        elif low == "user-agent":
            continue
        elif low == "set-cookie":
            lookup_values.append(text)
        else:
            values.append(text)
    return values, lookup_values, cookie


def cookie_names(cookie_header):
    if not cookie_header:
        return []
    names = []
    for part in str(cookie_header).split(";"):
        name = part.split("=", 1)[0].strip().lower()
        if name:
            names.append(name)
    return names


def payload_feature_map(path="", query="", body="", user_agent="", header_values=None, cookie_header="",
                        lookup_header_values=None):
    """Seven structural flags. header_values must already exclude test-metadata headers.

    lookup_header_values are scanned only for markup and JNDI. The live gateway
    puts Set-Cookie there. The other five flags read path, query, body, user
    agent, and the remaining header values.
    """
    text = content_text(path, query, body, user_agent, header_values)
    sensitive = text
    if lookup_header_values:
        sensitive = text + "\x01" + "\x01".join(unfold(part) for part in lookup_header_values)
    names = cookie_names(cookie_header)
    sql = bool(SQL_OR.search(text) or SQL_UNION.search(text) or (SQL_SELECT_COMMENT.search(text) and SQL_LINE_COMMENT.search(text)))
    return {
        "sql_structure": int(sql),
        "markup_script": int(bool(MARKUP.search(sensitive))),
        "path_traversal": int(bool(TRAVERSAL.search(text))),
        "command_chain": int(bool(COMMAND.search(text) or TEMPLATE.search(text))),
        "cookie_signal": int(bool(COOKIE_WORD.search(text) or any(name in COOKIE_AUTHORITY for name in names))),
        "log_control": int(bool(LOG_CONTROL.search(text))),
        "jndi_lookup": int(bool(JNDI.search(sensitive))),
    }
