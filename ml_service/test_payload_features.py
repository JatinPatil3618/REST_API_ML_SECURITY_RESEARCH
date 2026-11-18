"""Parity checks for the seven payload features. Does not read the held-out test CSV."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from payload_features import PAYLOAD_FEATURES, payload_feature_map


CASES = [
    ("empty", {}, {name: 0 for name in PAYLOAD_FEATURES}),
    ("protocol search", {"query": "search=protocol"}, {name: 0 for name in PAYLOAD_FEATURES}),
    ("semicolon without a command", {"query": "ref=a+b;c"}, {name: 0 for name in PAYLOAD_FEATURES}),
    ("sql or", {"query": "q=%27%20OR%20%271%27=%271"}, {"sql_structure": 1}),
    ("sql select comment", {"query": "q=select%20*%20from%20books--"}, {"sql_structure": 1}),
    ("script", {"body": "<script>alert(1)</script>"}, {"markup_script": 1}),
    ("traversal encoded", {"path": "/api/books/..%2Fetc%2Fpasswd"}, {"path_traversal": 1}),
    ("command", {"query": "search=;%20cat%20/etc/passwd"}, {"command_chain": 1}),
    ("template", {"path": "/greet/%7B%7B7*7%7D%7D"}, {"command_chain": 1}),
    ("cookie word", {"path": "/cookie"}, {"cookie_signal": 1}),
    ("cookie authority", {"cookie_header": "admin=true"}, {"cookie_signal": 1}),
    ("log newline", {"query": "q=a%0Ab"}, {"log_control": 1}),
    ("jndi", {"body": "${jndi:ldap://example/a}"}, {"jndi_lookup": 1}),
    ("jndi encoded", {"query": "q=%24%7Bjndi%3Aldap"}, {"jndi_lookup": 1}),
    ("jndi header", {"header_values": ["${jndi:ldap://example/a}"]}, {"jndi_lookup": 1}),
    ("jndi set-cookie", {"lookup_header_values": ["${jndi:ldap://example/a}"]}, {"jndi_lookup": 1}),
    ("markup set-cookie", {"lookup_header_values": ["<script>alert(1)</script>"]}, {"markup_script": 1}),
    ("header traversal", {"header_values": ["../etc/passwd"]}, {"path_traversal": 1}),
    ("forum path without markup", {"path": "/forum", "user_agent": "Mozilla/5.0"}, {}),
    (
        "forum message script",
        {"path": "/forum", "query": "message=%3Cscript%3Ealert()%3C%2Fscript%3E"},
        {"markup_script": 1},
    ),
    (
        "set-cookie title stays benign",
        {"lookup_header_values": ["ck=1; Domain=example.com/How-To-Select-a-Surgeon---Part-1.html"]},
        {},
    ),
    (
        "generic header title is sql",
        {"header_values": ["ck=1; Domain=example.com/How-To-Select-a-Surgeon---Part-1.html"]},
        {"sql_structure": 1},
    ),
]


def test_cases():
    for name, kwargs, expected in CASES:
        actual = payload_feature_map(**kwargs)
        for feature in PAYLOAD_FEATURES:
            want = expected.get(feature, 0)
            if actual[feature] != want:
                raise SystemExit(f"{name} {feature}={actual[feature]} expected {want} {actual}")
    print("payload feature cases passed", len(CASES))


if __name__ == "__main__":
    test_cases()
