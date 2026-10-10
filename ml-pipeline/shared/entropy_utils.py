"""
Shared entropy utility — identical formula used in both Python training
and expected from the Java gateway feature extractor.

Shannon entropy: H(S) = -sum(p(c) * log2(p(c))) for each character c in S
If string is empty: H(S) = 0.0
"""

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy (base-2) of a string.
    
    Args:
        s: Input string
    Returns:
        Entropy value in bits. Returns 0.0 for empty strings.
    """
    if not s:
        return 0.0
    
    n = len(s)
    counts = Counter(s)
    entropy = 0.0
    
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    
    return entropy


def count_digits(s: str) -> int:
    """Count digit characters (0-9) in a string."""
    return sum(1 for c in s if c.isdigit())


def count_special_chars(s: str) -> int:
    """
    Count special characters in URL as defined in project specification.
    Special chars: all non-alphanumeric, non-space characters
    """
    SPECIAL = set("!@#$%^&*()_+-=[]{}|;':\",./<>?\\`~")
    return sum(1 for c in s if c in SPECIAL)


# ---------------------------------------------------------------------------
# Parity test vectors — Java gateway must produce matching values
# These are used by scripts/parity_test.py
# ---------------------------------------------------------------------------
PARITY_TEST_VECTORS = [
    {
        "name": "simple_benign_url",
        "url": "/api/books/101",
        "expected_url_entropy": shannon_entropy("/api/books/101"),
        "expected_url_length": len("/api/books/101"),
        "expected_url_digit_count": count_digits("/api/books/101"),
        "expected_path_segment_count": 3,  # api, books, 101
    },
    {
        "name": "xss_url",
        "url": "/api/comments/book/101?q=<script>alert(1)</script>",
        "expected_url_entropy": shannon_entropy("/api/comments/book/101?q=<script>alert(1)</script>"),
        "expected_url_special_count": count_special_chars("/api/comments/book/101?q=<script>alert(1)</script>"),
    },
    {
        "name": "empty_string",
        "url": "",
        "expected_url_entropy": 0.0,
    },
]


if __name__ == "__main__":
    print("=== Entropy Parity Test Vectors ===")
    for vec in PARITY_TEST_VECTORS:
        print(f"\n{vec['name']}:")
        print(f"  url: {vec.get('url','')!r}")
        print(f"  entropy: {shannon_entropy(vec.get('url','')):.6f}")
        print(f"  digits: {count_digits(vec.get('url',''))}")
        print(f"  special: {count_special_chars(vec.get('url',''))}")
