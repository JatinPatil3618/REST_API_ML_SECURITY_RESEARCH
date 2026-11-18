"""Golden vectors for the ATRDF request-only feature contract.

Expected values come from ml-pipeline/shared/entropy_utils.py and
feature_definitions.REQUEST_ONLY_13. They are not derived from the Java extractor.
"""

import json
import os
import sys
import unittest
from urllib.parse import unquote_plus

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "ml-pipeline", "shared"))

from entropy_utils import count_digits, count_special_chars, shannon_entropy
from feature_definitions import REQUEST_ONLY_13

FEATURE_LIST_PATH = os.path.join(ROOT, "models", "atrdf", "feature_list_request_only.json")

NORMAL_URL = "http://api.example.com:8080/api/books/101"
LOCALHOST_URL = "http://localhost:8080/api/books"
QUERY_URL = "http://localhost:8080/api/books?search=science&category=Engineering"
PUNCT_URL = "http://localhost:8080/api/comments/book/101?q=<script>alert(1)</script>"
SPACE_URL = "http://localhost:8080/api/search?q=a b"
AT_URL = "http://localhost:8080/api/search?email=a@b.com"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
COMMENT_BODY = '{"text": "<script>alert(1)</script>"}'


def gateway_entropy(value: str) -> float:
    """Six-decimal rounding used by the published parity vectors."""
    return round(shannon_entropy(value or ""), 6)


def is_test_metadata_header(name: str) -> bool:
    header = name.lower()
    return (
        header == "x-ground-truth"
        or header.startswith("x-test-")
        or header.startswith("x-experiment-")
    )


def header_count(headers) -> int:
    return sum(1 for name in headers if not is_test_metadata_header(name))


def query_parameter_count(query: str) -> int:
    """Unique form-decoded query keys. Blank values and valueless flags count."""
    if not query:
        return 0
    keys = set()
    for part in query.split("&"):
        if part == "":
            continue
        raw_key = part.split("=", 1)[0]
        key = unquote_plus(raw_key)
        if key != "":
            keys.add(key)
    return len(keys)


def path_segment_count(path: str) -> int:
    return sum(1 for segment in path.split("/") if segment != "")


def extract_request_features(full_url, path, query, headers, user_agent, cookie, body):
    query = query or ""
    user_agent = user_agent or ""
    cookie = cookie or ""
    body = body or ""
    features = {
        "url_entropy": gateway_entropy(full_url),
        "header_count": header_count(headers),
        "path_length": len(path),
        "url_special_count": count_special_chars(full_url),
        "url_length": len(full_url),
        "path_segment_count": path_segment_count(path),
        "cookie_present": 1 if cookie.strip() else 0,
        "query_length": len(query),
        "url_digit_count": count_digits(full_url),
        "user_agent_entropy": gateway_entropy(user_agent),
        "query_parameter_count": query_parameter_count(query),
        "request_body_entropy": gateway_entropy(body),
        "request_body_digit_count": count_digits(body),
    }
    if list(features) != REQUEST_ONLY_13:
        raise AssertionError("feature order drifted from REQUEST_ONLY_13")
    return features


LEGIT_HEADERS = [
    "Host",
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Connection",
    "Authorization",
]


class AtrdfFeatureGoldenTests(unittest.TestCase):
    def test_feature_names_match_saved_list(self):
        with open(FEATURE_LIST_PATH, encoding="utf-8") as handle:
            saved = json.load(handle)
        self.assertEqual(saved, REQUEST_ONLY_13)
        self.assertEqual(len(REQUEST_ONLY_13), 13)

    def test_punctuation_definition_rejects_space_and_includes_canonical_symbols(self):
        specials = set("!@#$%^&*()_+-=[]{}|;':\",./<>?\\`~")
        self.assertNotIn(" ", specials)
        for char in "@#.:_+":
            self.assertIn(char, specials)
        self.assertEqual(count_special_chars("a b"), 0)
        self.assertEqual(count_special_chars("a@b.com"), 2)
        self.assertEqual(
            count_special_chars(PUNCT_URL),
            sum(1 for char in PUNCT_URL if char in specials),
        )

    def test_normal_url_uses_actual_digits_and_header_count(self):
        headers = ["Host", "User-Agent", "Accept"]
        features = extract_request_features(
            NORMAL_URL,
            "/api/books/101",
            "",
            headers,
            USER_AGENT,
            "",
            "",
        )
        self.assertEqual(features["url_length"], len(NORMAL_URL))
        self.assertEqual(features["path_length"], len("/api/books/101"))
        self.assertEqual(features["path_segment_count"], 3)
        self.assertEqual(features["url_digit_count"], count_digits(NORMAL_URL))
        self.assertEqual(features["url_digit_count"], 7)
        self.assertEqual(features["header_count"], 3)
        self.assertNotEqual(features["header_count"], 15)
        self.assertEqual(features["query_parameter_count"], 0)
        self.assertEqual(features["query_length"], 0)
        self.assertEqual(features["cookie_present"], 0)
        self.assertEqual(features["url_special_count"], count_special_chars(NORMAL_URL))
        self.assertEqual(features["url_entropy"], gateway_entropy(NORMAL_URL))

    def test_localhost_url_does_not_add_six_digits(self):
        features = extract_request_features(
            LOCALHOST_URL,
            "/api/books",
            "",
            ["Host", "User-Agent"],
            USER_AGENT,
            "",
            "",
        )
        actual_digits = count_digits(LOCALHOST_URL)
        self.assertEqual(actual_digits, 4)
        self.assertEqual(features["url_digit_count"], actual_digits)
        self.assertNotEqual(features["url_digit_count"], actual_digits + 6)
        self.assertEqual(features["header_count"], 2)

    def test_query_string_counts_unique_keys_not_body_fields(self):
        query = "search=science&category=Engineering"
        features = extract_request_features(
            QUERY_URL,
            "/api/books",
            query,
            LEGIT_HEADERS,
            USER_AGENT,
            "",
            "b=2&c=3",
        )
        self.assertEqual(features["query_length"], len(query))
        self.assertEqual(features["query_parameter_count"], 2)
        self.assertEqual(features["url_length"], len(QUERY_URL))
        self.assertEqual(features["request_body_digit_count"], count_digits("b=2&c=3"))
        self.assertEqual(query_parameter_count("a=1&a=2&flag"), 2)
        self.assertEqual(query_parameter_count("a=1&&b=2"), 2)
        self.assertEqual(query_parameter_count("a%5B%5D=1&a%5B%5D=2"), 1)
        self.assertEqual(query_parameter_count("q=a+b"), 1)
        self.assertEqual(unquote_plus("a%5B%5D"), "a[]")

    def test_header_counts_are_not_remapped(self):
        four = ["Host", "User-Agent", "Accept", "Connection"]
        six = LEGIT_HEADERS
        eight = LEGIT_HEADERS + ["Sec-Fetch-Site", "Sec-CH-UA"]
        self.assertEqual(header_count(four), 4)
        self.assertEqual(header_count(six), 6)
        self.assertEqual(header_count(eight), 8)
        self.assertNotEqual(header_count(six), 15)
        self.assertNotEqual(header_count(four), 5)

    def test_test_metadata_does_not_change_features(self):
        base = extract_request_features(
            LOCALHOST_URL,
            "/api/books",
            "",
            LEGIT_HEADERS,
            USER_AGENT,
            "",
            "",
        )
        normal = extract_request_features(
            LOCALHOST_URL,
            "/api/books",
            "",
            LEGIT_HEADERS + ["X-Test-Case-Id", "X-Experiment-Id", "X-Ground-Truth"],
            USER_AGENT,
            "",
            "",
        )
        sqli = extract_request_features(
            LOCALHOST_URL,
            "/api/books",
            "",
            LEGIT_HEADERS + ["X-Test-Case-Id"],
            USER_AGENT,
            "",
            "",
        )
        self.assertEqual(base, normal)
        self.assertEqual(base, sqli)
        self.assertEqual(base["header_count"], 6)

    def test_punctuation_and_space_vectors(self):
        punct = extract_request_features(
            PUNCT_URL,
            "/api/comments/book/101",
            "q=<script>alert(1)</script>",
            ["Host", "User-Agent"],
            USER_AGENT,
            "session=abc",
            COMMENT_BODY,
        )
        self.assertEqual(punct["url_special_count"], count_special_chars(PUNCT_URL))
        self.assertEqual(punct["path_segment_count"], 4)
        self.assertEqual(punct["cookie_present"], 1)
        self.assertEqual(punct["query_parameter_count"], 1)
        self.assertEqual(punct["request_body_entropy"], gateway_entropy(COMMENT_BODY))
        self.assertGreater(punct["url_special_count"], 0)

        spaced = extract_request_features(
            SPACE_URL,
            "/api/search",
            "q=a b",
            ["Host"],
            "",
            "",
            "",
        )
        without_space = SPACE_URL.replace(" ", "")
        self.assertEqual(
            spaced["url_special_count"],
            count_special_chars(without_space),
        )
        self.assertEqual(
            count_special_chars(AT_URL),
            count_special_chars(AT_URL.replace("@", "a")) + 1,
        )
        self.assertGreater(
            count_special_chars(AT_URL),
            count_special_chars(AT_URL.replace("@", "a").replace(".", "a")),
        )


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AtrdfFeatureGoldenTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    vectors = {
        "normal": extract_request_features(
            NORMAL_URL, "/api/books/101", "", ["Host", "User-Agent", "Accept"], USER_AGENT, "", ""
        ),
        "localhost": extract_request_features(
            LOCALHOST_URL, "/api/books", "", ["Host", "User-Agent"], USER_AGENT, "", ""
        ),
        "query": extract_request_features(
            QUERY_URL,
            "/api/books",
            "search=science&category=Engineering",
            LEGIT_HEADERS,
            USER_AGENT,
            "",
            "b=2&c=3",
        ),
        "punctuation": extract_request_features(
            PUNCT_URL,
            "/api/comments/book/101",
            "q=<script>alert(1)</script>",
            ["Host", "User-Agent"],
            USER_AGENT,
            "session=abc",
            COMMENT_BODY,
        ),
        "space": extract_request_features(
            SPACE_URL, "/api/search", "q=a b", ["Host"], "", "", ""
        ),
        "at_sign": {
            "url_special_count": count_special_chars(AT_URL),
            "url_digit_count": count_digits(AT_URL),
            "url_length": len(AT_URL),
            "url_entropy": gateway_entropy(AT_URL),
        },
    }
    print("GOLDEN_JSON")
    print(json.dumps(vectors, indent=2, sort_keys=True))
    sys.exit(0 if result.wasSuccessful() else 1)
