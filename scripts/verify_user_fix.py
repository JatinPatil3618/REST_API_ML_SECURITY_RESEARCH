import urllib.request
import json

browser_headers = {
    'Host': 'localhost:8080',
    'Connection': 'keep-alive',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.9',
    'Origin': 'http://localhost:5173',
    'Referer': 'http://localhost:5173/',
    'X-Authenticated-User': 'user01',
    'Authorization': 'Bearer dummy-token-user01'
}

test_urls = [
    ('All Books', 'http://localhost:8080/api/books'),
    ('Search Science', 'http://localhost:8080/api/books?search=science'),
    ('Search Maths', 'http://localhost:8080/api/books?search=maths'),
    ('Category Engineering', 'http://localhost:8080/api/books?category=Engineering')
]

for label, url in test_urls:
    try:
        req = urllib.request.Request(url, headers=browser_headers)
        res = urllib.request.urlopen(req)
        data = json.loads(res.read().decode())
        books = data.get('books', [])
        print(f"[PASS] {label:22} -> HTTP {res.status}, Books Count: {len(books)}")
        for b in books:
            print(f"       * [{b['id']}] {b['title']} (Category: {b['category']})")
    except Exception as e:
        print(f"[FAIL] {label:22} -> {e}")
