import React, { useState, useEffect } from 'react';

const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8080';

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
  const [token, setToken] = useState('');
  const [mitigation, setMitigation] = useState(null);
  
  const [books, setBooks] = useState([]);
  const [selectedBook, setSelectedBook] = useState(null);
  const [bookComments, setBookComments] = useState([]);
  const [newCommentText, setNewCommentText] = useState('');
  
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);
  
  const [requestHistory, setRequestHistory] = useState([]);

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
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
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
        openMitigation(resp, data, data.error || 'The catalog request was stopped.');
      }
    } catch (err) {
      logHistory('GET', url, 0, 'FAIL', Math.round(performance.now() - start), 'ERR', err.message);
      setStatusMessage({ type: 'error', text: 'The security gateway is unreachable. Please ensure it is running.' });
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

  const signIn = async (username) => {
    const password = import.meta.env.VITE_LAB_PASSWORD;
    if (!password) return null;
    const resp = await fetch(`${GATEWAY_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.token || null;
  };

  const mitigationLabel = (resp, data) => {
    const header = resp && resp.headers.get('X-Mitigation-Action');
    if (header) return header;
    if (data.code === 'BOLA_AUTHORIZATION_DENIED' || data.code === 'BOLA_PERMISSION_DENIED') {
      return 'ALERT + backend authorization';
    }
    return data.mitigation || 'Recorded';
  };

  const openMitigation = (resp, data, summary) => {
    setMitigation({
      summary,
      status: resp ? resp.status : 0,
      decision: resp ? (resp.headers.get('X-Security-Decision') || 'BLOCK') : 'FAIL',
      mitigation: resp ? mitigationLabel(resp, data) : 'Unavailable',
      techniques: resp ? (resp.headers.get('X-Mitigation-Techniques') || (Array.isArray(data.mitigation_techniques) ? data.mitigation_techniques.join(', ') : '')) : '',
      code: data.code || data.error || 'Denied',
      requestId: resp ? (resp.headers.get('X-Request-Id') || '') : ''
    });
  };

  useEffect(() => {
    let live = true;
    setToken('');
    signIn(currentUser).then((next) => {
      if (!live) return;
      setToken(next || '');
      if (!next) {
        setMitigation({
          summary: 'Sign-in did not complete, so management access cannot be checked.',
          status: 0,
          decision: 'FAIL',
          mitigation: 'Authentication required',
          code: 'SIGN_IN',
          requestId: ''
        });
      }
    });
    return () => { live = false; };
  }, [currentUser]);

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
      const resp = await fetch(`${GATEWAY_URL}/api/comments/book/${book.id}`);
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
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
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
        openMitigation(resp, data, data.error || 'The comment was stopped.');
      }
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    }
  };

  const openManagement = async (book) => {
    const start = performance.now();
    const url = `${GATEWAY_URL}/api/books/${book.id}?view=manage`;
    try {
      const resp = await fetch(url, {
        headers: token ? { 'Authorization': `Bearer ${token}` } : {}
      });
      const duration = Math.round(performance.now() - start);
      const reqId = resp.headers.get('X-Request-Id') || 'REQ-LOCAL';
      const dec = resp.headers.get('X-Security-Decision') || (resp.ok ? 'ALLOW' : 'BLOCK');
      const data = await resp.json().catch(() => ({}));
      logHistory('GET', url, resp.status, dec, duration, reqId, resp.ok ? 'Owner management read' : (data.error || 'Management denied'));
      if (resp.ok) {
        setMitigation({
          summary: `${currentUser} owns book ${book.id}. The catalog returned the management record. Nothing was changed.`,
          status: resp.status,
          decision: dec,
          mitigation: resp.headers.get('X-Mitigation-Action') || 'Owner access',
          code: 'OWNER_ALLOW',
          requestId: reqId
        });
      } else {
        const denied = data.code === 'BOLA_AUTHORIZATION_DENIED' || data.code === 'BOLA_PERMISSION_DENIED';
        openMitigation(
          resp,
          data,
          denied
            ? `${currentUser} cannot open book ${book.id}. ${data.error || 'It belongs to another user.'} The book was not changed.`
            : (data.error || 'Management access was stopped. The book was not changed.')
        );
      }
    } catch (err) {
      setStatusMessage({ type: 'error', text: err.message });
    }
  };

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
                  All catalog operations are inspected by the security gateway.
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
                          style={{ flex: 1 }}
                          disabled={!token}
                          onClick={() => openManagement(b)}
                        >
                          Manage
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* 2. REQUEST HISTORY VIEW */}
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
                        No requests logged yet. Search or open a book to record catalog requests.
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
              <p style={{ marginTop: '0.5rem' }}>• <strong>Session:</strong> {token ? 'Signed in' : 'Signing in'}</p>
            </div>
          </div>
        )}

        {/* BOOK DETAILS & COMMENTS MODAL */}
        {mitigation && (
          <div className="modal-overlay" onClick={() => setMitigation(null)}>
            <div className="modal-content mitigation-modal" role="dialog" aria-modal="true" aria-labelledby="mitigation-title" onClick={(e) => e.stopPropagation()}>
              <h2 id="mitigation-title">Mitigation</h2>
              <p>{mitigation.summary}</p>
              <dl className="mitigation-facts">
                <dt>HTTP</dt>
                <dd>{mitigation.status || 'Unavailable'}</dd>
                <dt>Decision</dt>
                <dd>{mitigation.decision}</dd>
                <dt>Action</dt>
                <dd>{mitigation.mitigation}</dd>
                {mitigation.techniques ? (
                  <>
                    <dt>Techniques</dt>
                    <dd>{mitigation.techniques}</dd>
                  </>
                ) : null}
                <dt>Result</dt>
                <dd>{mitigation.code}</dd>
                <dt>Request</dt>
                <dd>{mitigation.requestId || 'Unavailable'}</dd>
              </dl>
              <button type="button" className="btn btn-primary" onClick={() => setMitigation(null)}>Close</button>
            </div>
          </div>
        )}

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
                      placeholder="Add a comment..."
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
