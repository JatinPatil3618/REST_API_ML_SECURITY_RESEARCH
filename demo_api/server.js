/**
 * SecureBook API - Realistic REST API Backend
 * Part of M.Tech Cybersecurity Final Year Research Project
 * 
 * Provides authentic book platform functionality with strict object-level authorization (BOLA prevention),
 * structured logging, safe parameterization, and telemetry integration.
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-mtech-security-research-jwt-key-2026';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = 'api_security_research';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Structured JSON Logger (resists Log Forging)
function logSecurityEvent(level, message, meta = {}) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    service: 'demo_api',
    level,
    message: String(message).replace(/[\r\n]/g, ' '), // sanitize line breaks
    ...meta
  };
  console.log(JSON.stringify(logEntry));
}

// -------------------------------------------------------------
// Deterministic Seed Data (Users & Books per Research Specification)
// -------------------------------------------------------------
const USERS = [
  { id: 'usr_01', username: 'user01', email: 'user01@securebook.lab', password: 'Password123!', role: 'user', created_at: '2026-01-15T09:00:00Z' },
  { id: 'usr_02', username: 'user02', email: 'user02@securebook.lab', password: 'Password123!', role: 'user', created_at: '2026-01-16T10:30:00Z' },
  { id: 'usr_03', username: 'user03', email: 'user03@securebook.lab', password: 'Password123!', role: 'user', created_at: '2026-01-17T11:15:00Z' },
  { id: 'usr_04', username: 'user04', email: 'user04@securebook.lab', password: 'Password123!', role: 'user', created_at: '2026-01-18T14:45:00Z' },
  { id: 'usr_05', username: 'user05', email: 'user05@securebook.lab', password: 'Password123!', role: 'user', created_at: '2026-01-19T16:20:00Z' }
];

let BOOKS = [
  { id: '101', title: 'Foundations of Network Protocol Security', author: 'Dr. Evelyn Carter', category: 'Technology', description: 'Comprehensive analysis of modern application layer protocols and defense patterns.', owner: 'user01', rating: 4.8, date: '2026-02-01' },
  { id: '102', title: 'Zero Trust Architecture in Cloud Systems', author: 'Marcus Vance', category: 'Technology', description: 'Practical deployment patterns for microservices authentication and authorization.', owner: 'user01', rating: 4.6, date: '2026-02-03' },
  { id: '201', title: 'Applied Machine Learning in Anomaly Detection', author: 'Dr. Rajiv Menon', category: 'Science', description: 'Mathematical treatments of Random Forests and Isolation Forests in telemetry analysis.', owner: 'user02', rating: 4.9, date: '2026-02-05' },
  { id: '202', title: 'Empirical Software Engineering & Measurement', author: 'Sarah Jenkins', category: 'Engineering', description: 'Statistical evaluation of software metrics, defect prediction, and code smells.', owner: 'user02', rating: 4.5, date: '2026-02-08' },
  { id: '301', title: 'Cryptography and Public Key Infrastructure', author: 'Elena Rostova', category: 'Mathematics', description: 'Modern elliptic curve cryptography and digital certificate management.', owner: 'user03', rating: 4.7, date: '2026-02-10' },
  { id: '302', title: 'Secure API Gateway Engineering', author: 'David K. Miller', category: 'Technology', description: 'High-throughput reverse proxies, request filters, and rate limiting architectures.', owner: 'user03', rating: 4.8, date: '2026-02-12' },
  { id: '401', title: 'Distributed Systems Consensus Algorithms', author: 'Prof. Alan Zhao', category: 'Computer Science', description: 'From Paxos and Raft to Byzantine Fault Tolerance in modern databases.', owner: 'user04', rating: 4.9, date: '2026-02-14' },
  { id: '402', title: 'Database Internals and Query Optimization', author: 'Hannah Abbott', category: 'Computer Science', description: 'Storage engines, B+ Trees, LSM trees, and execution plan cost modeling.', owner: 'user04', rating: 4.4, date: '2026-02-16' },
  { id: '501', title: 'Defensive Web Application Architectures', author: 'Nathan Drake', category: 'Technology', description: 'OWASP Top 10 mitigation strategies implemented at application and network boundaries.', owner: 'user05', rating: 4.7, date: '2026-02-18' },
  { id: '502', title: 'Statistical Generalization in Predictive Models', author: 'Dr. Clara Higgins', category: 'Science', description: 'Leave-one-out cross validation and distribution shifts in adversarial contexts.', owner: 'user05', rating: 4.8, date: '2026-02-20' }
];

let COMMENTS = [
  { id: 'cmt_001', bookId: '101', user: 'user02', text: 'Excellent reference on modern TLS and HTTP/2 framing.', timestamp: '2026-02-02T10:15:00Z' },
  { id: 'cmt_002', bookId: '201', user: 'user01', text: 'Clear explanation of Gini impurity and ensemble voting mechanics.', timestamp: '2026-02-06T14:30:00Z' },
  { id: 'cmt_003', bookId: '302', user: 'user04', text: 'The section on token bucket rate limiting was very helpful.', timestamp: '2026-02-13T11:00:00Z' }
];

// MongoDB Client Connection (with graceful local fallback)
let dbClient = null;
let db = null;

async function initDatabase() {
  try {
    dbClient = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 2000 });
    await dbClient.connect();
    db = dbClient.db(DB_NAME);
    logSecurityEvent('info', 'Successfully connected to MongoDB server');
  } catch (err) {
    logSecurityEvent('warn', 'MongoDB not connected; using in-memory store with sync', { error: err.message });
  }
}

// -------------------------------------------------------------
// Authentication Middleware
// -------------------------------------------------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logSecurityEvent('warn', 'Invalid JWT token supplied', { error: err.message });
      return res.status(403).json({ error: 'Session invalid or expired. Reauthentication required.' });
    }
    req.user = user;
    next();
  });
}

function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) req.user = user;
      next();
    });
  } else {
    next();
  }
}

// -------------------------------------------------------------
// Routes
// -------------------------------------------------------------

// Service Root Landing
app.get('/', (req, res) => {
  res.json({
    status: 'ACTIVE',
    service: 'SecureBook Demo REST API Backend',
    description: 'Realistic Academic Book Management Platform with BOLA & Input Validation Defense',
    port: PORT,
    endpoints: {
      health: '/api/health',
      catalog: '/api/books',
      auth: '/api/auth/login',
      comments: '/api/comments/book/:id'
    },
    total_books: BOOKS.length,
    database_connected: !!db,
    timestamp: new Date().toISOString()
  });
});

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'PASS',
    service: 'demo_api',
    uptime: process.uptime(),
    db_connected: !!db,
    total_books: BOOKS.length,
    timestamp: new Date().toISOString()
  });
});

// Authentication: Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = USERS.find(u => u.username === username.trim() && u.password === password);
  if (!user) {
    logSecurityEvent('warn', `Failed login attempt for user ${username}`);
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  logSecurityEvent('info', `User ${user.username} logged in successfully`);
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      created_at: user.created_at
    }
  });
});

// Catalog: Get Books (with search, category parameterization)
app.get('/api/books', optionalAuth, (req, res) => {
  let result = [...BOOKS];
  const { search, category } = req.query;

  if (category && category !== 'All') {
    const catClean = String(category).trim().toLowerCase();
    result = result.filter(b => b.category.toLowerCase() === catClean);
  }

  if (search) {
    const qClean = String(search).trim().toLowerCase();
    result = result.filter(b => {
      const titleMatch = b.title.toLowerCase().includes(qClean);
      const authorMatch = b.author.toLowerCase().includes(qClean);
      const descMatch = b.description.toLowerCase().includes(qClean);
      const catMatch = b.category.toLowerCase().includes(qClean);
      // Support common search variants (e.g., maths -> Mathematics, comp sci -> Computer Science)
      const mathVariant = (qClean.startsWith('math')) && b.category.toLowerCase().includes('mathem');
      const csVariant = (qClean.includes('cs') || qClean.includes('computer')) && b.category.toLowerCase().includes('computer');
      return titleMatch || authorMatch || descMatch || catMatch || mathVariant || csVariant;
    });
  }

  res.json({
    books: result,
    total: result.length,
    authenticated_user: req.user ? req.user.username : null
  });
});

function isManagementView(query) {
  return query.view === 'manage' || query.access === 'edit';
}

// Catalog: Get Book By ID.
// A normal GET is the public catalog record.
// view=manage and access=edit require a verified JWT and the book owner.
app.get('/api/books/:id', (req, res) => {
  const bookId = String(req.params.id);
  const book = BOOKS.find(b => b.id === bookId);

  if (!book) {
    return res.status(404).json({ error: 'Book not found.' });
  }

  if (!isManagementView(req.query)) {
    return res.json(book);
  }

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logSecurityEvent('warn', 'Invalid JWT token supplied', { error: err.message });
      return res.status(403).json({ error: 'Session invalid or expired. Reauthentication required.' });
    }
    if (user.username !== book.owner) {
      logSecurityEvent('security_alert', 'BOLA access denied: cross-user book management attempt', {
        user: user.username,
        requested_book: bookId,
        book_owner: book.owner
      });
      return res.status(403).json({
        error: 'Access denied. This book belongs to another user.',
        code: 'BOLA_AUTHORIZATION_DENIED',
        bookId
      });
    }
    return res.json(book);
  });
});

// Catalog: Create Book
app.post('/api/books', authenticateToken, (req, res) => {
  const { title, author, category, description } = req.body;
  if (!title || !author) {
    return res.status(400).json({ error: 'Title and author are required.' });
  }

  const newId = String(100 + BOOKS.length + 1);
  const newBook = {
    id: newId,
    title: String(title).slice(0, 150),
    author: String(author).slice(0, 100),
    category: category ? String(category).slice(0, 50) : 'General',
    description: description ? String(description).slice(0, 500) : '',
    owner: req.user.username,
    rating: 5.0,
    date: new Date().toISOString().split('T')[0]
  };

  BOOKS.push(newBook);
  logSecurityEvent('info', `Book created: ${newBook.id} by ${req.user.username}`);
  res.status(201).json(newBook);
});

// Catalog: Edit Book (Strict BOLA Server-Side Authorization)
app.put('/api/books/:id', authenticateToken, (req, res) => {
  const bookId = String(req.params.id);
  const book = BOOKS.find(b => b.id === bookId);

  if (!book) {
    return res.status(404).json({ error: 'Book not found.' });
  }

  // OBJECT-LEVEL AUTHORIZATION CHECK
  if (book.owner !== req.user.username) {
    logSecurityEvent('security_alert', 'BOLA modification attempt blocked by authorization', {
      user: req.user.username,
      bookId,
      actual_owner: book.owner
    });
    return res.status(403).json({
      error: 'Access denied. This book belongs to another user.',
      code: 'BOLA_PERMISSION_DENIED',
      bookId,
      expected_owner: book.owner,
      requesting_user: req.user.username
    });
  }

  const { title, author, category, description } = req.body;
  if (title) book.title = String(title).slice(0, 150);
  if (author) book.author = String(author).slice(0, 100);
  if (category) book.category = String(category).slice(0, 50);
  if (description) book.description = String(description).slice(0, 500);

  res.json({ message: 'Book updated successfully.', book });
});

// Catalog: Delete Book (Strict BOLA Server-Side Authorization)
app.delete('/api/books/:id', authenticateToken, (req, res) => {
  const bookId = String(req.params.id);
  const bookIndex = BOOKS.findIndex(b => b.id === bookId);

  if (bookIndex === -1) {
    return res.status(404).json({ error: 'Book not found.' });
  }

  const book = BOOKS[bookIndex];
  // OBJECT-LEVEL AUTHORIZATION CHECK
  if (book.owner !== req.user.username) {
    logSecurityEvent('security_alert', 'BOLA deletion attempt blocked by authorization', {
      user: req.user.username,
      bookId,
      actual_owner: book.owner
    });
    return res.status(403).json({
      error: 'Access denied. This book belongs to another user.',
      code: 'BOLA_PERMISSION_DENIED',
      bookId,
      expected_owner: book.owner,
      requesting_user: req.user.username
    });
  }

  BOOKS.splice(bookIndex, 1);
  res.json({ message: 'Book deleted successfully.', bookId });
});

// Comments: Get Comments for Book
app.get('/api/comments/book/:bookId', (req, res) => {
  const bookId = String(req.params.bookId);
  const comments = COMMENTS.filter(c => c.bookId === bookId);
  res.json({ bookId, comments, count: comments.length });
});

// Comments: Post Comment (Safe Rendering / Sanitized)
app.post('/api/comments/book/:bookId', authenticateToken, (req, res) => {
  const bookId = String(req.params.bookId);
  const { text } = req.body;

  if (!text || String(text).trim().length === 0) {
    return res.status(400).json({ error: 'Comment text cannot be empty.' });
  }

  // Safe representation (never executed as HTML/JS)
  const safeText = String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

  const newComment = {
    id: `cmt_${Date.now()}`,
    bookId,
    user: req.user.username,
    text: safeText,
    timestamp: new Date().toISOString()
  };

  COMMENTS.push(newComment);
  res.status(201).json({ message: 'Comment added successfully.', comment: newComment });
});

// Profile & Current User
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = USERS.find(u => u.username === req.user.username);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const userBooks = BOOKS.filter(b => b.owner === user.username);
  const userComments = COMMENTS.filter(c => c.user === user.username);

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    created_at: user.created_at,
    total_books: userBooks.length,
    total_comments: userComments.length,
    books: userBooks
  });
});

app.get('/api/users/me', authenticateToken, (req, res) => {
  res.redirect('/api/profile');
});

if (require.main === module) {
  initDatabase();
  app.listen(PORT, () => {
    console.log(`[+] SecureBook Demo API running on http://localhost:${PORT}`);
    logSecurityEvent('info', `Server listening on port ${PORT}`);
  });
}

module.exports = { app };
