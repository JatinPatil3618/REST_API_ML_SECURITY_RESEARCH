require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
const connectDB = require('./config/db');
const { optionalAuth } = require('./middleware/auth');
const requestLoggerMiddleware = require('./middleware/requestLogger');

const authRoutes = require('./routes/auth');
const bookRoutes = require('./routes/books');
const commentRoutes = require('./routes/comments');
const profileRoutes = require('./routes/profile');

const app = express();
const PORT = parseInt(process.env.DEMO_API_PORT) || 3001;

// Connect to MongoDB
connectDB();

// Core middleware
app.use(cors({
  origin: [
    `http://localhost:${process.env.FRONTEND_PORT || 5173}`,
    `http://localhost:${process.env.DASHBOARD_PORT || 5174}`,
    `http://localhost:${process.env.GATEWAY_PORT || 8080}`,
    'http://localhost:3000',
    'http://127.0.0.1:8080'
  ],
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Attach request-id to every response
app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-Id', req.requestId);
  next();
});

// Optional auth (to know who is calling)
app.use(optionalAuth);

// Request logger (logs to MongoDB for user history)
app.use(requestLoggerMiddleware);

// Health endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'securebook-demo-api',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/books', bookRoutes);
app.use('/api/comments', commentRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/users', profileRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: `Endpoint ${req.method} ${req.path} not found` });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[API] Unhandled error:', err.message);
  res.status(500).json({ error: 'An internal error occurred' });
});

app.listen(PORT, () => {
  console.log(`[SecureBook API] Running on http://localhost:${PORT}`);
  console.log(`[SecureBook API] Health: http://localhost:${PORT}/api/health`);
});

module.exports = app;
