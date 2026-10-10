const RequestLog = require('../models/RequestLog');

// Logs each request to MongoDB for the "Request History" page
const requestLoggerMiddleware = (req, res, next) => {
  const start = Date.now();
  const requestId = req.headers['x-request-id'] || require('uuid').v4();
  req.requestId = requestId;

  res.on('finish', async () => {
    try {
      if (req.user && req.path.startsWith('/api/')) {
        await RequestLog.create({
          userId: req.user._id,
          username: req.user.username,
          method: req.method,
          endpoint: req.path,
          statusCode: res.statusCode,
          requestId,
          responseTimeMs: Date.now() - start
        });
      }
    } catch (_) { /* non-critical */ }
  });
  next();
};

module.exports = requestLoggerMiddleware;
