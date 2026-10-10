const mongoose = require('mongoose');

// Stores per-user request history for the "Request History" page
const requestLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: { type: String },
  method: { type: String },
  endpoint: { type: String },
  statusCode: { type: Number },
  requestId: { type: String },
  responseTimeMs: { type: Number },
  timestamp: { type: Date, default: Date.now }
}, { timestamps: false });

requestLogSchema.index({ userId: 1, timestamp: -1 });

module.exports = mongoose.model('RequestLog', requestLogSchema);
