const User = require('../models/User');
const Book = require('../models/Book');
const Comment = require('../models/Comment');
const RequestLog = require('../models/RequestLog');

// GET /api/profile  or  GET /api/users/me
const getProfile = async (req, res) => {
  try {
    const [bookCount, commentCount, recentRequests] = await Promise.all([
      Book.countDocuments({ owner: req.user._id }),
      Comment.countDocuments({ author: req.user._id }),
      RequestLog.find({ userId: req.user._id })
        .sort({ timestamp: -1 })
        .limit(20)
        .lean()
    ]);

    res.json({
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        seededId: req.user.seededId,
        createdAt: req.user.createdAt
      },
      stats: {
        bookCount,
        commentCount
      },
      recentRequests
    });
  } catch (err) {
    console.error('[Profile] getProfile error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve profile' });
  }
};

// GET /api/users/me/requests — request history page
const getRequestHistory = async (req, res) => {
  try {
    const { page = 1, limit = 30 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [total, requests] = await Promise.all([
      RequestLog.countDocuments({ userId: req.user._id }),
      RequestLog.find({ userId: req.user._id })
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean()
    ]);

    res.json({
      requests,
      pagination: { total, page: parseInt(page), limit: parseInt(limit) }
    });
  } catch (err) {
    console.error('[Profile] requestHistory error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve request history' });
  }
};

module.exports = { getProfile, getRequestHistory };
