const Comment = require('../models/Comment');
const Book = require('../models/Book');

// GET /api/comments/book/:bookId
const getComments = async (req, res) => {
  try {
    const { bookId } = req.params;
    let book;

    if (/^\d+$/.test(bookId)) {
      book = await Book.findOne({ bookId: parseInt(bookId) });
    } else {
      book = await Book.findById(bookId);
    }

    if (!book) return res.status(404).json({ error: 'Book not found' });

    const comments = await Comment.find({ bookId: book._id })
      .populate('author', 'username')
      .sort({ createdAt: -1 })
      .limit(50);

    res.json({ comments });
  } catch (err) {
    console.error('[Comments] getComments error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve comments' });
  }
};

// POST /api/comments/book/:bookId
const addComment = async (req, res) => {
  try {
    const { bookId } = req.params;
    const { content } = req.body;

    if (!content || !content.trim()) {
      return res.status(400).json({ error: 'Comment content is required' });
    }

    let book;
    if (/^\d+$/.test(bookId)) {
      book = await Book.findOne({ bookId: parseInt(bookId) });
    } else {
      book = await Book.findById(bookId);
    }

    if (!book) return res.status(404).json({ error: 'Book not found' });

    // XSS prevention: content is stored as plain text and escaped on render
    // The gateway ML model detects XSS patterns before reaching here
    const sanitizedContent = content
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');

    const comment = await Comment.create({
      bookId: book._id,
      author: req.user._id,
      authorUsername: req.user.username,
      content: sanitizedContent
    });

    res.status(201).json({ message: 'Comment added', comment });
  } catch (err) {
    console.error('[Comments] addComment error:', err.message);
    res.status(500).json({ error: 'Failed to add comment' });
  }
};

module.exports = { getComments, addComment };
