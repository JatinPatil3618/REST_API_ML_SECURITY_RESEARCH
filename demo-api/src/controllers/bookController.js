const Book = require('../models/Book');

// GET /api/books  — list with optional search/category filter
const getBooks = async (req, res) => {
  try {
    const { search, category, page = 1, limit = 20 } = req.query;
    const filter = {};

    if (search) {
      // Use parameterized mongoose query (not string concatenation)
      const searchRegex = new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [
        { title: searchRegex },
        { author: searchRegex },
        { description: searchRegex }
      ];
    }
    if (category) {
      filter.category = category;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await Book.countDocuments(filter);
    const books = await Book.find(filter)
      .populate('owner', 'username')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    res.json({
      books,
      pagination: { total, page: parseInt(page), limit: parseInt(limit), pages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('[Books] getBooks error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve books' });
  }
};

// GET /api/books/:id
const getBookById = async (req, res) => {
  try {
    const { id } = req.params;

    // Support both MongoDB _id and numeric bookId
    let book;
    if (/^\d+$/.test(id)) {
      book = await Book.findOne({ bookId: parseInt(id) }).populate('owner', 'username email');
    } else {
      book = await Book.findById(id).populate('owner', 'username email');
    }

    if (!book) {
      return res.status(404).json({ error: 'Book not found' });
    }

    // Authorization check: object-level enforcement
    // Any authenticated user can VIEW a public book (BOLA is about cross-owner modification)
    // The gateway ML detects behavioral patterns; backend enforces the hard rule for mutations
    res.json({ book });
  } catch (err) {
    console.error('[Books] getBookById error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve book' });
  }
};

// POST /api/books
const createBook = async (req, res) => {
  try {
    const { title, author, category, description, rating } = req.body;

    if (!title || !author) {
      return res.status(400).json({ error: 'Title and author are required' });
    }

    // Assign the next available bookId
    const maxBook = await Book.findOne().sort({ bookId: -1 }).select('bookId');
    const nextBookId = maxBook ? maxBook.bookId + 1 : 600;

    const book = await Book.create({
      bookId: nextBookId,
      title: title.trim(),
      author: author.trim(),
      category: category || 'Other',
      description: description ? description.trim() : '',
      owner: req.user._id,
      ownerUsername: req.user.username,
      rating: rating || 0
    });

    res.status(201).json({ message: 'Book created successfully', book });
  } catch (err) {
    console.error('[Books] createBook error:', err.message);
    res.status(500).json({ error: 'Failed to create book' });
  }
};

// PUT /api/books/:id
const updateBook = async (req, res) => {
  try {
    const { id } = req.params;
    let book;

    if (/^\d+$/.test(id)) {
      book = await Book.findOne({ bookId: parseInt(id) });
    } else {
      book = await Book.findById(id);
    }

    if (!book) {
      return res.status(404).json({ error: 'Book not found' });
    }

    // Real object-level authorization enforcement
    if (book.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access denied. This book belongs to another user.',
        code: 'BOLA_ATTEMPT',
        requestedBy: req.user.username,
        bookOwner: book.ownerUsername
      });
    }

    const { title, author, category, description, rating } = req.body;
    if (title) book.title = title.trim();
    if (author) book.author = author.trim();
    if (category) book.category = category;
    if (description !== undefined) book.description = description.trim();
    if (rating !== undefined) book.rating = rating;

    await book.save();
    res.json({ message: 'Book updated successfully', book });
  } catch (err) {
    console.error('[Books] updateBook error:', err.message);
    res.status(500).json({ error: 'Failed to update book' });
  }
};

// DELETE /api/books/:id
const deleteBook = async (req, res) => {
  try {
    const { id } = req.params;
    let book;

    if (/^\d+$/.test(id)) {
      book = await Book.findOne({ bookId: parseInt(id) });
    } else {
      book = await Book.findById(id);
    }

    if (!book) {
      return res.status(404).json({ error: 'Book not found' });
    }

    // Real object-level authorization enforcement
    if (book.owner.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        error: 'Access denied. This book belongs to another user.',
        code: 'BOLA_ATTEMPT',
        requestedBy: req.user.username,
        bookOwner: book.ownerUsername
      });
    }

    await Book.deleteOne({ _id: book._id });
    res.json({ message: 'Book deleted successfully' });
  } catch (err) {
    console.error('[Books] deleteBook error:', err.message);
    res.status(500).json({ error: 'Failed to delete book' });
  }
};

module.exports = { getBooks, getBookById, createBook, updateBook, deleteBook };
