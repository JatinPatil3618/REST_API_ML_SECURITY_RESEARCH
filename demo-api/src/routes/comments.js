const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth');
const { getComments, addComment } = require('../controllers/commentController');

router.get('/book/:bookId', getComments);
router.post('/book/:bookId', authMiddleware, addComment);

module.exports = router;
