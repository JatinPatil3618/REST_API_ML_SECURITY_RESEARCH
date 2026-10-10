const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth');
const { getProfile, getRequestHistory } = require('../controllers/profileController');

router.get('/', authMiddleware, getProfile);
router.get('/me', authMiddleware, getProfile);
router.get('/me/requests', authMiddleware, getRequestHistory);

module.exports = router;
