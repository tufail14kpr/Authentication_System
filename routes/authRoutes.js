// Authentication routes
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticate, authorize } = require('../middleware/authMiddleware');

// Public routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/password-reset-request', authController.requestPasswordReset);
router.post('/password-reset', authController.resetPassword);

// Protected routes
router.get('/me', authenticate, authController.getCurrentUser);
router.get('/admin-only', authenticate, authorize('admin'), (req, res) => {
  res.json({ 
    success: true, 
    message: 'Admin access granted', 
    data: { user: req.user } 
  });
});

module.exports = router;

