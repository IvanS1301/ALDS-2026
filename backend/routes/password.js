const express = require('express');

// Existing password controller functions
const {
    forgotPassword,
    resetPassword
} = require('../controllers/passwordController');

// Google OAuth controller functions
const {
    googleAuth,
    googleCallback
} = require('../controllers/googleOAuthController');

const router = express.Router();

// Import the requireAuth middleware
const requireAuth = require('../middleware/requireAuth');

// Existing password routes
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);

// Temporary Google OAuth setup routes
router.get('/google/auth', googleAuth);
router.get('/google/callback', googleCallback);

module.exports = router;
