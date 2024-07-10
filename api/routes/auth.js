const express = require('express');
const authController = require('../controllers/auth');
const router = express.Router();

/**
 * Create a user
 */
router.post("/register-user", authController.registerController)


module.exports = router;