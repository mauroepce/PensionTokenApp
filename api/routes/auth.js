const express = require('express');
const authController = require('../controllers/auth');
const router = express.Router();

/**
 * Create a user
 */
router.post("/register-user", authController.registerController)

/**
 * Login a user
 */
router.post("/login-user", authController.loginController)

/**
 * verify user
 */
router.get("/verify-user", authController.verifyUserController)

module.exports = router;