const express = require("express");
const router = express.Router();
const auth = require("../controllers/authController");
const { protect } = require("../middleware/authMiddleware");

// Auth Endpoints
router.post("/register", auth.register);
router.post("/verify-otp", auth.verifyOTP);
router.post("/set-password", auth.setPassword);
router.post("/login-password", auth.loginPassword); // Yahan 500 error check karein
router.post("/login-otp", auth.loginOTP);
router.post("/verify-login-otp", auth.verifyLoginOTP);

// Protected Endpoint
router.get("/profile", protect, auth.getProfile);

module.exports = router;