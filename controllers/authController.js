const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const sendOTP = require("../utils/sendOTP");

const generateToken = (userId) =>
  jwt.sign(
    { id: userId },
    process.env.JWT_SECRET || "secret",
    { expiresIn: "1d" }
  );

// 1. Register - Now sets isVerified to true by default for ease of use
exports.register = async (req, res) => {
  try {
    const { name, email, phone } = req.body;

    if (!phone || phone.length < 10) {
      return res.status(400).json({ message: "Phone number must be at least 10 digits" });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const otp = otpGenerator.generate(6, { 
      upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false 
    });

    await User.create({
      name, email, phone, otp,
      otpExpiry: Date.now() + 5 * 60 * 1000,
      isVerified: true // ✅ Auto-verify enabled
    });

    await sendOTP(email, otp); 
    res.json({ message: "Registration successful! OTP sent to email." });
  } catch (error) {
    res.status(500).json({ message: "Registration error", error: error.message });
  }
};

// 2. Verify OTP (General)
exports.verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.otp !== otp || user.otpExpiry < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    user.isVerified = true;
    await user.save();
    res.json({ message: "OTP Verified" });
  } catch (error) {
    res.status(500).json({ message: "Verification error", error: error.message });
  }
};

// 3. Set Password - Used when redirecting from Login
exports.setPassword = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    await user.save();

    res.json({ message: "Password Set Successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error setting password", error: error.message });
  }
};

// 4. Login with Password - Handles "Password not set" redirection logic
exports.loginPassword = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(404).json({ message: "User not found" });

    // ✅ CHECK: If password field is empty in DB, tell Frontend to redirect
    if (!user.password) {
      return res.status(400).json({ 
        message: "Password not set", 
        shouldSetPassword: true, 
        email: user.email 
      });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid password" });

    const token = generateToken(user._id);

    res.json({
      message: "Login successful",
      token,
      user: { name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ message: "Login error", error: error.message });
  }
};

// 5. Login with OTP (Request)
exports.loginOTP = async (req, res) => {
  try {
    const { email, phone } = req.body;
    const user = await User.findOne(email ? { email } : { phone });
    if (!user) return res.status(404).json({ message: "User not found" });

    const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false, lowerCaseAlphabets: false });
    user.otp = otp;
    user.otpExpiry = Date.now() + 5 * 60 * 1000;
    await user.save();

    await sendOTP(user.email, otp);
    console.log(`🔑 DEBUG OTP: ${otp}`);
    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    res.status(500).json({ message: "OTP error", error: error.message });
  }
};

// 6. Verify Login OTP
exports.verifyLoginOTP = async (req, res) => {
  try {
    const { email, phone, otp } = req.body;
    const user = await User.findOne(email ? { email } : { phone });

    if (!user || user.otp !== otp || user.otpExpiry < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();

    const token = generateToken(user._id);
    res.json({ message: "Login successful", token, user: { email: user.email, name: user.name } });
  } catch (error) {
    res.status(500).json({ message: "Verification error", error: error.message });
  }
};

// 7. Get Profile
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password -otp -otpExpiry");
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Profile Fetch Error:", error);
    res.status(500).json({ message: "Server error while fetching profile" });
  }
};
