const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, lowercase: true },
  phone: { type: String, unique: true, required: true },
  password: { type: String },
  otp: String,
  otpExpiry: Date,
  isVerified: { type: Boolean, default: false }
});

module.exports = mongoose.model("User", userSchema);