// backend/utils/sendOTP.js
const nodemailer = require("nodemailer");

const sendOTP = async (email, otp) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verification Code",
      text: `Your OTP is ${otp}`,
    });
    console.log(`📧 Email sent to ${email}`);
    return true;
  } catch (error) {
    // THIS PREVENTS THE 500 ERROR
    console.log("❌ Email failed, but server is still running.");
    console.log(`🔑 DEBUG OTP FOR ${email}: ${otp}`);
    return false; 
  }
};

module.exports = sendOTP;