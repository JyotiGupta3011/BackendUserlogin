const jwt = require("jsonwebtoken");

const protect = (req, res, next) => {
  // 1. Get token from the header (Format: Bearer <token>)
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access denied. No token provided." });
  }

  try {
    // 2. Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret");
    
    // 3. Attach the user ID from the token to the request object
    req.userId = decoded.id;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

module.exports = { protect };