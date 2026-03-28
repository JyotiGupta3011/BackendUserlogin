const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const limiter = require("./middleware/rateLimit"); 

dotenv.config();
const app = express();

// Middleware
app.use(express.json());

// CORS Configuration
app.use(cors({
  origin: "http://localhost:3000", 
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

// Apply Rate Limiting
app.use("/api", limiter); 

// Routes
app.use("/api", authRoutes);

const PORT = process.env.PORT || 5000;

connectDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}).catch(err => {
  console.error("Database connection failed:", err);
});