const express = require("express");

const securityMiddleware = require("./securityMiddleware.js");

const apiRoutes = require("./routes/apiRoutes.js");

const app = express();

app.use(express.json());

// Apply AI Security Middleware
app.use(securityMiddleware);

// Routes
app.use("/api", apiRoutes);

app.listen(3000, () => {
  console.log("🚀 Backend running on port 3000");
});
