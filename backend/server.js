const express = require("express");

const securityMiddleware = require("./securityMiddleware.js");
const behaviorStore = require("./store/behaviorStore.js");

const apiRoutes = require("./routes/apiRoutes.js");

const app = express();

app.use(express.json());
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Login-Failed");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// Apply AI Security Middleware
app.use(securityMiddleware);

// Routes
app.use("/api", apiRoutes);

// Backward-compatible operational routes without /api prefix.
app.get("/security/events", (req, res) => {
  const limit = Number(req.query.limit || 50);
  res.json({
    success: true,
    events: behaviorStore.getEvents(Number.isFinite(limit) ? limit : 50),
  });
});

app.get("/security/summary", (req, res) => {
  res.json({
    success: true,
    summary: behaviorStore.getSummary(),
  });
});

app.post("/security/reset", (req, res) => {
  behaviorStore.reset();
  res.json({
    success: true,
    message: "Security state cleared",
  });
});

app.listen(3001, () => {
  console.log("🚀 Backend running on port 3001");
});

