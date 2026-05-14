const express = require("express");

const behaviorStore = require("../store/behaviorStore.js");

const router = express.Router();

router.post("/login", (req, res) => {
  res.json({
    success: true,
    message: "Login successful",
  });
});

router.get("/profile", (req, res) => {
  res.json({
    success: true,
    message: "Profile fetched",
  });
});

router.get("/products", (req, res) => {
  res.json({
    success: true,
    message: "Products fetched for you",
  });
});

router.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "backend",
    status: "healthy",
    timestamp: new Date().toISOString(),
  });
});

router.get("/security/events", (req, res) => {
  const limit = Number(req.query.limit || 50);

  res.json({
    success: true,
    events: behaviorStore.getEvents(Number.isFinite(limit) ? limit : 50),
  });
});

router.get("/security/summary", (req, res) => {
  res.json({
    success: true,
    summary: behaviorStore.getSummary(),
  });
});

router.post("/security/reset", (req, res) => {
  behaviorStore.reset();

  res.json({
    success: true,
    message: "Security state cleared",
  });
});

module.exports = router;
