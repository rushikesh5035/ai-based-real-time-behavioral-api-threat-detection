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
    message: "Products fetched",
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
