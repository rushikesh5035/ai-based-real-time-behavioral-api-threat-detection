const express = require("express");

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

module.exports = router;
