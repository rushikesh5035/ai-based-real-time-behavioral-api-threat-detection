const axios = require("axios");

const extractFeatures = require("./services/featureExtractor.js");

const decisionEngine = require("./services/decisionEngine.js");

const behaviorStore = require("./store/behaviorStore.js");

async function securityMiddleware(req, res, next) {
  try {
    const ip = req.ip || req.connection.remoteAddress;

    // Check blocked IP
    const existingUser = behaviorStore.get(ip);

    if (existingUser?.blocked) {
      return res.status(403).json({
        success: false,

        message: "IP blocked by AI Security System",
      });
    }

    // Extract Features
    const features = extractFeatures(req);

    console.log("\n📊 Features:");

    console.log(features);

    // Call FastAPI
    const response = await axios.post(
      "http://127.0.0.1:8000/predict",

      {
        inter_api_access_duration_sec:
          features["inter_api_access_duration(sec)"],

        api_access_uniqueness: features["api_access_uniqueness"],

        sequence_length_count: features["sequence_length(count)"],

        vsession_duration_min: features["vsession_duration(min)"],

        ip_type: features["ip_type"],

        num_sessions: features["num_sessions"],

        num_users: features["num_users"],

        num_unique_apis: features["num_unique_apis"],

        source: features["source"],
      },
    );

    const result = response.data;

    console.log("🤖 Prediction:", result.prediction);

    console.log("⚠️ Risk Score:", result.risk_score);

    console.log("🚨 Decision:", result.decision);

    // Execute Decision
    const finalDecision = decisionEngine(
      ip,

      result.prediction,

      result.decision,
    );

    if (finalDecision.action === "BLOCK") {
      return res.status(403).json({
        success: false,

        message: finalDecision.message,
      });
    }

    if (finalDecision.action === "ALERT") {
      console.log("⚠️ ALERT:", finalDecision.message);
    }

    next();
  } catch (error) {
    console.error("Middleware Error:", error.message);

    next();
  }
}

module.exports = securityMiddleware;
