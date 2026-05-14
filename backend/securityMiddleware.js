const axios = require("axios");

const extractFeatures = require("./services/featureExtractor.js");
const decisionEngine = require("./services/decisionEngine.js");
const behaviorStore = require("./store/behaviorStore.js");

async function securityMiddleware(req, res, next) {
  try {
    // Always allow operational endpoints so recovery/health checks are never blocked.
    if (
      req.path === "/api/security/reset" ||
      req.path === "/api/health" ||
      req.path === "/health"
    ) {
      return next();
    }

    const ip = req.ip || req.connection.remoteAddress;

    // Record response status to compute rolling 4xx/5xx behavior ratios.
    res.on("finish", () => {
      if (!behaviorStore.has(ip)) return;
      if (res.locals?.securityRejected === true) return;
      const userData = behaviorStore.get(ip);
      if (!Array.isArray(userData.statusHistory)) {
        userData.statusHistory = [];
      }
      userData.statusHistory.push({
        timestamp: Date.now(),
        statusCode: res.statusCode,
      });
      userData.statusHistory = userData.statusHistory.filter(
        (item) => Date.now() - item.timestamp < 60000,
      );
      behaviorStore.set(ip, userData);
    });

    // Check blocked IP
    const existingUser = behaviorStore.get(ip);
    if (existingUser?.blocked) {
      res.locals.securityRejected = true;
      return res.status(403).json({
        success: false,
        message: "IP blocked by AI Security System",
      });
    }
    if ((existingUser?.rateLimitedUntil || 0) > Date.now()) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((existingUser.rateLimitedUntil - Date.now()) / 1000),
      );
      res.locals.securityRejected = true;
      res.set("Retry-After", String(retryAfterSeconds));
      return res.status(429).json({
        success: false,
        action: "RATE_LIMIT",
        retry_after_seconds: retryAfterSeconds,
        message: "Temporarily rate limited by AI Security System",
      });
    }

    // Extract behavior features from request history
    const features = extractFeatures(req);
    console.log("\nFeatures:", features);

    // Call v2 FastAPI model
    const response = await axios.post("http://127.0.0.1:8001/predict", {
      inter_api_access_duration_sec: features["inter_api_access_duration(sec)"],
      api_access_uniqueness: features["api_access_uniqueness"],
      sequence_length_count: features["sequence_length(count)"],
      vsession_duration_min: features["vsession_duration(min)"],
      ip_type: features["ip_type"],
      num_sessions: features["num_sessions"],
      num_users: features["num_users"],
      num_unique_apis: features["num_unique_apis"],
      source: features["source"],
      failed_auth_count: features["failed_auth_count"],
      token_reuse_ratio: features["token_reuse_ratio"],
      status_4xx_ratio: features["status_4xx_ratio"],
      status_5xx_ratio: features["status_5xx_ratio"],
    });

    const result = response.data;
    console.log("Prediction:", result.prediction);
    console.log("Decision:", result.decision);

    // Warm-up guard: avoid aggressive rate-limit on tiny request history.
    let modelDecision = result.decision;
    const seqLen = Number(features["sequence_length(count)"] || 0);
    const conf = Number(result.confidence || 0);
    if (seqLen <= 3 && modelDecision === "RATE_LIMIT" && conf < 0.8) {
      modelDecision = "ALLOW";
      console.log(
        "Warm-up override: RATE_LIMIT -> ALLOW",
        `(seqLen=${seqLen}, confidence=${conf.toFixed(4)})`,
      );
    }

    // Low-risk guard: if there are no auth failures and no 4xx/5xx behavior,
    // do not throttle borderline token-abuse predictions.
    const failedAuth = Number(features["failed_auth_count"] || 0);
    const ratio4xx = Number(features["status_4xx_ratio"] || 0);
    const ratio5xx = Number(features["status_5xx_ratio"] || 0);
    const lowRiskBehavior =
      failedAuth === 0 && ratio4xx === 0 && ratio5xx === 0;
    if (
      modelDecision === "RATE_LIMIT" &&
      result.prediction === "token_abuse" &&
      lowRiskBehavior &&
      conf < 0.75
    ) {
      modelDecision = "ALLOW";
      console.log(
        "Low-risk override: RATE_LIMIT -> ALLOW",
        `(failed_auth=${failedAuth}, status_4xx_ratio=${ratio4xx.toFixed(3)}, status_5xx_ratio=${ratio5xx.toFixed(3)}, confidence=${conf.toFixed(4)})`,
      );
    }

    // Execute final decision
    const finalDecision = decisionEngine(
      ip,
      result.prediction,
      modelDecision,
      result.confidence,
      result.rate_limit_seconds,
      result.policy_reason,
    );

    if (finalDecision.action === "BLOCK") {
      res.locals.securityRejected = true;
      return res.status(403).json({
        success: false,
        action: "BLOCK",
        prediction: result.prediction,
        confidence: result.confidence,
        policy_reason: result.policy_reason,
        message: finalDecision.message,
      });
    }

    if (finalDecision.action === "RATE_LIMIT") {
      res.locals.securityRejected = true;
      res.set("Retry-After", String(finalDecision.retryAfterSeconds));
      return res.status(429).json({
        success: false,
        action: "RATE_LIMIT",
        prediction: result.prediction,
        confidence: result.confidence,
        policy_reason: result.policy_reason,
        retry_after_seconds: finalDecision.retryAfterSeconds,
        message: finalDecision.message,
      });
    }

    if (finalDecision.action === "ALERT") {
      console.log("ALERT:", finalDecision.message);
    }

    next();
  } catch (error) {
    console.error("Middleware Error:", error.message);
    next();
  }
}

module.exports = securityMiddleware;
