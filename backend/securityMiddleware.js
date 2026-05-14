const axios = require("axios");

const extractFeatures = require("./services/featureExtractor.js");
const decisionEngine = require("./services/decisionEngine.js");
const behaviorStore = require("./store/behaviorStore.js");

const ML_SERVICE_URL = "http://127.0.0.1:8001";

async function securityMiddleware(req, res, next) {
  try {
    // Always allow operational endpoints so recovery/health checks are never blocked.
    if (
      req.path === "/api/security/reset" ||
      req.path === "/api/security/summary" ||
      req.path === "/api/security/events" ||
      req.path === "/security/reset" ||
      req.path === "/security/summary" ||
      req.path === "/security/events" ||
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

    // ── Check already-blocked IP ──
    const existingUser = behaviorStore.get(ip);
    if (existingUser?.blocked) {
      res.locals.securityRejected = true;
      behaviorStore.recordEvent({
        ip,
        path: req.path,
        method: req.method,
        prediction: "blocked_source",
        action: "BLOCK",
        confidence: null,
        policyReason: "already_blocked",
      });
      return res.status(403).json({
        success: false,
        action: "BLOCK",
        message: "IP blocked by AI Security System",
      });
    }

    // ── Check active rate-limit ──
    if ((existingUser?.rateLimitedUntil || 0) > Date.now()) {
      // Track repeated attempts while rate-limited
      existingUser.rateLimitAttempts = (existingUser.rateLimitAttempts || 0) + 1;

      // Escalate to BLOCK after 3 attempts while rate-limited
      if (existingUser.rateLimitAttempts >= 3) {
        existingUser.blocked = true;
        behaviorStore.set(ip, existingUser);
        res.locals.securityRejected = true;
        behaviorStore.recordEvent({
          ip,
          path: req.path,
          method: req.method,
          prediction: "rate_limit_escalation",
          action: "BLOCK",
          confidence: null,
          policyReason: "rate_limit_violation_block",
        });
        console.log(`[ESCALATION] IP ${ip} BLOCKED after ${existingUser.rateLimitAttempts} attempts while rate-limited`);
        return res.status(403).json({
          success: false,
          action: "BLOCK",
          policy_reason: "rate_limit_violation_block",
          message: "Blocked — continued requests during rate limit",
        });
      }

      behaviorStore.set(ip, existingUser);
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((existingUser.rateLimitedUntil - Date.now()) / 1000),
      );
      res.locals.securityRejected = true;
      res.set("Retry-After", String(retryAfterSeconds));
      behaviorStore.recordEvent({
        ip,
        path: req.path,
        method: req.method,
        prediction: "rate_limited_source",
        action: "RATE_LIMIT",
        confidence: null,
        policyReason: "active_rate_limit",
        retryAfterSeconds,
      });
      return res.status(429).json({
        success: false,
        action: "RATE_LIMIT",
        retry_after_seconds: retryAfterSeconds,
        message: "Temporarily rate limited by AI Security System",
      });
    }

    // ── Step 1: Extract behavioral features ──
    const features = extractFeatures(req);
    console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log(`[REQUEST] ${req.method} ${req.path} from ${ip}`);
    console.log("[FEATURES]", features);

    // ── Step 2: Call ML Service (pure inference — only prediction + confidence) ──
    const mlResponse = await axios.post(`${ML_SERVICE_URL}/predict`, {
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

    const { prediction, confidence } = mlResponse.data;
    console.log(`[ML SERVICE] prediction=${prediction}  confidence=${confidence !== null ? confidence.toFixed(4) : "null"}`);

    // ── Step 3: Decision Engine (hybrid ML + rule-based) ──
    const decision = decisionEngine(ip, prediction, confidence, features);

    // ── Record event for dashboard ──
    behaviorStore.recordEvent({
      ip,
      path: req.path,
      method: req.method,
      prediction,
      action: decision.action,
      confidence,
      policyReason: decision.policyReason,
      retryAfterSeconds: decision.retryAfterSeconds || null,
      sequenceLength: features["sequence_length(count)"],
      failedAuthCount: features["failed_auth_count"],
      tokenReuseRatio: features["token_reuse_ratio"],
      status4xxRatio: features["status_4xx_ratio"],
      status5xxRatio: features["status_5xx_ratio"],
    });

    // ── Enforce decision ──
    if (decision.action === "BLOCK") {
      res.locals.securityRejected = true;
      return res.status(403).json({
        success: false,
        action: "BLOCK",
        prediction,
        confidence,
        policy_reason: decision.policyReason,
        message: decision.message,
      });
    }

    if (decision.action === "RATE_LIMIT") {
      res.locals.securityRejected = true;
      res.set("Retry-After", String(decision.retryAfterSeconds));
      return res.status(429).json({
        success: false,
        action: "RATE_LIMIT",
        prediction,
        confidence,
        policy_reason: decision.policyReason,
        retry_after_seconds: decision.retryAfterSeconds,
        message: decision.message,
      });
    }

    if (decision.action === "ALERT") {
      console.log(`[ALERT] ${decision.message}`);
    }

    // ALLOW — continue to route handler
    next();
  } catch (error) {
    console.error("[MIDDLEWARE ERROR]", error.message);
    behaviorStore.recordEvent({
      ip: req.ip || req.connection.remoteAddress,
      path: req.path,
      method: req.method,
      prediction: "ml_service_error",
      action: "ERROR",
      confidence: null,
      policyReason: error.message,
    });
    // Fail open — allow the request through if ML service is down
    next();
  }
}

module.exports = securityMiddleware;
