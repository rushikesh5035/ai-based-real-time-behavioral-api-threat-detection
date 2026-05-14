const behaviorStore = require("../store/behaviorStore.js");

function decisionEngine(
  ip,
  prediction,
  decision,
  confidence = null,
  rateLimitSeconds = null,
  policyReason = "unspecified",
) {
  // Create state if missing
  if (!behaviorStore.has(ip)) {
    behaviorStore.set(ip, {
      blocked: false,
      alerts: 0,
      rateLimitedUntil: 0,
    });
  }

  const userState = behaviorStore.get(ip);

  // BLOCK
  if (decision === "BLOCK") {
    userState.blocked = true;

    behaviorStore.set(ip, userState);

    return {
      action: "BLOCK",
      confidence,
      policyReason,
      message: "Blocked by AI Security System",
    };
  }

  // RATE LIMIT
  if (decision === "RATE_LIMIT") {
    const seconds = Number.isFinite(rateLimitSeconds) ? rateLimitSeconds : 60;
    const now = Date.now();
    userState.rateLimitedUntil = Math.max(userState.rateLimitedUntil || 0, now + seconds * 1000);
    behaviorStore.set(ip, userState);

    return {
      action: "RATE_LIMIT",
      confidence,
      policyReason,
      retryAfterSeconds: Math.max(1, Math.ceil((userState.rateLimitedUntil - now) / 1000)),
      message: `Rate limited for ${seconds}s by AI Security System`,
    };
  }

  // ALERT
  if (decision === "ALERT") {
    userState.alerts += 1;

    behaviorStore.set(ip, userState);

    return {
      action: "ALERT",
      confidence,
      policyReason,
      message: "Suspicious behavior detected",
    };
  }

  // NORMAL
  return {
    action: "ALLOW",
    confidence,
    policyReason,
    message: "Traffic allowed",
  };
}

module.exports = decisionEngine;
