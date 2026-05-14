const behaviorStore = require("../store/behaviorStore.js");

/**
 * Hybrid Decision Engine
 *
 * Takes ML prediction + confidence + extracted behavioral features
 * and applies a two-layer policy:
 *   Layer 1 — ML prediction + confidence thresholds
 *   Layer 2 — Rule-based overrides using behavioral context
 *
 * Returns the final action: ALLOW, ALERT, RATE_LIMIT, or BLOCK.
 */
function decisionEngine(ip, prediction, confidence, features) {
  // ── Ensure IP state exists ──
  if (!behaviorStore.has(ip)) {
    behaviorStore.set(ip, {
      blocked: false,
      alerts: 0,
      rateLimitedUntil: 0,
    });
  }

  const userState = behaviorStore.get(ip);
  const seqLen = Number(features["sequence_length(count)"] || 0);
  const failedAuth = Number(features["failed_auth_count"] || 0);
  const ratio4xx = Number(features["status_4xx_ratio"] || 0);
  const ratio5xx = Number(features["status_5xx_ratio"] || 0);
  const conf = Number(confidence || 0);

  // ────────────────────────────────────────────────
  // LAYER 1: ML Prediction + Confidence Thresholds
  // ────────────────────────────────────────────────

  let action;
  let rateLimitSeconds = null;
  let policyReason;

  if (prediction === "normal") {
    if (conf >= 0.60) {
      action = "ALLOW";
      policyReason = "normal_high_confidence";
    } else {
      action = "RATE_LIMIT";
      rateLimitSeconds = 60;
      policyReason = "normal_low_confidence";
    }
  } else if (prediction === "token_abuse") {
    if (conf >= 0.85) {
      action = "RATE_LIMIT";
      rateLimitSeconds = 120;
      policyReason = "token_abuse_high_confidence";
    } else if (conf >= 0.65) {
      action = "ALERT";
      policyReason = "token_abuse_suspicious";
    } else {
      action = "RATE_LIMIT";
      rateLimitSeconds = 120;
      policyReason = "token_abuse_borderline";
    }
  } else if (prediction === "flood") {
    if (conf >= 0.90) {
      action = "BLOCK";
      policyReason = "flood_high_confidence";
    } else {
      action = "RATE_LIMIT";
      rateLimitSeconds = 180;
      policyReason = "flood_borderline";
    }
  } else if (prediction === "bruteforce") {
    if (conf >= 0.90) {
      action = "BLOCK";
      policyReason = "bruteforce_high_confidence";
    } else {
      action = "RATE_LIMIT";
      rateLimitSeconds = 300;
      policyReason = "bruteforce_borderline";
    }
  } else {
    // Unknown prediction — fail safe
    action = "BLOCK";
    policyReason = "unknown_prediction_failsafe";
  }

  const mlAction = action; // save for logging

  // ────────────────────────────────────────────────
  // LAYER 2: Rule-Based Overrides (behavioral context)
  // ────────────────────────────────────────────────

  // Rule 1 — Warm-up guard: too few requests to judge behavior reliably
  if (seqLen <= 5 && (action === "RATE_LIMIT" || action === "BLOCK") && conf < 0.85) {
    action = "ALLOW";
    rateLimitSeconds = null;
    policyReason = "warmup_allow";
  }

  // Rule 2 — Low-risk guard: no auth failures, no errors, AND low token reuse
  const tokenReuse = Number(features["token_reuse_ratio"] || 0);
  const lowRisk = failedAuth === 0 && ratio4xx === 0 && ratio5xx === 0 && tokenReuse < 0.7;
  if (action === "RATE_LIMIT" && prediction === "token_abuse" && lowRisk && conf < 0.75) {
    action = "ALLOW";
    rateLimitSeconds = null;
    policyReason = "token_abuse_low_risk_allow";
  }

  // Rule 3 — Escalation: repeated alerts -> upgrade to RATE_LIMIT
  if (action === "ALERT" && (userState.alerts || 0) >= 3) {
    action = "RATE_LIMIT";
    rateLimitSeconds = 120;
    policyReason = "alert_escalation_to_rate_limit";
  }

  // Rule 4 — Flood detection: very high request rate + low uniqueness
  const avgInterval = Number(features["inter_api_access_duration(sec)"] || 0);
  const uniqueness = Number(features["api_access_uniqueness"] || 1);
  if (action === "ALLOW" && seqLen >= 15 && avgInterval < 0.5 && uniqueness <= 0.2) {
    action = "RATE_LIMIT";
    rateLimitSeconds = 180;
    policyReason = "rule_flood_detected";
  }
  if (action === "RATE_LIMIT" && policyReason === "rule_flood_detected" && seqLen >= 30) {
    action = "BLOCK";
    policyReason = "rule_flood_severe";
  }

  // Rule 5 — Brute force detection: high failed auth in request window
  if (action === "ALLOW" && failedAuth >= 5) {
    action = "RATE_LIMIT";
    rateLimitSeconds = 300;
    policyReason = "rule_bruteforce_failed_auth";
  }
  if (action === "ALLOW" && failedAuth >= 10) {
    action = "BLOCK";
    policyReason = "rule_bruteforce_severe";
  }

  // Rule 6 — Token abuse detection: high token reuse ratio with enough requests
  if (action === "ALLOW" && seqLen >= 8 && tokenReuse >= 0.8) {
    action = "ALERT";
    policyReason = "rule_token_reuse_suspicious";
  }

  // ────────────────────────────────────────────────
  // LAYER 3: Apply IP State
  // ────────────────────────────────────────────────

  console.log(
    `\n[DECISION ENGINE] prediction=${prediction} confidence=${conf.toFixed(4)}` +
    `\n  → Layer 1 (ML+Confidence): ${mlAction} | ${policyReason !== mlAction ? policyReason : ""}` +
    `${mlAction !== action ? `\n  → Layer 2 (Rule Override):  ${mlAction} → ${action} (${policyReason})` : ""}` +
    `\n  → Final Action: ${action} | Policy: ${policyReason}`
  );

  if (action === "BLOCK") {
    userState.blocked = true;
    behaviorStore.set(ip, userState);

    return {
      action: "BLOCK",
      prediction,
      confidence: conf,
      policyReason,
      message: "Blocked by AI Security System",
    };
  }

  if (action === "RATE_LIMIT") {
    const seconds = Number.isFinite(rateLimitSeconds) ? rateLimitSeconds : 60;
    const now = Date.now();
    userState.rateLimitedUntil = Math.max(
      userState.rateLimitedUntil || 0,
      now + seconds * 1000,
    );
    behaviorStore.set(ip, userState);

    return {
      action: "RATE_LIMIT",
      prediction,
      confidence: conf,
      policyReason,
      retryAfterSeconds: Math.max(1, Math.ceil((userState.rateLimitedUntil - now) / 1000)),
      message: `Rate limited for ${seconds}s by AI Security System`,
    };
  }

  if (action === "ALERT") {
    userState.alerts = (userState.alerts || 0) + 1;
    behaviorStore.set(ip, userState);

    return {
      action: "ALERT",
      prediction,
      confidence: conf,
      policyReason,
      message: "Suspicious behavior detected — monitoring",
    };
  }

  // ALLOW
  return {
    action: "ALLOW",
    prediction,
    confidence: conf,
    policyReason,
    message: "Traffic allowed",
  };
}

module.exports = decisionEngine;