const behaviorStore = require("../store/behaviorStore.js");

function getClientToken(req) {
  const auth = req.headers?.authorization || "";
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
    return auth.slice(7).trim();
  }

  const apiKey = req.headers?.["x-api-key"];
  if (typeof apiKey === "string" && apiKey.trim().length > 0) {
    return apiKey.trim();
  }

  return "anonymous";
}

function extractFeatures(req) {
  const ip = req.ip || req.connection.remoteAddress;
  const endpoint = req.path;
  const now = Date.now();
  const token = getClientToken(req);
  const loginFailedHint =
    req.headers?.["x-login-failed"] === "1" || req.query?.login_failed === "1";

  // Create record if user doesn't exist
  if (!behaviorStore.has(ip)) {
    behaviorStore.set(ip, {
      requests: [],
      statusHistory: [],
      failedLoginEvents: [],
      sessionStart: now,
      blocked: false,
      alerts: 0,
      rateLimitedUntil: 0,
    });
  }

  const userData = behaviorStore.get(ip);

  // Store request
  userData.requests.push({
    endpoint,
    timestamp: now,
    token,
  });

  // Best-effort failed login tracking using request hints
  if (endpoint.includes("/login") && loginFailedHint) {
    userData.failedLoginEvents.push(now);
  }

  // Keep only last 1 minute requests
  userData.requests = userData.requests.filter(
    (item) => now - item.timestamp < 60000,
  );

  // Keep status history bounded to last 1 minute
  userData.statusHistory = (userData.statusHistory || []).filter(
    (item) => now - item.timestamp < 60000,
  );
  userData.failedLoginEvents = (userData.failedLoginEvents || []).filter(
    (ts) => now - ts < 60000,
  );

  // -----------------------------
  // Feature Calculations
  // -----------------------------

  const sequenceLength = userData.requests.length;
  const uniqueApis = new Set(userData.requests.map((r) => r.endpoint)).size;
  const apiAccessUniqueness = uniqueApis / Math.max(1, sequenceLength);
  const sessionDuration = (now - userData.sessionStart) / 1000;

  // Average interval
  let avgInterval = 0;

  if (sequenceLength > 1) {
    const intervals = [];

    for (let i = 1; i < sequenceLength; i++) {
      intervals.push(
        userData.requests[i].timestamp - userData.requests[i - 1].timestamp,
      );
    }

    avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  }

  // IP type simulation
  const ipType = ip.includes("127.0.0.1") ? "default" : "datacenter";

  // Source simulation
  const source = "E";

  const totalStatusEvents = Math.max(1, userData.statusHistory.length);
  const status4xxCount = userData.statusHistory.filter(
    (item) => item.statusCode >= 400 && item.statusCode < 500,
  ).length;
  const status5xxCount = userData.statusHistory.filter(
    (item) => item.statusCode >= 500,
  ).length;

  const tokenCountsMap = {};
  for (const item of userData.requests) {
    tokenCountsMap[item.token] = (tokenCountsMap[item.token] || 0) + 1;
  }
  const tokenCounts = Object.values(tokenCountsMap);
  const maxTokenUse = tokenCounts.length ? Math.max(...tokenCounts) : 1;
  // Stable definition for early requests: first use is not reuse.
  const tokenReuseRatio =
    sequenceLength <= 1
      ? 0
      : (maxTokenUse - 1) / Math.max(1, sequenceLength - 1);

  const failedAuthCount = (userData.failedLoginEvents || []).length;

  const ipLower = String(ip).toLowerCase();
  const isLocalIp =
    ipLower.includes("127.0.0.1") ||
    ipLower.includes("::1") ||
    ipLower.includes("localhost");

  return {
    "inter_api_access_duration(sec)": avgInterval / 1000,
    api_access_uniqueness: apiAccessUniqueness,
    "sequence_length(count)": sequenceLength,
    "vsession_duration(min)": sessionDuration / 60,
    ip_type: isLocalIp ? "default" : ipType,
    num_sessions: 1,
    num_users: 1,
    num_unique_apis: uniqueApis,
    source: source,
    failed_auth_count: failedAuthCount,
    token_reuse_ratio: Math.max(0, Math.min(1, tokenReuseRatio)),
    status_4xx_ratio: status4xxCount / totalStatusEvents,
    status_5xx_ratio: status5xxCount / totalStatusEvents,
  };
}

module.exports = extractFeatures;
