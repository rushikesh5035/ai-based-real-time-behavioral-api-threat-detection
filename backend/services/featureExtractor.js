const behaviorStore = require("../store/behaviorStore.js");

function extractFeatures(req) {
  const ip = req.ip || req.connection.remoteAddress;

  const endpoint = req.path;

  const now = Date.now();

  // Create record if user doesn't exist
  if (!behaviorStore.has(ip)) {
    behaviorStore.set(ip, {
      requests: [],
      uniqueEndpoints: new Set(),

      failedLogins: 0,

      sessionStart: now,

      blocked: false,
    });
  }

  const userData = behaviorStore.get(ip);

  // Store request
  userData.requests.push({
    endpoint,
    timestamp: now,
  });

  // Store endpoint
  userData.uniqueEndpoints.add(endpoint);

  // Keep only last 1 minute requests
  userData.requests = userData.requests.filter(
    (req) => now - req.timestamp < 60000,
  );

  // -----------------------------
  // Feature Calculations
  // -----------------------------

  const sequenceLength = userData.requests.length;

  const uniqueApis = userData.uniqueEndpoints.size;

  const apiAccessUniqueness = uniqueApis / sequenceLength;

  const sessionDuration = (now - userData.sessionStart) / 1000;

  // Average interval
  let avgInterval = 0;

  if (sequenceLength > 1) {
    let intervals = [];

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

  return {
    "inter_api_access_duration(sec)": avgInterval / 1000,

    api_access_uniqueness: apiAccessUniqueness,

    "sequence_length(count)": sequenceLength,

    "vsession_duration(min)": sessionDuration / 60,

    ip_type: ipType,

    num_sessions: 1,

    num_users: 1,

    num_unique_apis: uniqueApis,

    source: source,
  };
}

module.exports = extractFeatures;
