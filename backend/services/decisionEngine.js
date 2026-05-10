const behaviorStore = require("../store/behaviorStore.js");

function decisionEngine(ip, prediction, decision) {
  // Create state if missing
  if (!behaviorStore.has(ip)) {
    behaviorStore.set(ip, {
      blocked: false,

      alerts: 0,
    });
  }

  const userState = behaviorStore.get(ip);

  // BLOCK
  if (decision === "BLOCK") {
    userState.blocked = true;

    behaviorStore.set(ip, userState);

    return {
      action: "BLOCK",

      message: "Blocked by AI Security System",
    };
  }

  // ALERT
  if (decision === "ALERT") {
    userState.alerts += 1;

    behaviorStore.set(ip, userState);

    return {
      action: "ALERT",

      message: "Suspicious behavior detected",
    };
  }

  // NORMAL
  return {
    action: "ALLOW",

    message: "Traffic allowed",
  };
}

module.exports = decisionEngine;
