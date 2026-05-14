const behaviorStore = new Map();

const MAX_EVENTS = 200;

behaviorStore.events = [];

behaviorStore.recordEvent = function recordEvent(event) {
  const timestamp = new Date().toISOString();
  behaviorStore.events.unshift({
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    timestamp,
    ...event,
  });

  behaviorStore.events = behaviorStore.events.slice(0, MAX_EVENTS);
};

behaviorStore.getEvents = function getEvents(limit = 50) {
  return behaviorStore.events.slice(0, limit);
};

behaviorStore.getSummary = function getSummary() {
  const events = behaviorStore.events;
  const actionCounts = {
    ALLOW: 0,
    ALERT: 0,
    RATE_LIMIT: 0,
    BLOCK: 0,
    ERROR: 0,
  };
  const predictionCounts = {};

  for (const event of events) {
    const action = event.action || "ALLOW";
    actionCounts[action] = (actionCounts[action] || 0) + 1;

    const prediction = event.prediction || "unknown";
    predictionCounts[prediction] = (predictionCounts[prediction] || 0) + 1;
  }

  const sources = Array.from(behaviorStore.entries()).map(([ip, state]) => ({
    ip,
    blocked: Boolean(state.blocked),
    alerts: state.alerts || 0,
    requestCount: Array.isArray(state.requests) ? state.requests.length : 0,
    rateLimitedUntil: state.rateLimitedUntil || 0,
  }));

  return {
    totalEvents: events.length,
    actionCounts,
    predictionCounts,
    activeSources: sources.length,
    blockedSources: sources.filter((source) => source.blocked).length,
    rateLimitedSources: sources.filter(
      (source) => (source.rateLimitedUntil || 0) > Date.now(),
    ).length,
    alertSources: sources.filter((source) => source.alerts > 0).length,
    sources,
    recentEvents: behaviorStore.getEvents(25),
    updatedAt: new Date().toISOString(),
  };
};

behaviorStore.reset = function resetBehaviorStore() {
  behaviorStore.clear();
  behaviorStore.events = [];
};

module.exports = behaviorStore;
