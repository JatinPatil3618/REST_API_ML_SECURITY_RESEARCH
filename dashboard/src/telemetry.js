export const GATEWAY_URL = "http://127.0.0.1:8081";
export const PAGE_SIZE = 12;

export function maliciousProbability(event) {
  const probs = event && event.binaryProbabilities;
  if (!probs || typeof probs !== "object") return null;
  const value = probs.MALICIOUS ?? probs.malicious;
  return typeof value === "number" ? value : null;
}

export function trafficSource(event) {
  const experiment = event.experimentId || "";
  const testCase = event.testCaseId || "";
  if (experiment.startsWith("EXP-ZAP") || /zap/i.test(event.source || "")) return "ZAP";
  if (testCase === "CASE-WEB" || experiment === "EXP-LIVE") return "Browser";
  if (experiment || testCase) return "Other";
  return "Unspecified";
}

export function hasRule(event) {
  return Boolean(event.ruleId) && event.ruleId !== "NONE" && event.ruleOutcome !== "NONE";
}

export function inWindow(event, windowId, now) {
  if (windowId === "all") return true;
  const minutes = { "15m": 15, "1h": 60, "6h": 360, "24h": 1440 }[windowId];
  if (!minutes) return true;
  const time = Date.parse(event.timestamp);
  if (Number.isNaN(time)) return false;
  return now - time <= minutes * 60 * 1000;
}

export function matchesFilters(event, filters, now) {
  if (!inWindow(event, filters.window, now)) return false;
  if (filters.family !== "all" && event.predictedClass !== filters.family && event.attackFamily !== filters.family) return false;
  if (filters.decision !== "all" && event.decision !== filters.decision) return false;
  if (filters.ml === "unavailable") {
    if (event.mlDecision) return false;
  } else if (filters.ml !== "all" && event.mlDecision !== filters.ml) return false;
  if (filters.source !== "all" && trafficSource(event) !== filters.source) return false;
  if (filters.q) {
    const haystack = [
      event.requestId, event.method, event.endpoint, event.predictedClass, event.attackFamily,
      event.ruleId, event.experimentId, event.testCaseId, event.modelName, event.decision, event.mlDecision
    ].filter(Boolean).join(" ").toLowerCase();
    if (!haystack.includes(filters.q.trim().toLowerCase())) return false;
  }
  return true;
}

export function summarize(events) {
  const summary = {
    total: events.length,
    benign: 0,
    mlMalicious: 0,
    mlUnknown: 0,
    gatewayBlocks: 0,
    gatewayAlerts: 0,
    ruleMatches: 0,
    ruleOnlyBlocks: 0,
    atrdf: 0,
    bolaAlerts: 0,
    forwarded: 0,
    timestampMissing: 0
  };
  events.forEach((event) => {
    if (!event.timestamp || Number.isNaN(Date.parse(event.timestamp))) summary.timestampMissing += 1;
    if (event.mlDecision === "ALLOW") summary.benign += 1;
    else if (event.mlDecision === "BLOCK") summary.mlMalicious += 1;
    else summary.mlUnknown += 1;
    if (event.decision === "BLOCK") summary.gatewayBlocks += 1;
    if (event.decision === "ALERT") summary.gatewayAlerts += 1;
    if (hasRule(event)) summary.ruleMatches += 1;
    if (hasRule(event) && event.mlDecision === "ALLOW" && event.decision === "BLOCK") summary.ruleOnlyBlocks += 1;
    if (event.attackFamily === "ATRDF") summary.atrdf += 1;
    if (event.attackFamily === "BOLA" && event.mlDecision === "BLOCK") summary.bolaAlerts += 1;
    if (event.backendReached === true) summary.forwarded += 1;
  });
  return summary;
}

export function classCounts(events) {
  const counts = new Map();
  events.forEach((event) => {
    const name = event.predictedClass || "Unavailable";
    counts.set(name, (counts.get(name) || 0) + 1);
  });
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

export function sortEvents(events, sort) {
  const copy = [...events];
  copy.sort((a, b) => {
    const left = a[sort.key];
    const right = b[sort.key];
    if (sort.key === "timestamp") {
      const delta = (Date.parse(left) || 0) - (Date.parse(right) || 0);
      return sort.dir === "asc" ? delta : -delta;
    }
    const text = String(left ?? "").localeCompare(String(right ?? ""));
    return sort.dir === "asc" ? text : -text;
  });
  return copy;
}

export async function loadTelemetry() {
  const response = await fetch(`${GATEWAY_URL}/api/telemetry/events?limit=1000`);
  if (!response.ok) throw new Error(`Review gateway events returned HTTP ${response.status}`);
  const events = await response.json();
  if (!Array.isArray(events)) throw new Error("Review gateway events response was not a list");
  return events;
}

export async function probe(url) {
  try {
    const response = await fetch(url);
    return { ok: response.ok, status: response.status };
  } catch (error) {
    return { ok: false, status: 0, error: error.message };
  }
}
