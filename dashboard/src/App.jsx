import { useEffect, useMemo, useState } from "react";
import {
  GATEWAY_URL, PAGE_SIZE, classCounts, hasRule, loadTelemetry, maliciousProbability,
  matchesFilters, probe, sortEvents, summarize, trafficSource
} from "./telemetry";
import {
  activeRules, historicalBola, historicalFamilies, modelComparison,
  references, ruleOnlyExamples, scopedValidation
} from "./evidence";

const PAGES = [
  ["overview", "Research Overview"],
  ["live", "Live Telemetry"],
  ["timeline", "Attack Timeline"],
  ["atrdf", "ATRDF Detection & Mitigation"],
  ["bola", "BOLA Detection & Authorization"],
  ["zap", "OWASP ZAP Verification"],
  ["models", "Model Comparison"],
  ["health", "System Health & Reproducibility"]
];

const EMPTY_FILTERS = { window: "all", family: "all", decision: "all", ml: "all", source: "all", q: "" };

function formatWhen(value) {
  const time = Date.parse(value);
  if (Number.isNaN(time)) return "Unavailable";
  return new Date(time).toLocaleString();
}

function percent(value) {
  return value === null || value === undefined ? "Unavailable" : `${(value * 100).toFixed(1)}%`;
}

function Badge({ value }) {
  const name = (value || "unavailable").toLowerCase();
  const tone = name === "block" ? "block" : name === "alert" ? "alert" : "allow";
  return <span className={`badge ${tone}`}>{value || "Unavailable"}</span>;
}

function Filters({ filters, setFilters, families }) {
  return (
    <div className="filters">
      <label>Time window
        <select value={filters.window} onChange={(e) => setFilters({ ...filters, window: e.target.value })}>
          <option value="all">Current buffer</option>
          <option value="15m">Last 15 minutes</option>
          <option value="1h">Last hour</option>
          <option value="6h">Last 6 hours</option>
          <option value="24h">Last 24 hours</option>
        </select>
      </label>
      <label>Family
        <select value={filters.family} onChange={(e) => setFilters({ ...filters, family: e.target.value })}>
          <option value="all">All</option>
          {families.map((name) => <option key={name} value={name}>{name}</option>)}
        </select>
      </label>
      <label>Gateway decision
        <select value={filters.decision} onChange={(e) => setFilters({ ...filters, decision: e.target.value })}>
          <option value="all">All</option>
          <option value="ALLOW">ALLOW</option>
          <option value="ALERT">ALERT</option>
          <option value="BLOCK">BLOCK</option>
        </select>
      </label>
      <label>ML decision
        <select value={filters.ml} onChange={(e) => setFilters({ ...filters, ml: e.target.value })}>
          <option value="all">All</option>
          <option value="ALLOW">ALLOW</option>
          <option value="BLOCK">BLOCK</option>
          <option value="unavailable">Unavailable</option>
        </select>
      </label>
      <label>Source
        <select value={filters.source} onChange={(e) => setFilters({ ...filters, source: e.target.value })}>
          <option value="all">All</option>
          <option value="ZAP">ZAP</option>
          <option value="Browser">Browser</option>
          <option value="Other">Other</option>
          <option value="Unspecified">Unspecified</option>
        </select>
      </label>
      <label>Search
        <input value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} placeholder="Request id, route, rule" />
      </label>
    </div>
  );
}

function EventTable({ rows, selected, onSelect, sort, setSort }) {
  const header = (key, label) => (
    <th><button type="button" onClick={() => setSort({ key, dir: sort.key === key && sort.dir === "desc" ? "asc" : "desc" })}>{label}</button></th>
  );
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {header("timestamp", "Time")}
            {header("requestId", "Request")}
            {header("method", "Method")}
            {header("endpoint", "Route")}
            <th>Source</th>
            <th>ML</th>
            <th>Class</th>
            <th>Malicious probability</th>
            <th>Rule</th>
            <th>Gateway</th>
            <th>HTTP</th>
            <th>Backend</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan="12">No review-gateway events match this filter.</td></tr>
          ) : rows.map((event) => (
            <tr key={event.requestId || event.timestamp} className={selected && selected.requestId === event.requestId ? "clickable selected" : "clickable"} onClick={() => onSelect(event)}>
              <td>{formatWhen(event.timestamp)}</td>
              <td><code>{event.requestId || "Unavailable"}</code></td>
              <td>{event.method || "Unavailable"}</td>
              <td><code>{event.endpoint || "Unavailable"}</code></td>
              <td>{trafficSource(event)}</td>
              <td><Badge value={event.mlDecision} /></td>
              <td>{event.predictedClass || "Unavailable"}</td>
              <td>{percent(maliciousProbability(event))}</td>
              <td>{hasRule(event) ? event.ruleId : "None"}</td>
              <td><Badge value={event.decision} /></td>
              <td>{event.statusCode ?? "Unavailable"}</td>
              <td>{event.backendReached === true ? "Yes" : event.backendReached === false ? "No" : "Unavailable"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Trace({ event }) {
  if (!event) return <p className="muted">Select a request. The trace uses only fields stored for that request.</p>;
  const features = Array.isArray(event.topPredictiveFeatures) && event.topPredictiveFeatures.length > 0;
  const multi = event.multiclassProbabilities && Object.keys(event.multiclassProbabilities).length > 0;
  const steps = [
    ["HTTP request", `${event.method || "Unavailable"} ${event.endpoint || "Unavailable"} · ${event.requestId || "request id unavailable"}`],
    ["Feature extraction", features ? event.topPredictiveFeatures.join(", ") : "The gateway record does not include the extracted feature vector."],
    ["Binary inference", event.modelName ? `${event.modelName} · ML ${event.mlDecision || "unavailable"} · malicious probability ${percent(maliciousProbability(event))}` : "Model identifier unavailable in this record."],
    ["Multiclass inference", multi ? Object.entries(event.multiclassProbabilities).map(([name, value]) => `${name} ${percent(value)}`).join(" · ") : "Multiclass probabilities were not stored for this record."],
    ["Deterministic rule", hasRule(event) ? `${event.ruleId} · outcome ${event.ruleOutcome || "recorded"}` : "No review rule matched."],
    ["Gateway action", `${event.decision || "Unavailable"} · ${event.mitigation || event.finalReason || "mitigation text unavailable"}${Array.isArray(event.mitigationTechniques) && event.mitigationTechniques.length ? ` · techniques ${event.mitigationTechniques.join(", ")}` : ""} · HTTP ${event.statusCode ?? "unavailable"}`],
    ["Backend", event.backendReached === true ? "The demo API returned a status." : event.backendReached === false ? "The demo API was not called." : "Backend status was not stored."]
  ];
  return (
    <div className="trace">
      {steps.map(([title, body], index) => (
        <div key={title} className={body.includes("not ") || body.includes("unavailable") ? "step missing" : "step"}>
          <strong>{index + 1}. {title}</strong>
          <div>{body}</div>
        </div>
      ))}
    </div>
  );
}

function MetricTable({ headers, rows }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead>
        <tbody>{rows.map((row) => <tr key={row.join("|")}>{row.map((cell, index) => <td key={`${cell}-${index}`}>{cell}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

export default function App() {
  const [page, setPage] = useState("overview");
  const [events, setEvents] = useState([]);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState(null);
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [selected, setSelected] = useState(null);
  const [pageIndex, setPageIndex] = useState(0);
  const [sort, setSort] = useState({ key: "timestamp", dir: "desc" });
  const [health, setHealth] = useState({});

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const next = await loadTelemetry();
        if (!active) return;
        setEvents(next);
        setError("");
        setUpdated(new Date());
      } catch (err) {
        if (active) setError(err.message);
      }
    };
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => { active = false; clearInterval(timer); };
  }, []);

  useEffect(() => {
    let active = true;
    const check = async () => {
      const [gateway, ml, zap, catalog, api] = await Promise.all([
        probe(`${GATEWAY_URL}/health`),
        probe("/probe/ml/health"),
        probe("/probe/zap/JSON/core/view/version/"),
        probe("/probe/catalog/"),
        probe("/probe/api/api/health")
      ]);
      if (active) setHealth({ gateway, ml, zap, catalog, api, checked: new Date() });
    };
    check();
    const timer = setInterval(check, 10000);
    return () => { active = false; clearInterval(timer); };
  }, []);

  const now = updated ? updated.getTime() : Date.now();
  const filtered = useMemo(
    () => events.filter((event) => matchesFilters(event, filters, now)),
    [events, filters, now]
  );
  const summary = useMemo(() => summarize(filtered), [filtered]);
  const sorted = useMemo(() => sortEvents(filtered, sort), [filtered, sort]);
  const visible = sorted.slice(pageIndex * PAGE_SIZE, (pageIndex + 1) * PAGE_SIZE);
  const families = useMemo(() => {
    const names = new Set(scopedValidation.families.map(([name]) => name));
    names.add("BENIGN");
    names.add("BOLA");
    events.forEach((event) => { if (event.predictedClass) names.add(event.predictedClass); });
    return [...names];
  }, [events]);
  const counts = classCounts(filtered);
  const maxCount = counts[0]?.[1] || 1;

  useEffect(() => { setPageIndex(0); }, [filters, sort]);

  const status = error
    ? `Last error: ${error}. Last successful refresh: ${updated ? updated.toLocaleTimeString() : "none"}.`
    : `Source: review gateway ${GATEWAY_URL}. Last refresh ${updated ? updated.toLocaleTimeString() : "pending"}. ${events.length} events in the buffer.`;

  return (
    <div className="shell">
      <nav className="nav">
        <h1>REST API Security</h1>
        <p>Review evidence from port 8081. Production port 8080 is not this view.</p>
        {PAGES.map(([id, label]) => (
          <button key={id} className={page === id ? "active" : ""} type="button" onClick={() => setPage(id)}>{label}</button>
        ))}
      </nav>
      <main className="main">
        <div className="top">
          <div>
            <h2>{PAGES.find(([id]) => id === page)[1]}</h2>
            <p className="muted">{status}</p>
          </div>
        </div>
        {error && <div className="banner error">The review gateway could not be read. Counters stay at the last successful buffer. {error}</div>}
        {!error && events.length === 0 && <div className="banner error">The review gateway responded, and its current buffer is empty.</div>}

        {page === "overview" && (
          <>
            <Filters filters={filters} setFilters={setFilters} families={families} />
            <div className="cards">
              <div className="card"><span>Requests in filter</span><strong>{summary.total}</strong></div>
              <div className="card"><span>ML allow</span><strong>{summary.benign}</strong></div>
              <div className="card"><span>ML block</span><strong>{summary.mlMalicious}</strong></div>
              <div className="card"><span>Gateway blocks</span><strong>{summary.gatewayBlocks}</strong></div>
              <div className="card"><span>Rule-only blocks</span><strong>{summary.ruleOnlyBlocks}</strong></div>
              <div className="card"><span>ATRDF events</span><strong>{summary.atrdf}</strong></div>
              <div className="card"><span>BOLA model alerts</span><strong>{summary.bolaAlerts}</strong></div>
              <div className="card"><span>Backend reached</span><strong>{summary.forwarded}</strong></div>
            </div>
            <div className="panel">
              <h3>How these counters are defined</h3>
              <p>ML allow and ML block come from <code>mlDecision</code>. A gateway block is <code>decision = BLOCK</code>. An ALERT is not a block. A rule-only block is a matched rule while the model stayed ALLOW and the gateway blocked. A BOLA model alert is <code>attackFamily = BOLA</code> with ML BLOCK. It is not, by itself, a confirmed authorization failure. The gateway’s own stats route counts every decision other than ALLOW as blocked, so this page does not use that route.</p>
            </div>
            <div className="panel" style={{ marginTop: "0.8rem" }}>
              <h3>Predicted classes in this filter</h3>
              <div className="bars">
                {counts.length === 0 ? <p>No events in this filter.</p> : counts.map(([name, count]) => (
                  <div className="bar-row" key={name}><span>{name}</span><div className="bar"><i style={{ width: `${(count / maxCount) * 100}%` }} /></div><span>{count}</span></div>
                ))}
              </div>
            </div>
          </>
        )}

        {(page === "live" || page === "timeline") && (
          <>
            <Filters filters={filters} setFilters={setFilters} families={families} />
            <EventTable rows={visible} selected={selected} onSelect={setSelected} sort={sort} setSort={setSort} />
            <div className="pager">
              <button type="button" onClick={() => setPageIndex(Math.max(0, pageIndex - 1))} disabled={pageIndex === 0}>Previous</button>
              <span>Page {pageIndex + 1} of {Math.max(1, Math.ceil(sorted.length / PAGE_SIZE))}</span>
              <button type="button" onClick={() => setPageIndex(pageIndex + 1)} disabled={(pageIndex + 1) * PAGE_SIZE >= sorted.length}>Next</button>
            </div>
          </>
        )}
        {page === "timeline" && (
          <div className="panel" style={{ marginTop: "0.8rem" }}>
            <h3>Decision trace {selected ? selected.requestId : ""}</h3>
            <Trace event={selected || sorted[0]} />
          </div>
        )}

        {page === "atrdf" && (
          <div className="split">
            <div>
              <Filters filters={{ ...filters, family: filters.family === "all" ? "all" : filters.family }} setFilters={setFilters} families={scopedValidation.families.map(([name]) => name)} />
              <EventTable
                rows={sorted.filter((event) => event.attackFamily === "ATRDF" || String(event.ruleId || "").startsWith("ATRDF-") || scopedValidation.families.some(([name]) => name === event.predictedClass)).slice(0, PAGE_SIZE)}
                selected={selected}
                onSelect={setSelected}
                sort={sort}
                setSort={setSort}
              />
              <div className="panel" style={{ marginTop: "0.8rem" }}>
                <h3>Active review rules</h3>
                <MetricTable headers={["Rule", "What the code matches"]} rows={activeRules} />
              </div>
            </div>
            <div className="panel">
              <h3>How a request is handled</h3>
              <ol>
                <li>The review gateway on port 8081 receives the HTTP request.</li>
                <li>It builds 13 request statistics and 7 structural flags.</li>
                <li>The ML service scores <code>candidate_binary_rf_payload_six</code> at threshold 0.50.</li>
                <li>A malicious score asks <code>candidate_multiclass_rf_payload_six</code> for one of the six classes.</li>
                <li>ReviewRequestGuard records a rule match independently.</li>
                <li>An ATRDF model block returns before the demo API. Cookie Injection is HTTP 401. The other five classes are HTTP 403.</li>
                <li>A rule can still block when the model stays ALLOW. That row is a rule mitigation.</li>
              </ol>
              <p className="muted">Historical rule-only examples from the bounded review scan, not the live buffer: {ruleOnlyExamples.map((row) => row[0]).join(", ")}.</p>
            </div>
          </div>
        )}

        {page === "bola" && (
          <>
            <div className="panel">
              <h3>Two layers</h3>
              <p>The BOLA forest <code>bola_rf_behavioral</code> scores a window of 10 requests. ML BLOCK is stored as ALERT, and the demo API applies the JWT and the owner check.</p>
            </div>
            <h3 style={{ margin: "1rem 0 0.4rem" }}>Recorded ZAP scenarios</h3>
            <MetricTable
              headers={["Experiment", "ZAP message", "Request", "Scenario", "HTTP", "Recorded result"]}
              rows={historicalBola}
            />
            <h3 style={{ margin: "1rem 0 0.4rem" }}>BOLA rows currently in the gateway buffer</h3>
            <EventTable rows={sorted.filter((event) => event.attackFamily === "BOLA").slice(0, PAGE_SIZE)} selected={selected} onSelect={setSelected} sort={sort} setSort={setSort} />
          </>
        )}

        {page === "zap" && (
          <>
            <div className="panel">
              <h3>Recorded run EXP-ZAP-PREVIEW</h3>
              <p>ZAP 2.17.0 <code>sendRequest</code> to http://127.0.0.1:8081. Each family was ML BLOCK at malicious probability 1.0, the matching rule also matched, and the backend was not reached. This table is historical. Opening this page does not start a scan.</p>
              <MetricTable headers={["Family", "ZAP message", "Request", "Rule", "HTTP"]} rows={historicalFamilies} />
            </div>
            <h3 style={{ margin: "1rem 0 0.4rem" }}>ZAP-tagged rows still in the live buffer</h3>
            <EventTable rows={sorted.filter((event) => trafficSource(event) === "ZAP").slice(0, PAGE_SIZE)} selected={selected} onSelect={setSelected} sort={sort} setSort={setSort} />
          </>
        )}

        {page === "models" && (
          <>
            <div className="panel">
              <h3>ATRDF binary validation</h3>
              <p>Grouped development validation, 19,621 rows, threshold 0.50. Gradient boosting is histogram gradient boosting. Random Forest and logistic regression are the two models this comparison supports. Isolation Forest is a binary anomaly detector.</p>
              <MetricTable headers={["Model", "Accuracy", "Precision", "Recall", "F1", "FPR", "ROC-AUC", "PR-AUC", "ms/row"]} rows={modelComparison.atrdfBinary} />
              <MetricTable headers={["Model", "TN", "FP", "FN", "TP"]} rows={modelComparison.atrdfConfusion} />
            </div>
            <div className="panel" style={{ marginTop: "0.8rem" }}>
              <h3>ATRDF multiclass validation</h3>
              <p>The four supervised models share these family scores. Isolation Forest has no family label.</p>
              <MetricTable headers={["Class", "Precision", "Recall", "F1", "Support"]} rows={modelComparison.atrdfFamilies} />
            </div>
            <div className="panel" style={{ marginTop: "0.8rem" }}>
              <h3>BOLA offline validation</h3>
              <p>Session-disjoint validation, 5,030 rows. These columns are not the live session-window features, so this table does not measure the gateway.</p>
              <MetricTable headers={["Model", "Accuracy", "Precision", "Recall", "F1", "FPR", "ROC-AUC", "PR-AUC", "ms/row"]} rows={modelComparison.bolaBinary} />
              <MetricTable headers={["Model", "TN", "FP", "FN", "TP"]} rows={modelComparison.bolaConfusion} />
              <MetricTable headers={["Model", "NORMAL rows", "Row FPR", "Legitimate sessions", "Sessions with a false positive", "Session FPR"]} rows={modelComparison.bolaLegitimate} />
            </div>
          </>
        )}

        {page === "health" && (
          <>
            <div className="cards">
              {[
                ["Review gateway 8081", health.gateway],
                ["ML service 8000", health.ml],
                ["Catalog 4173", health.catalog],
                ["Demo API 5001", health.api],
                ["ZAP 8091", health.zap]
              ].map(([label, item]) => (
                <div className="card" key={label}>
                  <span>{label}</span>
                  <strong>{item ? (item.ok ? "Reachable" : `HTTP ${item.status || "down"}`) : "Checking"}</strong>
                </div>
              ))}
            </div>
            <div className="panel">
              <h3>Review configuration that this dashboard is reading</h3>
              <p>Profile <code>experimental-payload</code> on port 8081. ATRDF model <code>candidate_binary_rf_payload_six</code> and <code>candidate_multiclass_rf_payload_six</code>. Classes: Cookie Injection, Directory Traversal, LOG4J, Log Forging, RCE, SQL Injection. Threshold 0.50. BOLA model <code>bola_rf_behavioral</code>. The health JSON from the gateway can still display <code>"port": 8080</code> while the process is bound to 8081. Confirm the listener command line. Production port 8080 is outside this page.</p>
              <p className="muted">Health checked {health.checked ? health.checked.toLocaleTimeString() : "not yet"}.</p>
            </div>
            <div className="panel" style={{ marginTop: "0.8rem" }}>
              <h3>Reproducibility references</h3>
              <ul>{references.map((path) => <li key={path}><code>{path}</code></li>)}</ul>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
