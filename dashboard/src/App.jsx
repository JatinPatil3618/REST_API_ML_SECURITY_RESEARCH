import React, { useState, useEffect } from 'react';

const GATEWAY_URL = 'http://localhost:8080';
const ML_URL = 'http://localhost:8000';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState({
    total_requests: 0,
    normal: 0,
    malicious: 0,
    bola: 0,
    atrdf: 0,
    blocked: 0,
    allowed: 0,
    average_latency_ms: 0,
    p95_latency_ms: 0,
    p99_latency_ms: 0
  });

  const [events, setEvents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [mlInfo, setMlInfo] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Poll live telemetry from Gateway
  const fetchTelemetry = async () => {
    try {
      const statsRes = await fetch(`${GATEWAY_URL}/api/telemetry/stats`);
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }
      const eventsRes = await fetch(`${GATEWAY_URL}/api/telemetry/events?limit=50`);
      if (eventsRes.ok) {
        const eventsData = await eventsRes.json();
        setEvents(eventsData);
      }
    } catch (err) {
      console.warn('Gateway polling notice:', err.message);
    }
  };

  const fetchMlInfo = async () => {
    try {
      const res = await fetch(`${ML_URL}/model-info`);
      if (res.ok) {
        const data = await res.json();
        setMlInfo(data);
      }
    } catch (err) {
      console.warn('ML Service notice:', err.message);
    }
  };

  useEffect(() => {
    fetchTelemetry();
    fetchMlInfo();
    const interval = setInterval(() => {
      if (autoRefresh) fetchTelemetry();
    }, 2000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  // Empirical Experimental Results & Evaluation Metrics
  const BINARY_RESULTS = [
    { model: 'Random Forest (Primary)', acc: 0.9869, prec: 1.0, rec: 0.9391, f1: 0.9686, roc: 0.9796, pr: 0.9703, thresh: 0.30 },
    { model: 'Logistic Regression (Baseline)', acc: 0.9377, prec: 0.9562, rec: 0.7445, f1: 0.8372, roc: 0.9470, pr: 0.9157, thresh: 0.50 }
  ];

  const MULTICLASS_PER_CLASS = [
    { name: 'XSS', prec: 1.0, rec: 1.0, f1: 1.0, support: 1603 },
    { name: 'SQL Injection', prec: 1.0, rec: 1.0, f1: 1.0, support: 1585 },
    { name: 'Cookie Injection', prec: 1.0, rec: 1.0, f1: 1.0, support: 1548 },
    { name: 'Log Forging', prec: 1.0, rec: 1.0, f1: 1.0, support: 807 },
    { name: 'RCE', prec: 1.0, rec: 1.0, f1: 1.0, support: 789 },
    { name: 'Directory Traversal', prec: 1.0, rec: 1.0, f1: 1.0, support: 788 },
    { name: 'LOG4J', prec: 1.0, rec: 1.0, f1: 1.0, support: 747 }
  ];

  const BOLA_RESULTS = [
    { model: 'Random Forest (Primary)', normalF1: 1.0, bolaF1: 1.0, acc: 1.0, roc: 1.0 },
    { model: 'Logistic Regression (Baseline)', normalF1: 1.0, bolaF1: 1.0, acc: 1.0, roc: 1.0 }
  ];

  const ABLATION_RESULTS = [
    { set: 'FULL_25', count: 25, model: 'Random Forest', acc: 0.9869, macroF1: 0.9801, prec: 1.0, rec: 0.9390, latency: '0.0026 ms' },
    { set: 'REDUCED_18', count: 18, model: 'Random Forest', acc: 0.9868, macroF1: 0.9801, prec: 1.0, rec: 0.9389, latency: '0.0032 ms' },
    { set: 'REQUEST_ONLY_13', count: 13, model: 'Random Forest', acc: 0.9869, macroF1: 0.9801, prec: 1.0, rec: 0.9390, latency: '0.0022 ms' }
  ];

  const UNSEEN_ATTACKS = [
    { attack: 'XSS', acc: 0.9999, prec: 1.0, rec: 0.9981, f1: 0.9991, samples: 30290 },
    { attack: 'SQL Injection', acc: 0.9998, prec: 1.0, rec: 0.9968, f1: 0.9984, samples: 30272 },
    { attack: 'Cookie Injection', acc: 1.0, prec: 1.0, rec: 1.0, f1: 1.0, samples: 30235 },
    { attack: 'Log Forging', acc: 1.0, prec: 1.0, rec: 0.9988, f1: 0.9994, samples: 29494 },
    { attack: 'RCE', acc: 0.9999, prec: 1.0, rec: 0.9975, f1: 0.9987, samples: 29476 },
    { attack: 'Directory Traversal', acc: 1.0, prec: 1.0, rec: 1.0, f1: 1.0, samples: 29475 },
    { attack: 'LOG4J', acc: 0.9785, prec: 1.0, rec: 0.1513, f1: 0.2628, samples: 29434, outlier: true }
  ];

  return (
    <div className="dashboard-layout">
      {/* Left Navigation Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-title">REST API Security</div>
        <div className="sidebar-subtitle">Research Evaluation Platform</div>

        <nav className="sidebar-menu">
          <button
            className={`sidebar-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            📊 Live Telemetry Overview
          </button>
          <button
            className={`sidebar-item ${activeTab === 'stream' ? 'active' : ''}`}
            onClick={() => setActiveTab('stream')}
          >
            ⏱️ Attack Timeline Monitor
          </button>
          <button
            className={`sidebar-item ${activeTab === 'atrdf' ? 'active' : ''}`}
            onClick={() => setActiveTab('atrdf')}
          >
            🛡️ ATRDF Payload Models
          </button>
          <button
            className={`sidebar-item ${activeTab === 'bola' ? 'active' : ''}`}
            onClick={() => setActiveTab('bola')}
          >
            🔑 BOLA Behavioral Models
          </button>
          <button
            className={`sidebar-item ${activeTab === 'ablation' ? 'active' : ''}`}
            onClick={() => setActiveTab('ablation')}
          >
            ⚖️ Feature Ablation Study
          </button>
          <button
            className={`sidebar-item ${activeTab === 'unseen' ? 'active' : ''}`}
            onClick={() => setActiveTab('unseen')}
          >
            🎯 Unseen Attack Generalization
          </button>
          <button
            className={`sidebar-item ${activeTab === 'latency' ? 'active' : ''}`}
            onClick={() => setActiveTab('latency')}
          >
            ⚡ Latency & Overhead
          </button>
        </nav>

        <div className="sidebar-footer">
          <div>Gateway: <strong>localhost:8080</strong></div>
          <div>ML Service: <strong>localhost:8000</strong></div>
          <div style={{ marginTop: '0.4rem' }}>Status: <span style={{ color: '#4ade80' }}>● Synchronized</span></div>
        </div>
      </aside>

      {/* Main Content Dashboard */}
      <main className="content-area">
        <div className="top-bar">
          <div>
            <h1 className="page-title">REST API Security Research Dashboard</h1>
            <p className="page-description">
              Mechanism-Aware Machine Learning Detection & Generalization Across Access-Control and Input Threats
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={e => setAutoRefresh(e.target.checked)}
              />
              Auto-poll (2s)
            </label>
            <a
              href="http://localhost:5173"
              target="_blank"
              rel="noreferrer"
              style={{
                fontSize: '0.85rem',
                padding: '0.45rem 0.85rem',
                background: '#ffffff',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                fontWeight: 600,
                color: '#1e40af'
              }}
            >
              Open SecureBook Lab ↗
            </a>
          </div>
        </div>

        {/* Live Counters Banner */}
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-label">Total Requests</div>
            <div className="stat-value">{stats.total_requests}</div>
            <div className="stat-sub">Processed through Gateway</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Normal Traffic</div>
            <div className="stat-value" style={{ color: 'var(--success)' }}>{stats.normal}</div>
            <div className="stat-sub">Classified as Legitimate</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Malicious Detected</div>
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{stats.malicious}</div>
            <div className="stat-sub">Intercepted Attacks</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">BOLA Attacks</div>
            <div className="stat-value" style={{ color: '#9333ea' }}>{stats.bola}</div>
            <div className="stat-sub">Session Behavioral Abuse</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">ATRDF Attacks</div>
            <div className="stat-value" style={{ color: '#0284c7' }}>{stats.atrdf}</div>
            <div className="stat-sub">Input Payload Threats</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Blocked Requests</div>
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{stats.blocked}</div>
            <div className="stat-sub">HTTP 403 Forbidden</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Average Latency</div>
            <div className="stat-value">{stats.average_latency_ms} <span style={{ fontSize: '0.9rem' }}>ms</span></div>
            <div className="stat-sub">P95: {stats.p95_latency_ms}ms | P99: {stats.p99_latency_ms}ms</div>
          </div>
        </div>

        {/* 1. OVERVIEW & LIVE EVENTS TAB */}
        {activeTab === 'overview' && (
          <div>
            <div className="card">
              <div className="card-title">
                <span>Recent Security Events Stream (Click any row for Prediction Breakdown)</span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Showing last 50 events</span>
              </div>

              <div className="table-responsive">
                <table>
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Request ID</th>
                      <th>Method</th>
                      <th>Endpoint</th>
                      <th>User</th>
                      <th>Attack Family</th>
                      <th>Predicted Class</th>
                      <th>Confidence</th>
                      <th>Decision</th>
                      <th>HTTP</th>
                      <th>Latency</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.length === 0 ? (
                      <tr>
                        <td colSpan="11" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                          No telemetry events captured yet. Stimulate traffic via the SecureBook Lab or automated scripts.
                        </td>
                      </tr>
                    ) : (
                      events.map((e, idx) => (
                        <tr
                          key={idx}
                          className="clickable-row"
                          onClick={() => setSelectedEvent(e)}
                          style={{
                            backgroundColor: e.decision === 'BLOCK' ? 'rgba(254, 242, 242, 0.5)' : 'transparent'
                          }}
                        >
                          <td>{new Date(e.timestamp).toLocaleTimeString()}</td>
                          <td><code>{e.requestId}</code></td>
                          <td><strong>{e.method}</strong></td>
                          <td><code style={{ fontSize: '0.75rem' }}>{e.endpoint}</code></td>
                          <td>{e.authenticatedUser}</td>
                          <td>
                            <span className={`badge ${e.attackFamily === 'BOLA' ? 'badge-bola' : e.attackFamily === 'ATRDF' ? 'badge-atrdf' : ''}`}>
                              {e.attackFamily}
                            </span>
                          </td>
                          <td><strong>{e.predictedClass}</strong></td>
                          <td>{e.confidence ? `${(e.confidence * 100).toFixed(1)}%` : 'N/A'}</td>
                          <td>
                            <span className={`badge badge-${e.decision ? e.decision.toLowerCase() : 'allow'}`}>
                              {e.decision}
                            </span>
                          </td>
                          <td>{e.statusCode}</td>
                          <td>{e.totalGatewayLatencyMs} ms</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* 2. ATTACK TIMELINE MONITOR TAB */}
        {activeTab === 'stream' && (
          <div className="card">
            <div className="card-title">
              <span>Chronological Stream Timeline</span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
              Real-time audit log illustrating alternation between legitimate user browsing and adversarial attacks.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              {events.length === 0 ? (
                <p style={{ color: 'var(--text-muted)' }}>No chronological events available.</p>
              ) : (
                events.map((ev, i) => (
                  <div
                    key={i}
                    onClick={() => setSelectedEvent(ev)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '1rem',
                      padding: '0.75rem 1rem',
                      background: ev.decision === 'BLOCK' ? '#fff1f2' : '#f8fafc',
                      borderLeft: `4px solid ${ev.decision === 'BLOCK' ? '#e11d48' : '#10b981'}`,
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                  >
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', width: '80px' }}>
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                    <span className={`badge badge-${ev.decision ? ev.decision.toLowerCase() : 'allow'}`} style={{ width: '70px', textAlign: 'center' }}>
                      {ev.decision}
                    </span>
                    <code style={{ fontSize: '0.8rem', fontWeight: 600 }}>{ev.method} {ev.endpoint}</code>
                    <span style={{ marginLeft: 'auto', fontSize: '0.8rem' }}>
                      <strong>{ev.predictedClass}</strong> ({ev.attackFamily}) | Latency: {ev.totalGatewayLatencyMs}ms
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* 3. ATRDF PAYLOAD MODELS TAB */}
        {activeTab === 'atrdf' && (
          <div>
            <div className="card">
              <div className="card-title">
                <span>ATRDF Binary Detection Performance (Test Split: 36,554 records)</span>
              </div>
              <div className="table-responsive">
                <table>
                  <thead>
                    <tr>
                      <th>Algorithm</th>
                      <th>Accuracy</th>
                      <th>Precision</th>
                      <th>Recall</th>
                      <th>F1-Score</th>
                      <th>ROC-AUC</th>
                      <th>PR-AUC</th>
                      <th>Calibrated Threshold</th>
                    </tr>
                  </thead>
                  <tbody>
                    {BINARY_RESULTS.map((r, i) => (
                      <tr key={i}>
                        <td><strong>{r.model}</strong></td>
                        <td>{(r.acc * 100).toFixed(2)}%</td>
                        <td>{(r.prec * 100).toFixed(2)}%</td>
                        <td>{(r.rec * 100).toFixed(2)}%</td>
                        <td>{(r.f1 * 100).toFixed(2)}%</td>
                        <td>{r.roc.toFixed(4)}</td>
                        <td>{r.pr.toFixed(4)}</td>
                        <td>{r.thresh}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="card">
              <div className="card-title">
                <span>ATRDF Multiclass Classification Performance Across Attack Families</span>
              </div>
              <div className="table-responsive">
                <table>
                  <thead>
                    <tr>
                      <th>Attack Category</th>
                      <th>Precision</th>
                      <th>Recall</th>
                      <th>F1-Score</th>
                      <th>Test Set Support</th>
                    </tr>
                  </thead>
                  <tbody>
                    {MULTICLASS_PER_CLASS.map((c, i) => (
                      <tr key={i}>
                        <td><strong>{c.name}</strong></td>
                        <td>{(c.prec * 100).toFixed(2)}%</td>
                        <td>{(c.rec * 100).toFixed(2)}%</td>
                        <td>{(c.f1 * 100).toFixed(2)}%</td>
                        <td>{c.support.toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* 4. BOLA BEHAVIORAL MODELS TAB */}
        {activeTab === 'bola' && (
          <div>
            <div className="card">
              <div className="card-title">
                <span>BOLA Behavioral Session Model Performance (W=10 Rolling Window)</span>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                Evaluated across 575 completely untouched test sessions (4,960 requests). Direct user identities and object IDs
                were excluded from training to prevent memorization shortcuts.
              </p>
              <div className="table-responsive">
                <table>
                  <thead>
                    <tr>
                      <th>Model</th>
                      <th>Normal F1</th>
                      <th>BOLA F1</th>
                      <th>Overall Accuracy</th>
                      <th>ROC-AUC</th>
                      <th>Splitting Scheme</th>
                    </tr>
                  </thead>
                  <tbody>
                    {BOLA_RESULTS.map((b, i) => (
                      <tr key={i}>
                        <td><strong>{b.model}</strong></td>
                        <td>{(b.normalF1 * 100).toFixed(2)}%</td>
                        <td>{(b.bolaF1 * 100).toFixed(2)}%</td>
                        <td>{(b.acc * 100).toFixed(2)}%</td>
                        <td>{b.roc.toFixed(4)}</td>
                        <td>Strict Session-Level Split (80/10/10)</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="card">
              <div className="card-title">
                <span>Key Behavioral Decision Signals</span>
              </div>
              <ul style={{ fontSize: '0.875rem', lineHeight: 1.8, paddingLeft: '1.25rem', color: '#334155' }}>
                <li><strong>cross_owner_ratio_recent:</strong> Proportion of recent 10 requests targeting resources owned by other users.</li>
                <li><strong>unique_owners_recent:</strong> Number of distinct resource owners accessed within the rolling session window.</li>
                <li><strong>owner_switch:</strong> Frequency of consecutive switches between different resource owners.</li>
                <li><strong>same_object_repeat_ratio:</strong> Baseline repeat frequency characteristic of legitimate user workflows.</li>
                <li><strong>request_burst_rate:</strong> Frequency and inter-request timing distinguishing automated enumeration from human pacing.</li>
              </ul>
            </div>
          </div>
        )}

        {/* 5. ABLATION STUDY TAB */}
        {activeTab === 'ablation' && (
          <div className="card">
            <div className="card-title">
              <span>Feature Set Ablation Trade-Off Analysis</span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
              Comparison proving that the deployable 13-feature Request-Only set achieves equivalent detection capability
              as richer offline feature sets without requiring post-response attributes.
            </p>
            <div className="table-responsive">
              <table>
                <thead>
                  <tr>
                    <th>Feature Set</th>
                    <th>Feature Count</th>
                    <th>Model</th>
                    <th>Accuracy</th>
                    <th>Macro F1</th>
                    <th>Precision</th>
                    <th>Recall</th>
                    <th>Inference Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {ABLATION_RESULTS.map((a, i) => (
                    <tr key={i} style={{ backgroundColor: a.set === 'REQUEST_ONLY_13' ? '#f0fdf4' : 'transparent' }}>
                      <td><strong>{a.set}</strong> {a.set === 'REQUEST_ONLY_13' ? '(Operational Live)' : ''}</td>
                      <td>{a.count}</td>
                      <td>{a.model}</td>
                      <td>{(a.acc * 100).toFixed(2)}%</td>
                      <td><strong>{(a.macroF1 * 100).toFixed(2)}%</strong></td>
                      <td>{(a.prec * 100).toFixed(2)}%</td>
                      <td>{(a.rec * 100).toFixed(2)}%</td>
                      <td>{a.latency}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 6. UNSEEN ATTACK GENERALIZATION TAB */}
        {activeTab === 'unseen' && (
          <div className="card">
            <div className="card-title">
              <span>Leave-One-Attack-Out Zero-Day Generalization</span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
              In accordance with Research Question 3, each attack family was systematically held out during training
              and tested as an unrepresented zero-day attack.
            </p>
            <div className="table-responsive">
              <table>
                <thead>
                  <tr>
                    <th>Held-Out Attack</th>
                    <th>Overall Accuracy</th>
                    <th>Precision</th>
                    <th>Malicious Recall (Detection)</th>
                    <th>F1-Score</th>
                    <th>Test Evaluation Samples</th>
                  </tr>
                </thead>
                <tbody>
                  {UNSEEN_ATTACKS.map((u, i) => (
                    <tr
                      key={i}
                      style={{
                        backgroundColor: u.outlier ? '#fff1f2' : 'transparent',
                        fontWeight: u.outlier ? 600 : 400
                      }}
                    >
                      <td><strong>{u.attack}</strong> {u.outlier ? '⚠️ Key Empirical Finding' : ''}</td>
                      <td>{(u.acc * 100).toFixed(2)}%</td>
                      <td>{(u.prec * 100).toFixed(2)}%</td>
                      <td style={{ color: u.outlier ? '#dc2626' : 'var(--text-main)' }}>
                        <strong>{(u.rec * 100).toFixed(2)}%</strong>
                      </td>
                      <td>{(u.f1 * 100).toFixed(2)}%</td>
                      <td>{u.samples.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ background: '#f8fafc', padding: '1rem', borderRadius: '6px', marginTop: '1.25rem', border: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
              <h4 style={{ fontWeight: 600, color: '#0f172a', marginBottom: '0.35rem' }}>Methodological Research Finding:</h4>
              <p style={{ color: '#475569' }}>
                When <strong>LOG4J</strong> is excluded from training, detection recall drops to <strong>15.13%</strong>.
                This confirms Hypothesis H3: generalization to fundamentally novel attack syntaxes is bounded by the representation space
                rather than universally successful. In contrast, injection families sharing syntactic character distributions (XSS, SQLi, Directory Traversal)
                generalize with recall exceeding 99.6%.
              </p>
            </div>
          </div>
        )}

        {/* 7. LATENCY & OVERHEAD TAB */}
        {activeTab === 'latency' && (
          <div className="card">
            <div className="card-title">
              <span>Gateway Processing Overhead & Latency Profile</span>
            </div>
            <div className="meta-grid" style={{ marginBottom: '1.5rem' }}>
              <div className="meta-item">
                <span>Feature Extraction Latency</span>
                ~0.15 ms / request (High-performance Java parser)
              </div>
              <div className="meta-item">
                <span>ML Inference Latency</span>
                ~2.20 ms / request (FastAPI Random Forest CPU execution)
              </div>
              <div className="meta-item">
                <span>Decision & Policy Overhead</span>
                ~0.05 ms / request
              </div>
              <div className="meta-item">
                <span>Total Gateway Overhead</span>
                ~3.40 ms mean latency
              </div>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Quantifies Research Question 4: Request-only feature extraction inside a pre-response Java gateway introduces negligible
              overhead (&lt;5 ms), making real-time inline mitigation practical for high-throughput production microservices.
            </p>
          </div>
        )}

        {/* PREDICTION DETAILS MODAL */}
        {selectedEvent && (
          <div className="modal-overlay" onClick={() => setSelectedEvent(null)}>
            <div className="modal-card" onClick={e => e.stopPropagation()}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
                <div>
                  <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Telemetry Event Deep Dive</h3>
                  <code style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{selectedEvent.requestId}</code>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  style={{ background: 'none', border: 'none', fontSize: '1.25rem', cursor: 'pointer' }}
                >
                  ✕
                </button>
              </div>

              <div className="meta-grid">
                <div className="meta-item">
                  <span>Timestamp</span>
                  {selectedEvent.timestamp}
                </div>
                <div className="meta-item">
                  <span>Client IP / Source</span>
                  {selectedEvent.source}
                </div>
                <div className="meta-item">
                  <span>HTTP Request</span>
                  <strong>{selectedEvent.method}</strong> {selectedEvent.endpoint}
                </div>
                <div className="meta-item">
                  <span>Authenticated User</span>
                  {selectedEvent.authenticatedUser}
                </div>
                <div className="meta-item">
                  <span>Attack Family</span>
                  {selectedEvent.attackFamily}
                </div>
                <div className="meta-item">
                  <span>Predicted Class</span>
                  <strong>{selectedEvent.predictedClass}</strong>
                </div>
                <div className="meta-item">
                  <span>Classifier Confidence</span>
                  {selectedEvent.confidence ? `${(selectedEvent.confidence * 100).toFixed(1)}%` : 'N/A'}
                </div>
                <div className="meta-item">
                  <span>Security Decision</span>
                  <span className={`badge badge-${selectedEvent.decision ? selectedEvent.decision.toLowerCase() : 'allow'}`}>
                    {selectedEvent.decision}
                  </span>
                </div>
                <div className="meta-item">
                  <span>Mitigation Policy</span>
                  {selectedEvent.mitigation}
                </div>
                <div className="meta-item">
                  <span>HTTP Response Status</span>
                  {selectedEvent.statusCode}
                </div>
                <div className="meta-item">
                  <span>Model Executed</span>
                  {selectedEvent.modelName} (v{selectedEvent.modelVersion})
                </div>
                <div className="meta-item">
                  <span>Backend Reached?</span>
                  {selectedEvent.backendReached ? 'YES (Allowed)' : 'NO (Blocked at Gateway)'}
                </div>
              </div>

              <div style={{ marginTop: '1.25rem' }}>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem' }}>Latency Breakdown:</h4>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Detection: {selectedEvent.detectionLatencyMs} ms |
                  Mitigation: {selectedEvent.mitigationLatencyMs} ms |
                  Total Gateway Overhead: {selectedEvent.totalGatewayLatencyMs} ms
                </p>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
