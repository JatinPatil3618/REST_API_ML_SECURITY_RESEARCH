# System Architecture Document

## Project: Machine-Learning-Based Detection and Generalization of REST API Security Attacks Across Access-Control and Input-Manipulation Threats

### 1. Architectural Philosophy
The system implements a research-grounded, production-like REST API security gateway. It enforces strict separation between:
1. **Business-Logic / Access-Control Abuse (BOLA)**: Requires sequential, session-relative context tracking over a rolling window ($W=10$). Models never learn specific object IDs or direct authorization outcomes.
2. **Payload / Input-Manipulation Attacks (ATRDF)**: Requires syntactic and statistical character-level request representations (entropy, length, token distributions).
3. **Detection vs. Mitigation**: Detection evaluates the statistical anomalies and classifier predictions; Mitigation decides system action (ALLOW, BLOCK 403, SANITIZE, REAUTHENTICATE).
4. **Pre-Response Gateway Invariance**: The live gateway relies exclusively on request-time features ($13$ features), never anticipating response attributes (e.g. status code, response body size) which are only available post-execution.

### 2. Network and Component Dataflow
```
                       +-----------------------------+
                       |    SecureBook Frontend      |
                       |       (Port 5173)           |
                       +--------------+--------------+
                                      | HTTP
                                      v
                       +-----------------------------+
                       |     OWASP ZAP Controller    |
                       |         (Port 8090)         |
                       +--------------+--------------+
                                      | HTTP
                                      v
                       +-----------------------------+
                       |    Spring Boot Gateway      |
                       |         (Port 8080)         |
                       +--------------+--------------+
                                      |
         +----------------------------+----------------------------+
         |                                                         |
         v                                                         v
 [Endpoint: /api/books/:id]                                [Endpoint: /api/search, /api/comments]
         |                                                         |
 [BOLA Session Tracker (W=10)]                             [ATRDF Syntactic Extractor (13 Feat)]
         |                                                         |
         +----------------------------+----------------------------+
                                      | POST /predict
                                      v
                       +-----------------------------+
                       |     FastAPI ML Service      |
                       |         (Port 8000)         |
                       |  - Binary RF (ATRDF)        |
                       |  - Multiclass RF (ATRDF)    |
                       |  - Behavioral RF (BOLA)     |
                       |  - Baseline Logistic Reg    |
                       +--------------+--------------+
                                      | Prediction + Probabilities + Signals
                                      v
                       +-----------------------------+
                       |       Decision Engine       |
                       | - If Attack: BLOCK (403)    |
                       | - If Normal: Forward        |
                       +--------------+--------------+
                                      | Forward Allowed
                                      v
                       +-----------------------------+
                       |     Demo REST API Backend   |
                       |       (Node/Express 5001)   |
                       | - Authorization Checks      |
                       | - Virtual Safe Sandbox      |
                       +--------------+--------------+
                                      |
                                      +------------------------+
                                      |                        |
                                      v                        v
                       +-----------------------------+  +-------------------------------+
                       |      MongoDB Telemetry      |  | API Security Research Dash    |
                       |         (Port 27017)        |  |          (Port 5174)          |
                       +-----------------------------+  +-------------------------------+
```

### 3. Component Details
1. **Frontend (`frontend/`)**: React + Vite, light clean aesthetic. SecureBook API Lab. Realistic user workflow: browsing, searching books, submitting comments, viewing profile, interacting with a controlled Security Lab testing suite.
2. **Gateway (`gateway/`)**: Spring Boot 3.x filter caching request stream, generating unique `request_id`, routing through feature extraction, querying ML inference, and executing policy.
3. **ML Service (`ml_service/`)**: Python FastAPI loading models once at boot. Provides `/predict/atrdf/binary`, `/predict/atrdf/multiclass`, `/predict/bola`, and `/model-info`.
4. **Demo API (`demo_api/`)**: Node.js/Express service enforcing actual server-side object permissions (`owner_id === user_id`) and safely responding to catalog queries.
5. **Database (`MongoDB`)**: Stores users, books, comments, along with the research telemetry collections (`security_events`, `predictions`, `mitigation_events`, `experiments`, `research_metrics`).
6. **Dashboard (`dashboard/`)**: React + Vite application tailored for thesis defense and research analysis. Displays real-time latency, confusion matrices, feature importance graphs, leave-one-attack-out generalization, and ablation comparisons.
