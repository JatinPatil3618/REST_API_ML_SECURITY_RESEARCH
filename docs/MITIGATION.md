# Detection versus Mitigation Architecture

## 1. Conceptual Separation
A critical requirement of this research system is the distinction between **Detection** and **Mitigation**:
- **Detection**: Evaluates statistical characteristics and returns the classifier belief ($P(\text{Malicious} \mid X)$).
- **Mitigation**: An operational security policy that acts upon detection results, application state, and business constraints to protect the downstream service.

---

## 2. Policy Mapping Matrix

| Attack Family / Class | Detected Mechanism | Gateway HTTP Action | Safe Mitigation Outcome | Backend Execution |
| :--- | :--- | :--- | :--- | :--- |
| **BENIGN** | Normal browsing | `200 OK` (Forward) | Pass-through to Demo API | Full execution |
| **BOLA** | Cross-owner access | `403 Forbidden` | Strict object authorization enforcement | Blocked |
| **XSS** | Unsafe script tag | `403 Forbidden` / Sanitize | Safe browser rendering; HTML escaped | Script not executed |
| **SQL Injection** | Syntax quotation break | `403 Forbidden` | Parameterized prepared statement | SQL query not formed |
| **Cookie Injection** | Malformed auth token | `401 Unauthorized` | Invalidate session; reauthentication required | Identity not hijacked |
| **Log Forging** | CRLF control chars | `403 Forbidden` | Structured JSON logging; newline stripping | Audit log untampered |
| **RCE** | Shell pipe / command syntax | `403 Forbidden` | Complete execution denial | **Execution: NOT PERFORMED** |
| **Directory Traversal** | Path relative dots (`../`) | `403 Forbidden` | Strict path whitelist validation | Filesystem unread |
| **LOG4J** | JNDI lookup pattern | `403 Forbidden` | Safe lookup parsing; outbound call blocked | Lookup disabled |

---

## 3. Human-Friendly Error Messages
To prevent information leakage to attackers while maintaining human usability:
- BOLA: `"Access denied. This book belongs to another user."`
- XSS: `"Unsafe content blocked."`
- SQLi: `"Suspicious query input detected and rejected."`
- RCE: `"Command execution attempt blocked. No command was executed."`
