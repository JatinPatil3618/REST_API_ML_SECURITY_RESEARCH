# Research Limitations and Boundary Conditions

## 1. Controlled Experimental Environment
- The empirical evaluations are conducted within controlled local and benchmark testbeds (ATRDF Dataset 4 corpus and VAmPI environment).
- While the datasets accurately represent OWASP API Security Top 10 vulnerabilities, live real-world production traffic may exhibit higher lexical diversity and unpredictable header combinations.

---

## 2. Generalization Boundedness
- As demonstrated in **Hypothesis H3** and the Leave-One-Attack-Out experiments, machine learning representations do **not** universally detect all zero-day attacks.
- Attacks that share syntactic or character-level entropy distributions with known categories (e.g., cross-site scripting vs. SQL injection quotes) generalize effectively (>99% recall).
- Conversely, attacks that introduce novel protocols or syntactic tokens (such as **Log4j JNDI lookup expressions**) suffer catastrophic recall degradation (dropping to **15.13%**) when unrepresented during training.

---

## 3. Defense-in-Depth Prerequisite: ML Does Not Replace Authorization
- A core finding of this research is that machine learning models must **never** replace server-side object authorization.
- While the BOLA session model identifies anomalous cross-owner browsing spikes, deterministic authorization guards (verifying `book.owner === user.id`) remain mandatory for strict access control.
- Machine learning serves as an inline anomaly and intrusion detection filter rather than an authoritative access arbiter.

---

## 4. What Should Not Be Claimed
- **100% Detection**: The system does not claim complete or absolute security coverage.
- **Universal Zero-Day Detection**: Unseen attack generalization is explicitly attack-dependent.
- **Zero False Positives**: While precision is high on the evaluation split, distribution shifts in client applications can introduce false positives requiring ongoing threshold recalibration.
