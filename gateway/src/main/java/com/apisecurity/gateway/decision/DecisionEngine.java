package com.apisecurity.gateway.decision;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class DecisionEngine {

    @Value("${gateway.confidence.threshold:0.70}")
    private double defaultConfidenceThreshold;

    @Value("${gateway.fail-safe.mode:ALERT}")
    private String failSafeMode;

    public static class SecurityDecision {
        public String action; // ALLOW, BLOCK, ALERT
        public String attackFamily;
        public String predictedClass;
        public double confidence;
        public String mitigation;
        public List<String> mitigationTechniques;
        public String userMessage;
        public int httpStatusCode;

        public SecurityDecision(String action, String attackFamily, String predictedClass, double confidence, String mitigation, String userMessage, int httpStatusCode) {
            this.action = action;
            this.attackFamily = attackFamily;
            this.predictedClass = predictedClass;
            this.confidence = confidence;
            this.mitigation = mitigation;
            this.userMessage = userMessage;
            this.httpStatusCode = httpStatusCode;
        }
    }

    public SecurityDecision evaluate(Map<String, Object> mlResult, String mode) {
        if (mlResult == null || mlResult.containsKey("error")) {
            SecurityDecision failSafe = new SecurityDecision(
                failSafeMode,
                "UNKNOWN",
                "UNAVAILABLE",
                0.0,
                "Fail-safe Alert",
                "Security verification temporarily unavailable",
                200
            );
            failSafe.mitigationTechniques = List.of("fail_safe_alert");
            return failSafe;
        }

        String decision = (String) mlResult.getOrDefault("decision", "ALLOW");
        String attackFamily = (String) mlResult.getOrDefault("attack_family", "BENIGN");
        String mitigation = (String) mlResult.getOrDefault("mitigation", "ALLOW");
        String predictedClass = (String) mlResult.getOrDefault("predicted_class", "NORMAL");
        List<String> techniques = readTechniques(mlResult);

        double confidence = 0.0;
        if (mlResult.get("confidence") instanceof Number) {
            confidence = ((Number) mlResult.get("confidence")).doubleValue();
        } else if (mlResult.get("multiclass_detection") instanceof Map) {
            Map<?, ?> mDet = (Map<?, ?>) mlResult.get("multiclass_detection");
            if (mDet.get("confidence") instanceof Number) {
                confidence = ((Number) mDet.get("confidence")).doubleValue();
            }
        } else if (mlResult.get("binary_detection") instanceof Map) {
            Map<?, ?> binDet = (Map<?, ?>) mlResult.get("binary_detection");
            if (binDet.get("confidence") instanceof Number) {
                confidence = ((Number) binDet.get("confidence")).doubleValue();
            }
        } else if (mlResult.get("detection") instanceof Map) {
            Map<?, ?> det = (Map<?, ?>) mlResult.get("detection");
            if (det.get("confidence") instanceof Number) {
                confidence = ((Number) det.get("confidence")).doubleValue();
            }
        }

        if ("BLOCK".equalsIgnoreCase(decision)) {
            String userMsg;
            int status = 403;

            if ("BOLA".equalsIgnoreCase(attackFamily)) {
                userMsg = "Access denied. This book belongs to another user.";
            } else {
                switch (predictedClass) {
                    case "XSS":
                        userMsg = "Unsafe content blocked.";
                        break;
                    case "SQL Injection":
                        userMsg = "Suspicious query input detected and rejected.";
                        break;
                    case "Cookie Injection":
                        userMsg = "Invalid session state. Reauthentication required.";
                        status = 401;
                        break;
                    case "Log Forging":
                        userMsg = "Malformed logging input detected.";
                        break;
                    case "RCE":
                        userMsg = "Command execution attempt blocked. No command was executed.";
                        break;
                    case "Directory Traversal":
                        userMsg = "Invalid resource path.";
                        break;
                    case "LOG4J":
                        userMsg = "Dangerous lookup pattern blocked.";
                        break;
                    default:
                        userMsg = "Request blocked due to security policy violation.";
                }
            }

            SecurityDecision blocked = new SecurityDecision(
                "BLOCK",
                attackFamily,
                predictedClass,
                confidence,
                mitigation,
                userMsg,
                status
            );
            blocked.mitigationTechniques = techniques;
            return blocked;
        }

        SecurityDecision allowed = new SecurityDecision(
            "ALLOW",
            attackFamily,
            predictedClass,
            confidence,
            mitigation,
            "Request allowed",
            200
        );
        allowed.mitigationTechniques = techniques;
        return allowed;
    }

    private static List<String> readTechniques(Map<String, Object> mlResult) {
        Object raw = mlResult.get("mitigation_techniques");
        if (!(raw instanceof List)) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (Object item : (List<?>) raw) {
            if (item != null) {
                out.add(String.valueOf(item));
            }
        }
        return out.isEmpty() ? null : out;
    }
}
